package vault

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"filippo.io/age"
)

// Prompter asks for a passphrase. confirm means a new passphrase: ask twice.
type Prompter func(prompt string, confirm bool) (string, error)

// Status describes the unlock state.
type Status struct {
	Protected bool
	Unlocked  bool
	Expiry    time.Time
}

// CurrentStatus reports whether the identity is available. A plain identity is
// always available.
func CurrentStatus() (Status, error) {
	raw, err := os.ReadFile(IdentityPath())
	if err != nil {
		return Status{}, fmt.Errorf("identity: %w", err)
	}
	kind, err := ClassifyIdentity(raw)
	if err != nil {
		return Status{}, err
	}
	if !kind.Protected() {
		return Status{Unlocked: true}, nil
	}
	_, exp, ok, err := CacheGet()
	if err != nil {
		return Status{}, err
	}
	return Status{Protected: true, Unlocked: ok, Expiry: exp}, nil
}

// Unlock unwraps the identity, test-decrypts the store so a wrong identity is
// never cached, and caches the plain identity for ttl. The passphrase is never
// cached.
func Unlock(ttl time.Duration, p Prompter) (time.Time, error) {
	raw, err := os.ReadFile(IdentityPath())
	if err != nil {
		return time.Time{}, fmt.Errorf("identity: %w", err)
	}
	kind, err := ClassifyIdentity(raw)
	if err != nil {
		return time.Time{}, err
	}
	if !kind.Protected() {
		return time.Time{}, errors.New("identity is not passphrase-protected; nothing to unlock")
	}
	pass, err := p("Passphrase: ", false)
	if err != nil {
		return time.Time{}, err
	}
	text, err := Unwrap(raw, kind, pass)
	if err != nil {
		return time.Time{}, err
	}
	ids, err := parseUnwrapped(text, kindOfUnwrapped(text))
	if err != nil {
		return time.Time{}, err
	}
	if store, err := os.ReadFile(StorePath()); err == nil {
		if _, err := decode(store, ids); err != nil {
			return time.Time{}, fmt.Errorf("identity cannot decrypt the store: %w", err)
		}
	}
	return CachePut(text, ttl)
}

// Keygen writes a new scrypt-wrapped X25519 identity and returns the public
// recipient. It refuses to overwrite.
func Keygen(out string, p Prompter) (string, error) {
	if out == "" {
		out = DefaultIdentityPath()
	}
	if _, err := os.Lstat(out); err == nil {
		return "", fmt.Errorf("%s exists; refusing to overwrite", out)
	}
	pass, err := p("New passphrase: ", true)
	if err != nil {
		return "", err
	}
	id, err := age.GenerateX25519Identity()
	if err != nil {
		return "", err
	}
	sr, err := age.NewScryptRecipient(pass)
	if err != nil {
		return "", err
	}
	if err := writeExclusive(out, wrap(id.String()+"\n", sr)); err != nil {
		return "", err
	}
	if recipientsFile() == "" {
		if _, err := os.Stat(StorePath()); errors.Is(err, os.ErrNotExist) {
			if err := atomicWrite(recipientsPath(), ".recipients-*", []byte(id.Recipient().String()+"\n")); err != nil {
				return "", err
			}
		}
	}
	return id.Recipient().String(), nil
}

func wrap(plain string, r age.Recipient) []byte {
	var buf bytes.Buffer
	w, _ := age.Encrypt(&buf, r)
	w.Write([]byte(plain))
	w.Close()
	return buf.Bytes()
}

func writeExclusive(path string, data []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}

// RekeyOptions are the rekey inputs.
type RekeyOptions struct {
	From, To string
	NoBackup bool
}

// RekeyResult reports what rekey did.
type RekeyResult struct {
	Entries    int
	Recipients string
	Backups    bool
}

// identityFromFile loads any identity file; a protected one prompts.
func identityFromFile(path string, p Prompter) ([]age.Identity, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("identity: %w", err)
	}
	kind, err := ClassifyIdentity(raw)
	if err != nil {
		return nil, err
	}
	text := string(raw)
	if kind.Protected() {
		pass, err := p("Passphrase for "+path+": ", false)
		if err != nil {
			return nil, err
		}
		if text, err = Unwrap(raw, kind, pass); err != nil {
			return nil, err
		}
		kind = kindOfUnwrapped(text)
	}
	return parseUnwrapped(text, kind)
}

// Rekey re-encrypts the store to a single new recipient derived from the new
// identity, then writes the recipients file.
func Rekey(o RekeyOptions, p Prompter) (RekeyResult, error) {
	from := o.From
	if from == "" {
		from = os.Getenv("PERRY_IDENTITY")
	}
	if from == "" {
		from = defaultSSHKey()
	}
	to := o.To
	if to == "" {
		to = DefaultIdentityPath()
	}
	if from == to {
		return RekeyResult{}, errors.New("--from and --to are the same file")
	}
	if _, err := os.Stat(StorePath()); err != nil {
		return RekeyResult{}, errors.New("no store to rekey")
	}
	if os.Getenv("PERRY_RECIPIENTS") != "" {
		return RekeyResult{}, errors.New("unset PERRY_RECIPIENTS: rekey writes the recipients file in the config dir")
	}
	unlock, err := lock(true)
	if err != nil {
		return RekeyResult{}, err
	}
	defer unlock()
	oldIDs, err := identityFromFile(from, p)
	if err != nil {
		return RekeyResult{}, err
	}
	raw, err := os.ReadFile(StorePath())
	if err != nil {
		return RekeyResult{}, err
	}
	d, err := decode(raw, oldIDs)
	if err != nil {
		return RekeyResult{}, err
	}
	newIDs, err := identityFromFile(to, p)
	if err != nil {
		return RekeyResult{}, err
	}
	xid, ok := newIDs[0].(*age.X25519Identity)
	if !ok {
		return RekeyResult{}, errors.New("new identity must be an age X25519 identity")
	}
	rcpt := xid.Recipient()
	ct, err := encode(d, []age.Recipient{rcpt})
	if err != nil {
		return RekeyResult{}, err
	}
	check, err := decode(ct, newIDs)
	if err != nil || len(check.Entries) != len(d.Entries) {
		return RekeyResult{}, errors.New("new store does not decrypt with the new identity; nothing changed")
	}
	bak, rbak := StorePath()+".bak", recipientsPath()+".bak"
	if o.NoBackup {
		os.Remove(bak)
		os.Remove(rbak)
	} else {
		if err := atomicWrite(bak, ".rekey-*", raw); err != nil {
			return RekeyResult{}, err
		}
		if old, err := os.ReadFile(recipientsPath()); err == nil {
			if err := atomicWrite(rbak, ".rekey-*", old); err != nil {
				return RekeyResult{}, err
			}
		}
	}
	if err := atomicWrite(recipientsPath(), ".rekey-*", []byte(rcpt.String()+"\n")); err != nil {
		return RekeyResult{}, err
	}
	if err := atomicWrite(StorePath(), ".store-*", ct); err != nil {
		return RekeyResult{}, err
	}
	CacheDrop()
	return RekeyResult{Entries: len(d.Entries), Recipients: recipientsPath(), Backups: !o.NoBackup}, nil
}

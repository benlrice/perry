package vault

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"filippo.io/age"
	"golang.org/x/crypto/ssh"
)

func fixedPass(p string) Prompter {
	return func(string, bool) (string, error) { return p, nil }
}

// sshHome makes a temp HOME with a plain ed25519 key and returns its path.
func sshHome(t *testing.T) string {
	t.Helper()
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(home, "cfg"))
	t.Setenv("PERRY_IDENTITY", "")
	t.Setenv("PERRY_RECIPIENTS", "")
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	blk, err := ssh.MarshalPrivateKey(priv, "")
	if err != nil {
		t.Fatal(err)
	}
	os.MkdirAll(filepath.Join(home, ".ssh"), 0o700)
	os.WriteFile(filepath.Join(home, ".ssh", "id_ed25519"), pem.EncodeToMemory(blk), 0o600)
	sp, _ := ssh.NewPublicKey(pub)
	os.WriteFile(filepath.Join(home, ".ssh", "id_ed25519.pub"), ssh.MarshalAuthorizedKey(sp), 0o644)
	return home
}

func add(t *testing.T, e Entry) {
	t.Helper()
	if err := Update(func(d *Data) error { d.Entries = append(d.Entries, e); return nil }); err != nil {
		t.Fatal(err)
	}
}

func TestStoreRoundTripModesAndNoPlaintext(t *testing.T) {
	sshHome(t)
	add(t, Entry{Host: "jira.example.com", Kind: "jira", Secret: "hunter2hunter2", Created: "t", Updated: "t"})
	st, err := os.Stat(StorePath())
	if err != nil || st.Mode().Perm() != 0o600 {
		t.Fatalf("store mode: %v %v", st, err)
	}
	raw, _ := os.ReadFile(StorePath())
	if strings.Contains(string(raw), "jira.example.com") || strings.Contains(string(raw), "hunter2") {
		t.Error("plaintext in store file")
	}
	err = View(func(d *Data) error {
		if len(d.Entries) != 1 || d.Entries[0].Secret != "hunter2hunter2" {
			t.Errorf("entries: %+v", d.Entries)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if m, _ := filepath.Glob(filepath.Join(ConfigDir(), ".store-*")); len(m) != 0 {
		t.Errorf("temp files left: %v", m)
	}
}

func TestMissingStoreIsEmpty(t *testing.T) {
	sshHome(t)
	View(func(d *Data) error {
		if len(d.Entries) != 0 {
			t.Error("not empty")
		}
		return nil
	})
}

func TestUpdateErrorWritesNothing(t *testing.T) {
	sshHome(t)
	Update(func(d *Data) error { return errors.New("boom") })
	if _, err := os.Stat(StorePath()); err == nil {
		t.Error("store written after failed update")
	}
}

func TestResolveRef(t *testing.T) {
	d := &Data{Entries: []Entry{
		{Host: "a.example.com", Kind: "jira", Username: "u1", Secret: "s1"},
		{Host: "b.example.com", Kind: "jira", Secret: "s2"},
		{Host: "g.example.com:8080", Kind: "grafana", Secret: "s3"},
		{Host: "solo.example.com", Kind: "slack", Secret: "s4", Notes: "n"},
	}}
	r, err := d.ResolveRef("a.example.com:username", "")
	if err != nil || r.Field != "username" || r.Entry.Secret != "s1" || r.Label != "a.example.com" {
		t.Errorf("field: %+v %v", r, err)
	}
	if r, err = d.ResolveRef("g.example.com:8080", ""); err != nil || r.Entry.Secret != "s3" || r.Field != "secret" || r.Label != "g.example.com:8080" {
		t.Errorf("host:port: %+v %v", r, err)
	}
	if r, err = d.ResolveRef("slack", ""); err != nil || r.Entry.Host != "solo.example.com" {
		t.Errorf("kind: %+v %v", r, err)
	}
	if _, err = d.ResolveRef("jira", ""); err == nil || err.Error() != `ambiguous ref "jira"; candidates: a.example.com, b.example.com` {
		t.Errorf("ambiguous: %v", err)
	}
	if strings.Contains(err.Error(), "s1") {
		t.Error("ambiguity error leaked data")
	}
	if r, err = d.ResolveRef("jira:secret", "jira"); err == nil {
		t.Errorf("still ambiguous: %+v", r)
	}
	if _, err = d.ResolveRef("a.example.com:bogus", ""); err == nil || !strings.Contains(err.Error(), `unknown field "bogus"`) {
		t.Errorf("unknown field: %v", err)
	}
	if _, err = d.ResolveRef("nope:secret", ""); err == nil || !strings.Contains(err.Error(), `no entry matches "nope"`) {
		t.Errorf("base error: %v", err)
	}
}

func TestCheckAuth(t *testing.T) {
	if err := CheckAuth(Entry{Host: "h", Auth: "basic"}); err == nil || !strings.Contains(err.Error(), "auth basic needs a username (set with: perry edit h --set-user U)") {
		t.Errorf("basic: %v", err)
	}
	if err := CheckAuth(Entry{Auth: "digest"}); err == nil || err.Error() != `auth must be basic, bearer or token, got "digest"` {
		t.Errorf("bad: %v", err)
	}
	if err := CheckAuth(Entry{Auth: "bearer"}); err != nil {
		t.Error(err)
	}
	if !WantsUser("JIRA") || WantsUser("github") {
		t.Error("WantsUser")
	}
}

func TestClassifyIdentity(t *testing.T) {
	id, _ := age.GenerateX25519Identity()
	if k, err := ClassifyIdentity([]byte("# comment\n" + id.String() + "\n")); err != nil || k != PlainAge {
		t.Errorf("plain age: %v %v", k, err)
	}
	if k, err := ClassifyIdentity(wrapScrypt(t, id.String()+"\n", "pw")); err != nil || k != ScryptAge {
		t.Errorf("scrypt: %v %v", k, err)
	}
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	blk, _ := ssh.MarshalPrivateKey(priv, "")
	if k, err := ClassifyIdentity(pem.EncodeToMemory(blk)); err != nil || k != PlainSSH {
		t.Errorf("ssh: %v %v", k, err)
	}
	enc, _ := ssh.MarshalPrivateKeyWithPassphrase(priv, "", []byte("pw"))
	if k, err := ClassifyIdentity(pem.EncodeToMemory(enc)); err != nil || k != EncryptedSSH {
		t.Errorf("enc ssh: %v %v", k, err)
	}
	if _, err := ClassifyIdentity([]byte("junk")); err == nil || err.Error() != "identity: unrecognized format" {
		t.Errorf("junk: %v", err)
	}
	text, err := Unwrap(pem.EncodeToMemory(enc), EncryptedSSH, "pw")
	if err != nil || !strings.Contains(text, "OPENSSH PRIVATE KEY") {
		t.Errorf("unwrap ssh: %v", err)
	}
	if _, err := Unwrap(pem.EncodeToMemory(enc), EncryptedSSH, "bad"); err == nil || err.Error() != "wrong passphrase" {
		t.Errorf("wrong pass: %v", err)
	}
}

func wrapScrypt(t *testing.T, plain, pass string) []byte {
	t.Helper()
	r, err := age.NewScryptRecipient(pass)
	if err != nil {
		t.Fatal(err)
	}
	return wrap(plain, r)
}

func TestLockedFlow_KeygenRekeyUnlock(t *testing.T) {
	sshHome(t)
	t.Cleanup(func() { CacheDrop() })
	// CacheGet succeeds on an empty keyring even where adding a key is denied (CI runners).
	if _, err := CachePut("probe", time.Minute); err != nil {
		t.Skipf("keyring unavailable: %v", err)
	}
	CacheDrop()
	add(t, Entry{Host: "h", Kind: "k", Secret: "longsecretvalue", Created: "t", Updated: "t"})

	rcpt, err := Keygen("", fixedPass("pw"))
	if err != nil || !strings.HasPrefix(rcpt, "age1") {
		t.Fatalf("keygen: %q %v", rcpt, err)
	}
	if _, err := os.Stat(recipientsPath()); err == nil {
		t.Error("recipients file written although a store exists")
	}
	if _, err := Keygen("", fixedPass("pw")); err == nil || !strings.Contains(err.Error(), "exists; refusing to overwrite") {
		t.Errorf("overwrite: %v", err)
	}

	res, err := Rekey(RekeyOptions{}, fixedPass("pw"))
	if err != nil || res.Entries != 1 || !res.Backups {
		t.Fatalf("rekey: %+v %v", res, err)
	}
	for _, p := range []string{StorePath() + ".bak"} {
		if _, err := os.Stat(p); err != nil {
			t.Errorf("missing backup %s", p)
		}
	}
	// identity.age now exists, so it is the identity: locked until unlock.
	if err := View(func(*Data) error { return nil }); !errors.Is(err, ErrLocked) {
		t.Fatalf("want ErrLocked, got %v", err)
	}
	if st, _ := CurrentStatus(); !st.Protected || st.Unlocked {
		t.Errorf("status: %+v", st)
	}
	if _, err := Unlock(time.Minute, fixedPass("wrong")); err == nil || err.Error() != "wrong passphrase" {
		t.Errorf("wrong passphrase: %v", err)
	}
	if _, err := Unlock(time.Minute, fixedPass("pw")); err != nil {
		t.Fatal(err)
	}
	if err := View(func(d *Data) error {
		if len(d.Entries) != 1 {
			t.Errorf("entries after rekey: %d", len(d.Entries))
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if err := CacheDrop(); err != nil {
		t.Fatal(err)
	}
	if err := View(func(*Data) error { return nil }); !errors.Is(err, ErrLocked) {
		t.Errorf("want ErrLocked after lock, got %v", err)
	}
}

func TestRekeyRefusals(t *testing.T) {
	sshHome(t)
	if _, err := Rekey(RekeyOptions{}, fixedPass("x")); err == nil || err.Error() != "no store to rekey" {
		t.Errorf("no store: %v", err)
	}
	add(t, Entry{Host: "h", Kind: "k", Secret: "s"})
	if _, err := Rekey(RekeyOptions{From: "a", To: "a"}, fixedPass("x")); err == nil {
		t.Error("same file accepted")
	}
	t.Setenv("PERRY_RECIPIENTS", "/nonexistent")
	if _, err := Rekey(RekeyOptions{}, fixedPass("x")); err == nil || !strings.Contains(err.Error(), "unset PERRY_RECIPIENTS") {
		t.Errorf("recipients env: %v", err)
	}
}

func TestUnlockPlainIdentityRefused(t *testing.T) {
	sshHome(t)
	if _, err := Unlock(time.Minute, fixedPass("x")); err == nil || !strings.Contains(err.Error(), "nothing to unlock") {
		t.Errorf("got %v", err)
	}
	if st, err := CurrentStatus(); err != nil || !st.Unlocked || st.Protected {
		t.Errorf("status: %+v %v", st, err)
	}
}

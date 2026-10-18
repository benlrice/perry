package vault

import (
	"bytes"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"filippo.io/age"
	"filippo.io/age/agessh"
	"golang.org/x/crypto/ssh"
)

// IdentityKind says how an identity file is stored.
type IdentityKind int

const (
	PlainAge IdentityKind = iota + 1
	ScryptAge
	PlainSSH
	EncryptedSSH
)

// Protected reports whether the kind needs the unlock cache.
func (k IdentityKind) Protected() bool { return k == ScryptAge || k == EncryptedSSH }

// ClassifyIdentity decides which of the four kinds a file holds.
func ClassifyIdentity(raw []byte) (IdentityKind, error) {
	if bytes.HasPrefix(raw, []byte("age-encryption.org/")) {
		return ScryptAge, nil
	}
	for _, l := range strings.Split(string(raw), "\n") {
		if strings.HasPrefix(strings.TrimSpace(l), "AGE-SECRET-KEY-") {
			return PlainAge, nil
		}
	}
	_, err := ssh.ParseRawPrivateKey(raw)
	if err == nil {
		return PlainSSH, nil
	}
	var missing *ssh.PassphraseMissingError
	if errors.As(err, &missing) {
		return EncryptedSSH, nil
	}
	return 0, errors.New("identity: unrecognized format")
}

// IdentityPath picks PERRY_IDENTITY, then identity.age when it exists, then the
// default ed25519 SSH key.
func IdentityPath() string {
	if p := os.Getenv(EnvIdentity); p != "" {
		return p
	}
	if _, err := os.Stat(DefaultIdentityPath()); err == nil {
		return DefaultIdentityPath()
	}
	return defaultSSHKey()
}

func parseUnwrapped(text string, kind IdentityKind) ([]age.Identity, error) {
	switch kind {
	case PlainAge, ScryptAge:
		return age.ParseIdentities(strings.NewReader(text))
	default:
		id, err := agessh.ParseIdentity([]byte(text))
		if err != nil {
			return nil, err
		}
		return []age.Identity{id}, nil
	}
}

// kindOfUnwrapped is the kind of identity text that the cache holds.
func kindOfUnwrapped(text string) IdentityKind {
	if k, err := ClassifyIdentity([]byte(text)); err == nil {
		return k
	}
	return PlainAge
}

// loadIdentity never prompts. A protected identity comes from the cache.
func loadIdentity() ([]age.Identity, error) {
	raw, err := os.ReadFile(IdentityPath())
	if err != nil {
		return nil, fmt.Errorf("identity: %w", err)
	}
	kind, err := ClassifyIdentity(raw)
	if err != nil {
		return nil, err
	}
	if !kind.Protected() {
		return parseUnwrapped(string(raw), kind)
	}
	text, _, ok, err := CacheGet()
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, ErrLocked
	}
	return parseUnwrapped(text, kindOfUnwrapped(text))
}

// Unwrap removes the passphrase from an identity file and returns the plain
// identity text.
func Unwrap(raw []byte, kind IdentityKind, pass string) (string, error) {
	switch kind {
	case ScryptAge:
		id, err := age.NewScryptIdentity(pass)
		if err != nil {
			return "", err
		}
		r, err := age.Decrypt(bytes.NewReader(raw), id)
		if err != nil {
			return "", errors.New("wrong passphrase")
		}
		plain, err := io.ReadAll(r)
		if err != nil {
			return "", errors.New("wrong passphrase")
		}
		return strings.TrimSpace(string(plain)), nil
	case EncryptedSSH:
		key, err := ssh.ParseRawPrivateKeyWithPassphrase(raw, []byte(pass))
		if err != nil {
			if errors.Is(err, x509.IncorrectPasswordError) {
				return "", errors.New("wrong passphrase")
			}
			return "", err
		}
		blk, err := ssh.MarshalPrivateKey(key, "")
		if err != nil {
			return "", err
		}
		return string(pem.EncodeToMemory(blk)), nil
	}
	return "", errors.New("identity is not passphrase-protected; nothing to unlock")
}

// recipientsFile is PERRY_RECIPIENTS, then <configdir>/recipients when it
// exists. Empty means fall back to the default SSH public key.
func recipientsFile() string {
	if p := os.Getenv(EnvRecipients); p != "" {
		return p
	}
	if _, err := os.Stat(recipientsPath()); err == nil {
		return recipientsPath()
	}
	return ""
}

func loadRecipients() ([]age.Recipient, error) {
	path := recipientsFile()
	if path == "" {
		path = defaultSSHKey() + ".pub"
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("recipients: %w", err)
	}
	var out []age.Recipient
	for _, l := range trimLines(string(raw)) {
		r, err := parseRecipient(l)
		if err != nil {
			return nil, fmt.Errorf("recipients: %w", err)
		}
		out = append(out, r)
	}
	if len(out) == 0 {
		return nil, errors.New("recipients: none configured")
	}
	return out, nil
}

func parseRecipient(line string) (age.Recipient, error) {
	if strings.HasPrefix(line, "age1") {
		return age.ParseX25519Recipient(line)
	}
	return agessh.ParseRecipient(line)
}

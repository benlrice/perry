package vault

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"filippo.io/age"
)

// Entry is one stored credential. The key is (Host, Kind).
type Entry struct {
	Host     string   `json:"host"`
	Kind     string   `json:"kind"`
	Username string   `json:"username,omitempty"`
	Auth     string   `json:"auth,omitempty"`
	Secret   string   `json:"secret"`
	Tags     []string `json:"tags,omitempty"`
	Notes    string   `json:"notes,omitempty"`
	Created  string   `json:"created"`
	Updated  string   `json:"updated"`
}

// Data is the decrypted store document.
type Data struct {
	Version int     `json:"version"`
	Entries []Entry `json:"entries"`
}

// Find returns the index of the exact (host, kind) match, or -1.
func (d *Data) Find(host, kind string) int {
	for i, e := range d.Entries {
		if e.Host == host && e.Kind == kind {
			return i
		}
	}
	return -1
}

// lock takes the store lock and returns the release function. The lock file is
// separate from the store so the atomic rename does not break locking.
func lock(exclusive bool) (func(), error) {
	if err := os.MkdirAll(ConfigDir(), 0o700); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(lockPath(), os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		return nil, err
	}
	how := syscall.LOCK_SH
	if exclusive {
		how = syscall.LOCK_EX
	}
	if err := syscall.Flock(int(f.Fd()), how); err != nil {
		f.Close()
		return nil, err
	}
	return func() { syscall.Flock(int(f.Fd()), syscall.LOCK_UN); f.Close() }, nil
}

// Load reads and decrypts the store. A missing file is an empty store.
func Load() (*Data, error) {
	raw, err := os.ReadFile(StorePath())
	if errors.Is(err, os.ErrNotExist) {
		return &Data{Version: 1}, nil
	}
	if err != nil {
		return nil, err
	}
	ids, err := loadIdentity()
	if err != nil {
		return nil, err
	}
	return decode(raw, ids)
}

func decode(raw []byte, ids []age.Identity) (*Data, error) {
	r, err := age.Decrypt(bytes.NewReader(raw), ids...)
	if err != nil {
		return nil, fmt.Errorf("decrypt store: %w", err)
	}
	plain, err := io.ReadAll(r)
	if err != nil {
		return nil, fmt.Errorf("decrypt store: %w", err)
	}
	var d Data
	if err := json.Unmarshal(plain, &d); err != nil {
		return nil, fmt.Errorf("parse store: %w", err)
	}
	return &d, nil
}

// View runs fn on the decrypted store under a shared lock.
func View(fn func(*Data) error) error {
	unlock, err := lock(false)
	if err != nil {
		return err
	}
	defer unlock()
	d, err := Load()
	if err != nil {
		return err
	}
	return fn(d)
}

// Update runs fn on the decrypted store under an exclusive lock and writes the
// result when fn succeeds. The lock covers the whole read-modify-write.
func Update(fn func(*Data) error) error {
	unlock, err := lock(true)
	if err != nil {
		return err
	}
	defer unlock()
	d, err := Load()
	if err != nil {
		return err
	}
	if err := fn(d); err != nil {
		return err
	}
	rcpts, err := loadRecipients()
	if err != nil {
		return err
	}
	return save(d, rcpts)
}

func encode(d *Data, rcpts []age.Recipient) ([]byte, error) {
	d.Version = 1
	if d.Entries == nil {
		d.Entries = []Entry{}
	}
	plain, err := json.Marshal(d)
	if err != nil {
		return nil, err
	}
	var buf bytes.Buffer
	w, err := age.Encrypt(&buf, rcpts...)
	if err != nil {
		return nil, err
	}
	if _, err := w.Write(plain); err != nil {
		return nil, err
	}
	if err := w.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func save(d *Data, rcpts []age.Recipient) error {
	ct, err := encode(d, rcpts)
	if err != nil {
		return err
	}
	return atomicWrite(StorePath(), ".store-*", ct)
}

// atomicWrite writes data to a temp file in the target dir (0600, fsync) and
// renames it over path.
func atomicWrite(path, pattern string, data []byte) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, pattern)
	if err != nil {
		return err
	}
	name := tmp.Name()
	fail := func(err error) error { tmp.Close(); os.Remove(name); return err }
	if err := tmp.Chmod(0o600); err != nil {
		return fail(err)
	}
	if _, err := tmp.Write(data); err != nil {
		return fail(err)
	}
	if err := tmp.Sync(); err != nil {
		return fail(err)
	}
	if err := tmp.Close(); err != nil {
		os.Remove(name)
		return err
	}
	if err := os.Rename(name, path); err != nil {
		os.Remove(name)
		return err
	}
	return nil
}

func trimLines(s string) []string {
	var out []string
	for _, l := range strings.Split(s, "\n") {
		l = strings.TrimSpace(l)
		if l == "" || strings.HasPrefix(l, "#") {
			continue
		}
		out = append(out, l)
	}
	return out
}

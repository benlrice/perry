package claudecfg

import (
	"errors"
	"os"
	"path/filepath"
)

// fileEdit is a planned change to one file.
type fileEdit struct {
	path    string // as the user gave it
	real    string // symlinks followed
	old     []byte
	existed bool
	mode    os.FileMode
	new     []byte
}

func (f *fileEdit) changed() bool { return !f.existed || string(f.old) != string(f.new) }

func loadFile(path string) (*fileEdit, error) {
	f := &fileEdit{path: path, real: path, mode: 0o600}
	if r, err := filepath.EvalSymlinks(path); err == nil {
		f.real = r
	}
	st, err := os.Stat(f.real)
	if errors.Is(err, os.ErrNotExist) {
		return f, nil
	}
	if err != nil {
		return nil, err
	}
	if f.old, err = os.ReadFile(f.real); err != nil {
		return nil, err
	}
	f.existed, f.mode = true, st.Mode().Perm()
	return f, nil
}

// write saves the new content. An existing file gets a .bak of the old content
// first. It returns the backup path, if any.
func (f *fileEdit) write() (string, error) {
	dir := filepath.Dir(f.real)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", err
	}
	bak := ""
	if f.existed {
		bak = f.real + ".bak"
		if err := atomic(bak, f.old, 0o600); err != nil {
			return "", err
		}
	}
	return bak, atomic(f.real, f.new, f.mode)
}

func atomic(path string, data []byte, mode os.FileMode) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), ".perry-install-*")
	if err != nil {
		return err
	}
	name := tmp.Name()
	fail := func(err error) error { tmp.Close(); os.Remove(name); return err }
	if err := tmp.Chmod(mode); err != nil {
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

// Package vault owns the encrypted store, the identity, the unlock cache and refs.
package vault

import (
	"os"
	"path/filepath"
)

// ConfigDir returns $XDG_CONFIG_HOME/perry, or ~/.config/perry when the
// variable is empty.
func ConfigDir() string {
	if x := os.Getenv("XDG_CONFIG_HOME"); x != "" {
		return filepath.Join(x, "perry")
	}
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".config", "perry")
}

// StorePath is the encrypted store file.
func StorePath() string { return filepath.Join(ConfigDir(), "store.age") }

func lockPath() string       { return filepath.Join(ConfigDir(), "store.lock") }
func recipientsPath() string { return filepath.Join(ConfigDir(), "recipients") }

// DefaultIdentityPath is the passphrase-wrapped age identity written by keygen.
func DefaultIdentityPath() string { return filepath.Join(ConfigDir(), "identity.age") }

func sshDir() string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".ssh")
}

func defaultSSHKey() string { return filepath.Join(sshDir(), "id_ed25519") }

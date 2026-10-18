// Package vault owns the encrypted store, the identity, the unlock cache and refs.
package vault

import (
	"os"
	"path/filepath"
)

// Names of the variables and files perry reads. Other modules use these, so a
// new one is added here once.
const (
	EnvPrefix     = "PERRY_"
	EnvIdentity   = "PERRY_IDENTITY"
	EnvRecipients = "PERRY_RECIPIENTS"

	storeFile      = "store.age"
	lockFile       = "store.lock"
	recipientsName = "recipients"
	identityFile   = "identity.age"
)

// ConfigFiles lists the file names perry keeps in the config dir.
func ConfigFiles() []string {
	return []string{storeFile, lockFile, recipientsName, identityFile}
}

// ProtectedPaths lists the absolute paths that hold or point to secret
// material: the config dir, and the identity file when PERRY_IDENTITY names one.
func ProtectedPaths() []string {
	paths := []string{ConfigDir()}
	if id := os.Getenv(EnvIdentity); id != "" {
		paths = append(paths, id)
	}
	return paths
}

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
func StorePath() string { return filepath.Join(ConfigDir(), storeFile) }

func lockPath() string       { return filepath.Join(ConfigDir(), lockFile) }
func recipientsPath() string { return filepath.Join(ConfigDir(), recipientsName) }

// DefaultIdentityPath is the passphrase-wrapped age identity written by keygen.
func DefaultIdentityPath() string { return filepath.Join(ConfigDir(), identityFile) }

func sshDir() string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".ssh")
}

func defaultSSHKey() string { return filepath.Join(sshDir(), "id_ed25519") }

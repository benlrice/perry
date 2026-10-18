package vault

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"math"
	"strconv"
	"strings"
	"time"

	"golang.org/x/sys/unix"
)

// ErrLocked means the identity is passphrase-protected and the unlock cache is
// absent or expired.
var ErrLocked = errors.New("locked — run `perry unlock` in your terminal")

const (
	keyType = "user"
	// possessor: all rights; user, group, other: none.
	keyPerm = 0x3f0000
)

func cacheDesc() string {
	sum := sha256.Sum256([]byte(absStorePath()))
	return "perry:" + hex.EncodeToString(sum[:8])
}

func absStorePath() string { return StorePath() }

// joinSession gives the process a session keyring that links the user keyring,
// so the key is possessed. Without it setperm fails on logins that lack
// pam_keyinit. Errors are ignored; later calls report them.
func joinSession() {
	if _, err := unix.KeyctlJoinSessionKeyring(""); err != nil {
		return
	}
	unix.KeyctlInt(unix.KEYCTL_LINK, unix.KEY_SPEC_USER_KEYRING, unix.KEY_SPEC_SESSION_KEYRING, 0, 0)
}

// CachePut stores the unwrapped identity for ttl. The TTL is absolute.
func CachePut(identity string, ttl time.Duration) (time.Time, error) {
	joinSession()
	secs := int(math.Ceil(ttl.Seconds()))
	if secs < 1 {
		secs = 1 // 0 would mean "no timeout"
	}
	expiry := time.Now().Add(time.Duration(secs) * time.Second)
	payload := strconv.FormatInt(expiry.Unix(), 10) + "\n" + identity
	id, err := unix.AddKey(keyType, cacheDesc(), []byte(payload), unix.KEY_SPEC_USER_KEYRING)
	if err != nil {
		return time.Time{}, fmt.Errorf("keyring unavailable: %w", err)
	}
	if err := unix.KeyctlSetperm(id, keyPerm); err != nil {
		unix.KeyctlInt(unix.KEYCTL_INVALIDATE, id, 0, 0, 0)
		return time.Time{}, fmt.Errorf("keyring unavailable: %w", err)
	}
	if _, err := unix.KeyctlInt(unix.KEYCTL_SET_TIMEOUT, id, secs, 0, 0); err != nil {
		unix.KeyctlInt(unix.KEYCTL_INVALIDATE, id, 0, 0, 0)
		return time.Time{}, fmt.Errorf("keyring unavailable: %w", err)
	}
	return expiry, nil
}

func isAbsent(err error) bool {
	return errors.Is(err, unix.ENOKEY) || errors.Is(err, unix.EKEYEXPIRED) || errors.Is(err, unix.EKEYREVOKED)
}

// CacheGet returns the cached identity and its expiry. ok is false when locked.
func CacheGet() (identity string, expiry time.Time, ok bool, err error) {
	joinSession()
	id, err := unix.KeyctlSearch(unix.KEY_SPEC_USER_KEYRING, keyType, cacheDesc(), 0)
	if err != nil {
		if isAbsent(err) {
			return "", time.Time{}, false, nil
		}
		return "", time.Time{}, false, fmt.Errorf("keyring unavailable: %w", err)
	}
	buf := make([]byte, 4096)
	for {
		n, err := unix.KeyctlBuffer(unix.KEYCTL_READ, id, buf, 0)
		if err != nil {
			if isAbsent(err) {
				return "", time.Time{}, false, nil
			}
			return "", time.Time{}, false, fmt.Errorf("keyring unavailable: %w", err)
		}
		if n > len(buf) {
			buf = make([]byte, n)
			continue
		}
		buf = buf[:n]
		break
	}
	head, body, found := strings.Cut(string(buf), "\n")
	secs, perr := strconv.ParseInt(head, 10, 64)
	if !found || perr != nil {
		return "", time.Time{}, false, nil
	}
	expiry = time.Unix(secs, 0)
	if !expiry.After(time.Now()) {
		return "", time.Time{}, false, nil
	}
	return body, expiry, true, nil
}

// CacheDrop removes the cached identity. An absent key is success.
func CacheDrop() error {
	joinSession()
	id, err := unix.KeyctlSearch(unix.KEY_SPEC_USER_KEYRING, keyType, cacheDesc(), 0)
	if err != nil {
		if isAbsent(err) {
			return nil
		}
		return fmt.Errorf("keyring unavailable: %w", err)
	}
	if _, err := unix.KeyctlInt(unix.KEYCTL_INVALIDATE, id, 0, 0, 0); err != nil && !isAbsent(err) {
		return fmt.Errorf("keyring unavailable: %w", err)
	}
	return nil
}

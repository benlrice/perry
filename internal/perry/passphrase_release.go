//go:build !perrytest

package perry

// testPassphrase is off in release builds: PERRY_PASSPHRASE is ignored.
func testPassphrase() (string, bool) { return "", false }

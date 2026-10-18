//go:build perrytest

package perry

import "os"

// testPassphrase lets the black-box tests answer passphrase prompts.
func testPassphrase() (string, bool) { return os.LookupEnv("PERRY_PASSPHRASE") }

package perry

import (
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/benlrice/perry/internal/vault"
	"golang.org/x/term"
)

// prompter reads a passphrase. Source order: the test-build variable, then the
// non-interactive error, then /dev/tty.
func prompter(prompt string, confirm bool) (string, error) {
	if p, ok := testPassphrase(); ok {
		if p == "" {
			return "", errors.New("empty passphrase")
		}
		return p, nil
	}
	if nonInteractive {
		return "", errors.New("passphrase unavailable (non-interactive)")
	}
	tty, err := os.OpenFile("/dev/tty", os.O_RDWR, 0)
	if err != nil {
		return "", errors.New("passphrase required but no TTY available")
	}
	defer tty.Close()
	ask := func(p string) (string, error) {
		fmt.Fprint(tty, p)
		b, err := term.ReadPassword(int(tty.Fd()))
		fmt.Fprintln(tty)
		return string(b), err
	}
	pass, err := ask(prompt)
	if err != nil {
		return "", err
	}
	if confirm {
		again, err := ask("Repeat passphrase: ")
		if err != nil {
			return "", err
		}
		if again != pass {
			return "", errors.New("passphrases do not match")
		}
	}
	if pass == "" {
		return "", errors.New("empty passphrase")
	}
	return pass, nil
}

var _ vault.Prompter = prompter

func fdOf(r any) (int, bool) {
	if f, ok := r.(*os.File); ok {
		return int(f.Fd()), true
	}
	return 0, false
}

func isTerminal(r any) bool {
	fd, ok := fdOf(r)
	return ok && term.IsTerminal(fd)
}

// readSecret reads a hidden line on a TTY, otherwise all of stdin with the
// trailing CR and LF removed. It never reads the secret from argv.
func readSecret(prompt string) (string, error) {
	if fd, ok := fdOf(stdin); ok && term.IsTerminal(fd) {
		fmt.Fprint(stderr, prompt)
		b, err := term.ReadPassword(fd)
		fmt.Fprintln(stderr)
		return string(b), err
	}
	b, err := io.ReadAll(stdin)
	if err != nil {
		return "", err
	}
	return strings.TrimRight(string(b), "\r\n"), nil
}

// readLine reads one line byte by byte so no later input is buffered away.
func readLine(r io.Reader) (string, error) {
	var sb strings.Builder
	buf := make([]byte, 1)
	for {
		n, err := r.Read(buf)
		if n > 0 {
			if buf[0] == '\n' {
				return strings.TrimRight(sb.String(), "\r"), nil
			}
			sb.WriteByte(buf[0])
		}
		if err != nil {
			if err == io.EOF && sb.Len() > 0 {
				return sb.String(), nil
			}
			return sb.String(), err
		}
	}
}

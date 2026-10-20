// Package leak answers one question: does any text hold a stored secret?
package leak

import (
	"errors"

	"github.com/benlrice/perry/internal/redact"
	"github.com/benlrice/perry/internal/vault"
)

// Verdict is the outcome of a check.
type Verdict int

const (
	// Clean means no text holds a stored secret.
	Clean Verdict = iota
	// Leaked means at least one text holds a stored secret.
	Leaked
	// Locked means the store needs an unlock, so nothing was checked.
	Locked
	// Unverifiable means the store could not be read for another reason.
	Unverifiable
)

// Result is a verdict with the store error behind Unverifiable and Locked. It
// never names the entry or the text that matched.
type Result struct {
	Verdict Verdict
	Err     error
}

// In reports whether any text holds a form of any secret in d.
func In(d *vault.Data, texts ...string) bool {
	return redact.New(d.Entries, nil).Contains(texts...)
}

// Check reads the store and runs In on it.
func Check(texts ...string) Result {
	var hit bool
	err := vault.View(func(d *vault.Data) error {
		hit = In(d, texts...)
		return nil
	})
	switch {
	case errors.Is(err, vault.ErrLocked):
		return Result{Locked, err}
	case err != nil:
		return Result{Unverifiable, err}
	case hit:
		return Result{Verdict: Leaked}
	}
	return Result{}
}

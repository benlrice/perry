// Package inject turns a command that names stored entries into a Plan: the
// argv and environment with real values, and a scrubber for the output.
package inject

import (
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"syscall"

	"github.com/benlrice/perry/internal/redact"
	"github.com/benlrice/perry/internal/vault"
)

// EnvSpec sets one child variable from a stored field.
type EnvSpec struct{ Name, Ref string }

// Request describes one command to run.
type Request struct {
	Argv []string
	// ExpandArgv replaces {{perry:REF[:field]}} placeholders in Argv. When it
	// is false, Argv is passed as written.
	ExpandArgv bool
	Env        []EnvSpec
}

// Streams are the child's standard streams.
type Streams struct {
	In       io.Reader
	Out, Err io.Writer
}

// Plan is a command ready to run. It holds copies of every value it needs, so
// the store can be unlocked before Run.
type Plan struct {
	Argv []string
	Env  []string
	// Hint is a warning for stderr. It never holds a value.
	Hint  string
	scrub *redact.Redactor
}

// errSet collects error messages without repeats, in first-seen order.
type errSet struct {
	seen map[string]bool
	msgs []string
}

func (s *errSet) add(err error) {
	m := err.Error()
	if s.seen == nil {
		s.seen = map[string]bool{}
	}
	if !s.seen[m] {
		s.seen[m] = true
		s.msgs = append(s.msgs, m)
	}
}

// Prepare resolves every ref in req against d. The error it returns is already
// scrubbed, so a caller can print it as it is.
func Prepare(d *vault.Data, req Request) (*Plan, error) {
	var refs []vault.Ref
	var errs errSet
	resolve := func(ref string) (string, bool) {
		r, err := d.ResolveRef(ref, "")
		if err != nil {
			errs.add(err)
			return "", false
		}
		refs = append(refs, r)
		v := r.Entry.Field(r.Field)
		if v == "" {
			errs.add(emptyFieldError(r))
		}
		return v, true
	}

	p := &Plan{Argv: append([]string(nil), req.Argv...), Env: childEnv()}
	if req.ExpandArgv {
		for i, w := range req.Argv {
			p.Argv[i] = placeholderRe.ReplaceAllStringFunc(w, func(ph string) string {
				if v, ok := resolve(placeholderRe.FindStringSubmatch(ph)[1]); ok {
					return v
				}
				return ph
			})
		}
	}
	for _, s := range req.Env {
		if v, ok := resolve(s.Ref); ok {
			p.Env = append(p.Env, s.Name+"="+v)
		}
	}

	p.scrub = redact.New(items(d, refs))
	if len(errs.msgs) > 0 {
		return nil, errors.New(p.scrub.Scrub(strings.Join(errs.msgs, "; ")))
	}
	if req.ExpandArgv {
		p.Hint = curlUserHint(req.Argv)
	}
	return p, nil
}

// Run starts the command with scrubbed streams and returns its exit code:
// the child's own code, or 128 plus the signal number.
func (p *Plan) Run(s Streams) (int, error) {
	cmd := exec.Command(p.Argv[0], p.Argv[1:]...)
	cmd.Env = p.Env
	cmd.Stdin = s.In
	so, se := p.scrub.Writer(s.Out), p.scrub.Writer(s.Err)
	cmd.Stdout, cmd.Stderr = so, se
	err := cmd.Run()
	so.Flush()
	se.Flush()
	if err == nil {
		return 0, nil
	}
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		if ws, ok := ee.Sys().(syscall.WaitStatus); ok && ws.Signaled() {
			return 128 + int(ws.Signal()), nil
		}
		return ee.ExitCode(), nil
	}
	return 0, err
}

// childEnv is the parent environment minus every PERRY_* variable.
func childEnv() []string {
	var env []string
	for _, kv := range os.Environ() {
		if !strings.HasPrefix(kv, vault.EnvPrefix) {
			env = append(env, kv)
		}
	}
	return env
}

// emptyFieldError names the entry and the fix for an empty field value.
func emptyFieldError(r vault.Ref) error {
	e := r.Entry
	switch r.Field {
	case "username":
		return fmt.Errorf("entry %s has no username (set with: perry edit %s --set-user U)", e.Host, e.Host)
	case "notes":
		return fmt.Errorf("entry %s has no notes (set with: perry edit %s --notes TEXT)", e.Host, e.Host)
	}
	return fmt.Errorf("entry %s has an empty secret (replace with: perry add --host %s --kind %s --update)", e.Host, e.Host, e.Kind)
}

// items builds the redactor input: referenced entries under their ref label,
// every other entry under its host.
func items(d *vault.Data, refs []vault.Ref) []redact.Item {
	var out []redact.Item
	used := map[string]bool{}
	for _, r := range refs {
		e := r.Entry
		out = append(out, redact.Item{Host: e.Host, Kind: e.Kind, Secret: e.Secret, Username: e.Username, Label: r.Label})
		used[e.Host+"\x00"+e.Kind] = true
	}
	for _, e := range d.Entries {
		if !used[e.Host+"\x00"+e.Kind] {
			out = append(out, redact.Item{Host: e.Host, Kind: e.Kind, Secret: e.Secret, Username: e.Username})
		}
	}
	return out
}

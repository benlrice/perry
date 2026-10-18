package perry

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"syscall"

	"github.com/benlrice/perry/internal/redact"
	"github.com/benlrice/perry/internal/vault"
)

// childEnv is the parent environment minus every PERRY_* variable.
func childEnv() []string {
	var env []string
	for _, kv := range os.Environ() {
		if !strings.HasPrefix(kv, "PERRY_") {
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

// startChild runs argv with the scrubbed streams and returns its exit code.
func startChild(argv, env []string, r *redact.Redactor) (int, error) {
	cmd := exec.Command(argv[0], argv[1:]...)
	cmd.Env = env
	cmd.Stdin = stdin
	so, se := r.Writer(stdout), r.Writer(stderr)
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

func cmdRun(args []string) error {
	if len(args) > 0 && args[0] == "--" {
		args = args[1:]
	} else if len(args) > 0 && strings.HasPrefix(args[0], "-") {
		return usageErrorf("unknown option %q", args[0])
	}
	if len(args) == 0 {
		return usageErrorf("usage: perry run [--] CMD [ARG]...")
	}
	argv := make([]string, len(args))
	copy(argv, args)

	var code int
	err := vault.View(func(d *vault.Data) error {
		var refs []vault.Ref
		var errs []string
		seen := map[string]bool{}
		for i, w := range args {
			argv[i] = placeholderRe.ReplaceAllStringFunc(w, func(ph string) string {
				ref := placeholderRe.FindStringSubmatch(ph)[1]
				r, err := d.ResolveRef(ref, "")
				if err != nil {
					if m := err.Error(); !seen[m] {
						seen[m], errs = true, append(errs, m)
					}
					return ph
				}
				refs = append(refs, r)
				v := r.Entry.Field(r.Field)
				if v == "" {
					err := emptyFieldError(r)
					if m := err.Error(); !seen[m] {
						seen[m], errs = true, append(errs, m)
					}
				}
				return v
			})
		}
		red := redact.New(items(d, refs))
		if len(errs) > 0 {
			fmt.Fprintf(stderr, "perry: run: %s\n", red.Scrub(strings.Join(errs, "; ")))
			code = 1
			return nil
		}
		if h := curlUserHint(args); h != "" {
			fmt.Fprintln(stderr, h)
		}
		var err error
		code, err = startChild(argv, childEnv(), red)
		return err
	})
	if err != nil {
		return err
	}
	if code != 0 {
		return &exitError{code: code}
	}
	return nil
}

func cmdExec(args []string) error {
	type spec struct{ name, ref string }
	var specs []spec
	i := 0
loop:
	for ; i < len(args); i++ {
		a := args[i]
		var v string
		switch {
		case a == "--":
			i++
			break loop
		case a == "--env" || a == "-env" || a == "-e":
			if i+1 >= len(args) {
				return usageErrorf("%s needs VAR=REF", a)
			}
			i++
			v = args[i]
		case strings.HasPrefix(a, "--env="):
			v = strings.TrimPrefix(a, "--env=")
		case strings.HasPrefix(a, "-env="):
			v = strings.TrimPrefix(a, "-env=")
		case strings.HasPrefix(a, "-e="):
			v = strings.TrimPrefix(a, "-e=")
		default:
			return usageErrorf("unknown option %q", a)
		}
		name, ref, ok := strings.Cut(v, "=")
		if !ok {
			return usageErrorf("--env %q needs VAR=REF", v)
		}
		if name == "" || ref == "" {
			return usageErrorf("--env %q needs a name and a ref", v)
		}
		specs = append(specs, spec{name, ref})
	}
	if len(specs) == 0 {
		return usageErrorf("no --env given")
	}
	argv := args[i:]
	if len(argv) == 0 {
		return usageErrorf("usage: perry exec --env VAR=REF... -- CMD [ARG]...")
	}

	var code int
	err := vault.View(func(d *vault.Data) error {
		var refs []vault.Ref
		env := childEnv()
		var errs []string
		seen := map[string]bool{}
		for _, s := range specs {
			r, err := d.ResolveRef(s.ref, "")
			if err == nil && r.Entry.Field(r.Field) == "" {
				err = emptyFieldError(r)
			}
			if err != nil {
				if m := err.Error(); !seen[m] {
					seen[m], errs = true, append(errs, m)
				}
				continue
			}
			refs = append(refs, r)
			env = append(env, s.name+"="+r.Entry.Field(r.Field))
		}
		red := redact.New(items(d, refs))
		if len(errs) > 0 {
			fmt.Fprintf(stderr, "perry: exec: %s\n", red.Scrub(strings.Join(errs, "; ")))
			code = 1
			return nil
		}
		var err error
		code, err = startChild(argv, env, red)
		return err
	})
	if err != nil {
		return err
	}
	if code != 0 {
		return &exitError{code: code}
	}
	return nil
}

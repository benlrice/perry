package perry

import (
	"fmt"
	"strings"

	"github.com/benlrice/perry/internal/inject"
	"github.com/benlrice/perry/internal/vault"
)

func cmdRun(args []string) error {
	if len(args) > 0 && args[0] == "--" {
		args = args[1:]
	} else if len(args) > 0 && strings.HasPrefix(args[0], "-") {
		return usageErrorf("unknown option %q", args[0])
	}
	if len(args) == 0 {
		return usageErrorf("usage: perry run [--] CMD [ARG]...")
	}
	return runPlan("run", inject.Request{Argv: args, ExpandArgv: true})
}

func cmdExec(args []string) error {
	type spec struct{ name, ref string }
	var envs []spec
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
		envs = append(envs, spec{name, ref})
	}
	if len(envs) == 0 {
		return usageErrorf("no --env given")
	}
	argv := args[i:]
	if len(argv) == 0 {
		return usageErrorf("usage: perry exec --env VAR=REF... -- CMD [ARG]...")
	}

	specs := make([]inject.EnvSpec, len(envs))
	for k, e := range envs {
		specs[k] = inject.EnvSpec{Name: e.name, Ref: e.ref}
	}
	return runPlan("exec", inject.Request{Argv: argv, Env: specs})
}

// runPlan prepares the request under the store lock, then runs the child with
// the lock released.
func runPlan(name string, req inject.Request) error {
	var plan *inject.Plan
	err := vault.View(func(d *vault.Data) error {
		var err error
		plan, err = inject.Prepare(d, req)
		if err != nil {
			return &exitError{1, err.Error()}
		}
		return nil
	})
	if err != nil {
		return err
	}
	if plan.Hint != "" {
		fmt.Fprintln(stderr, plan.Hint)
	}
	code, err := plan.Run(inject.Streams{In: stdin, Out: stdout, Err: stderr})
	if err != nil {
		return err
	}
	if code != 0 {
		return &exitError{code: code}
	}
	return nil
}

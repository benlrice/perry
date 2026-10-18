// Package perry is the command line: flags, prompts, output and exit codes.
package perry

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/benlrice/perry/internal/vault"
)

// Standard streams. Commands use these so tests can swap them.
var (
	stdin  io.Reader = os.Stdin
	stdout io.Writer = os.Stdout
	stderr io.Writer = os.Stderr
)

// nonInteractive is set by the hook: a prompt inside a hook blocks the agent.
var nonInteractive bool

// exitError carries an exit code. An empty msg prints nothing.
type exitError struct {
	code int
	msg  string
}

func (e *exitError) Error() string { return e.msg }

func usageErrorf(format string, a ...any) error {
	return &exitError{2, fmt.Sprintf(format, a...)}
}

type command struct {
	run func(args []string) error
}

var dispatch map[string]func(args []string) error

func init() {
	dispatch = map[string]func([]string) error{
		"add": cmdAdd, "list": cmdList, "search": cmdSearch, "show": cmdShow, "get": cmdGet,
		"run": cmdRun, "exec": cmdExec, "edit": cmdEdit, "rm": cmdRm, "import": cmdImport,
		"scan": cmdScan, "hook": cmdHook, "keygen": cmdKeygen, "unlock": cmdUnlock,
		"lock": cmdLock, "status": cmdStatus, "rekey": cmdRekey, "install": cmdInstall,
	}
}

func isHelpFlag(a string) bool { return a == "-h" || a == "--help" || a == "-help" }

// Main runs the CLI and returns the process exit code.
func Main(args []string) int {
	if len(args) == 0 {
		fmt.Fprint(stderr, usageText())
		return 2
	}
	name, rest := args[0], args[1:]
	switch {
	case name == "help":
		return printHelp(rest)
	case isHelpFlag(name):
		fmt.Fprint(stdout, usageText())
		return 0
	}
	fn, ok := dispatch[name]
	if !ok {
		fmt.Fprintf(stderr, "perry: unknown command %q; run `perry help` for the command list\n", name)
		return 2
	}
	if wantsHelp(name, rest) {
		fmt.Fprint(stdout, commandHelp(name))
		return 0
	}
	err := fn(rest)
	if err == nil {
		return 0
	}
	var ee *exitError
	if errors.As(err, &ee) {
		if ee.msg != "" {
			fmt.Fprintf(stderr, "perry: %s: %s\n", name, ee.msg)
		}
		return ee.code
	}
	fmt.Fprintf(stderr, "perry: %s: %v\n", name, err)
	if errors.Is(err, vault.ErrLocked) {
		return 3
	}
	return 1
}

// wantsHelp: for every command except run, a help flag before a literal --
// asks for help. For run, only a first argument that is a help flag does.
func wantsHelp(name string, args []string) bool {
	if name == "run" {
		return len(args) > 0 && isHelpFlag(args[0])
	}
	for _, a := range args {
		if a == "--" {
			return false
		}
		if isHelpFlag(a) {
			return true
		}
	}
	return false
}

func printHelp(args []string) int {
	if len(args) == 0 {
		fmt.Fprint(stdout, usageText())
		return 0
	}
	if _, ok := dispatch[args[0]]; !ok {
		fmt.Fprintf(stderr, "perry: unknown command %q; run `perry help` for the command list\n", args[0])
		return 2
	}
	fmt.Fprint(stdout, commandHelp(args[0]))
	return 0
}

// parseFlags parses flags that may come before or after positional arguments.
func parseFlags(fs *flag.FlagSet, args []string) ([]string, error) {
	fs.SetOutput(io.Discard)
	var pos []string
	for {
		if err := fs.Parse(args); err != nil {
			return nil, usageErrorf("%v", err)
		}
		args = fs.Args()
		if len(args) == 0 {
			return pos, nil
		}
		pos = append(pos, args[0])
		args = args[1:]
	}
}

// stringList is a repeatable flag.
type stringList []string

func (s *stringList) String() string     { return strings.Join(*s, ",") }
func (s *stringList) Set(v string) error { *s = append(*s, v); return nil }

func flagSet(name string) *flag.FlagSet { return flag.NewFlagSet(name, flag.ContinueOnError) }

func wasSet(fs *flag.FlagSet, name string) bool {
	set := false
	fs.Visit(func(f *flag.Flag) {
		if f.Name == name {
			set = true
		}
	})
	return set
}

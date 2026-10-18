package perry

import (
	"fmt"
	"strings"
)

type cmdInfo struct {
	name, summary, usage string
	flags                []string
	examples             []string
	notes                string
}

// cmdTable drives per-command help and the top-level listing. A test compares
// it with the dispatch map.
var cmdTable = []cmdInfo{
	{"add", "Store a credential.", "perry add --host H --kind K [--user U] [--auth A] [--tag T]... [--notes N] [--update]",
		[]string{"--host H  host name", "--kind K  kind, for example jira", "--user U  username (blank for token-only)", "--auth A  basic, bearer or token", "--tag T  tag (repeatable)", "--notes N  free text", "--update  replace an existing entry"},
		[]string{"printf '%s' \"$TOKEN\" | perry add --host jira.example.com --kind jira --user alice --auth basic"},
		"The secret comes from a hidden prompt or from stdin. It is never read from the command line."},
	{"list", "List entries without secrets.", "perry list", nil, nil, "Sorted by host, then kind."},
	{"search", "Find entries by keyword.", "perry search KEYWORD", nil, []string{"perry search jira"},
		"Case-insensitive match on host, kind, notes and tags."},
	{"show", "Show one entry without the secret.", "perry show REF [--kind K]", []string{"--kind K  narrow an ambiguous ref"}, nil,
		"Prints a ready usage line when an auth style is set."},
	{"get", "Print one field. User terminal only.", "perry get REF --reveal [--kind K]", []string{"--reveal  required"}, nil,
		"Refuses when stdout is not a terminal. The Claude hook denies this command."},
	{"run", "Run a command with placeholders replaced.", "perry run [--] CMD [ARG]...", nil,
		[]string{"perry run -- curl -u '{{perry:H:username}}:{{perry:H}}' URL"},
		"Output is scrubbed. PERRY_* variables are removed from the child environment."},
	{"exec", "Run a command with secrets in environment variables.", "perry exec --env VAR=REF... -- CMD [ARG]...",
		[]string{"--env VAR=REF  set VAR from REF (repeatable)"}, []string{"perry exec --env TOKEN=github -- gh api user"},
		"Output is scrubbed."},
	{"edit", "Change entry metadata. The secret stays.", "perry edit REF [--kind K] [--set-host H] [--set-kind K] [--set-user U] [--set-auth A] [--notes N] [--tag T]... [--add-tag T] [--rm-tag T]",
		[]string{"--set-host H", "--set-kind K", "--set-user U", "--set-auth A  empty clears", "--notes N", "--tag T  replace all tags", "--add-tag T", "--rm-tag T"}, nil, ""},
	{"rm", "Remove an entry.", "perry rm REF [--kind K]", []string{"--kind K  narrow an ambiguous ref"}, nil, ""},
	{"import", "Import credentials from a text file. User terminal only.", "perry import FILE", nil, nil,
		"Asks for a missing host or kind. Prints labels, never secrets."},
	{"scan", "Check stdin for a stored secret.", "perry scan < FILE", nil, nil,
		"Exit 0 when clean, 1 when a stored secret is found."},
	{"hook", "Claude Code PreToolUse hook.", "perry hook [--paths-only]", []string{"--paths-only  path checks only; never opens the store"}, nil,
		"Reads the hook JSON on stdin. Always exits 0 when it runs normally."},
	{"keygen", "Create a passphrase-protected identity.", "perry keygen [--out PATH]", []string{"--out PATH  default: identity.age in the config dir"}, nil,
		"Prints the public recipient on stdout."},
	{"unlock", "Unlock a passphrase-protected identity. User terminal only.", "perry unlock [--ttl DURATION | --until HH:MM]",
		[]string{"--ttl DURATION  default 8h", "--until HH:MM  next local occurrence"}, nil, ""},
	{"lock", "Forget the unlocked identity.", "perry lock", nil, nil, "Exits 0 even when already locked."},
	{"status", "Show the lock state.", "perry status", nil, nil, "Exits 3 when locked."},
	{"rekey", "Re-encrypt the store to a new identity. User terminal only.", "perry rekey [--from PATH] [--to PATH] [--no-backup]",
		[]string{"--from PATH  old identity", "--to PATH  new identity", "--no-backup  do not keep .bak files"}, nil, ""},
	{"install", "Install the hook, deny rules and CLAUDE.md block. User terminal only.", "perry install claude [--dry-run] [--uninstall] [--paths-only] [--settings FILE] [--claude-md FILE]",
		[]string{"--dry-run  show changes, write nothing", "--uninstall  remove the hook and CLAUDE.md block", "--paths-only  lightweight hook", "--settings FILE", "--claude-md FILE"}, nil, ""},
}

func usageText() string {
	var b strings.Builder
	b.WriteString("usage: perry COMMAND [ARGS]\n\nCommands:\n")
	for _, c := range cmdTable {
		fmt.Fprintf(&b, "  %-8s %s\n", c.name, c.summary)
	}
	b.WriteString("\nRun `perry help COMMAND` for details.\n")
	return b.String()
}

func commandHelp(name string) string {
	for _, c := range cmdTable {
		if c.name != name {
			continue
		}
		var b strings.Builder
		fmt.Fprintf(&b, "%s\n\nusage: %s\n", c.summary, c.usage)
		if len(c.flags) > 0 {
			b.WriteString("\nOptions:\n")
			for _, f := range c.flags {
				fmt.Fprintf(&b, "  %s\n", f)
			}
		}
		if len(c.examples) > 0 {
			b.WriteString("\nExamples:\n")
			for _, e := range c.examples {
				fmt.Fprintf(&b, "  %s\n", e)
			}
		}
		if c.notes != "" {
			fmt.Fprintf(&b, "\n%s\n", c.notes)
		}
		return b.String()
	}
	return ""
}

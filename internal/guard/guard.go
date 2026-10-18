// Package guard decides whether Claude Code may run a tool call.
package guard

import (
	"encoding/json"
	"errors"
	"regexp"

	"github.com/benlrice/perry/internal/redact"
	"github.com/benlrice/perry/internal/vault"
)

// Input is the part of the hook payload that the guard reads.
type Input struct {
	CWD       string
	ToolName  string
	ToolInput json.RawMessage
	PathsOnly bool
}

// Decision is the verdict. Reason never contains a secret.
type Decision struct {
	Deny   bool
	Reason string
	// Locked is set when the store was locked: only path checks ran.
	Locked bool
}

func deny(reason string) Decision { return Decision{Deny: true, Reason: reason} }

var writeTools = map[string]bool{"Write": true, "Edit": true, "MultiEdit": true, "NotebookEdit": true}

// Decide applies the checks in order.
func Decide(in Input) Decision {
	raw := string(in.ToolInput)
	var tree any
	_ = json.Unmarshal(in.ToolInput, &tree)
	all := append([]string{raw}, collect(tree)...)

	bash := in.ToolName == "Bash"
	pathTexts := all
	var cmd string
	switch {
	case bash:
		cmd = stripData(bashCommand(tree))
		pathTexts = replaceCommand(tree, cmd)
	case writeTools[in.ToolName]:
		pathTexts = pathFields(tree)
	}

	pc := newPathChecker()
	for _, t := range pathTexts {
		if label, m, ok := pc.check(t, false); ok {
			return deny("blocked access to " + label + ` (matched "` + m + `").`)
		}
	}
	if bash {
		if label, m, ok := pc.relative(in.CWD, cmd); ok {
			return deny("blocked access to " + label + ` (matched "` + m + `").`)
		}
		if d, ok := userOnly(cmd); ok {
			return d
		}
	}
	if in.PathsOnly {
		return Decision{}
	}

	var hit bool
	err := vault.View(func(d *vault.Data) error {
		for _, e := range d.Entries {
			for _, t := range all {
				if redact.Contains(t, e.Secret, e.Username) {
					hit = true
					return nil
				}
			}
		}
		return nil
	})
	switch {
	case errors.Is(err, vault.ErrLocked):
		return Decision{Locked: true}
	case err != nil:
		if bash {
			return deny("blocked: cannot verify command against the secret store.")
		}
		return Decision{}
	case hit:
		return deny("blocked: tool input contains a stored secret.")
	}
	return Decision{}
}

// collect returns every string key and value in a decoded JSON tree.
func collect(v any) []string {
	var out []string
	var walk func(any)
	walk = func(v any) {
		switch x := v.(type) {
		case string:
			out = append(out, x)
		case []any:
			for _, e := range x {
				walk(e)
			}
		case map[string]any:
			for k, e := range x {
				out = append(out, k)
				walk(e)
			}
		}
	}
	walk(v)
	return out
}

func bashCommand(tree any) string {
	if m, ok := tree.(map[string]any); ok {
		if s, ok := m["command"].(string); ok {
			return s
		}
	}
	return ""
}

// replaceCommand is collect(tree) with the command value swapped for its
// stripped form.
func replaceCommand(tree any, stripped string) []string {
	m, ok := tree.(map[string]any)
	if !ok {
		return collect(tree)
	}
	cp := make(map[string]any, len(m))
	for k, v := range m {
		cp[k] = v
	}
	cp["command"] = stripped
	return collect(cp)
}

func pathFields(tree any) []string {
	m, ok := tree.(map[string]any)
	if !ok {
		return nil
	}
	var out []string
	for _, k := range []string{"file_path", "notebook_path"} {
		if s, ok := m[k].(string); ok {
			out = append(out, s)
		}
	}
	return out
}

const cmdB = "(?:^|[\\s;&|(`'\"/])"

var (
	helpRe = regexp.MustCompile(`(perry(?:\s+-\S*)*\s+)(get|unlock|install)([^;&|\n]*?\s(?:--help|-help|-h)(?:\s|$))`)
	userRe = []struct {
		re     *regexp.Regexp
		reason string
	}{
		{regexp.MustCompile(cmdB + `perry(?:\s+-\S*)*\s+get\b`), "blocked: `perry get` / --reveal is for the user's terminal only"},
		{regexp.MustCompile(`(?:^|\s)--?reveal\b`), "blocked: `perry get` / --reveal is for the user's terminal only"},
		{regexp.MustCompile(cmdB + `perry(?:\s+-\S*)*\s+unlock\b`), "blocked: `perry unlock` is for the user's own terminal only"},
		{regexp.MustCompile(cmdB + `perry(?:\s+-\S*)*\s+rekey\b`), "blocked: `perry rekey` is for the user's own terminal only"},
		{regexp.MustCompile(cmdB + `perry(?:\s+-\S*)*\s+install\b`), "blocked: `perry install` edits the Claude settings; the user runs it from their own terminal"},
		{regexp.MustCompile(cmdB + `keyctl\b`), "blocked: `keyctl` could expose the unlock cache"},
	}
)

func userOnly(cmd string) (Decision, bool) {
	text := helpRe.ReplaceAllString(cmd, "${1}HELP${3}")
	for _, u := range userRe {
		if m := u.re.FindString(text); m != "" {
			return deny(u.reason + ` (matched "` + trimMatch(m) + `").`), true
		}
	}
	return Decision{}, false
}

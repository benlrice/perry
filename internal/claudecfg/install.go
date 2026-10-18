// Package claudecfg installs perry into the Claude Code settings and CLAUDE.md.
package claudecfg

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"strings"
)

const (
	// FullMatcher covers every tool that can carry or send a secret.
	FullMatcher      = "Read|Bash|Grep|Glob|Edit|Write|MultiEdit|NotebookEdit|WebFetch|mcp__.*"
	PathsOnlyMatcher = "Bash"

	beginMarker = "<!-- perry:begin (managed by `perry install claude`; edits inside are overwritten) -->"
	endMarker   = "<!-- perry:end -->"
	heading     = "## Credentials (perry)"
)

// Options controls Install.
type Options struct {
	SettingsPath, ClaudeMDPath string
	Exe                        string // absolute path of the running binary
	Doc                        string // docs/claude-code.md
	DryRun, Uninstall          bool
	PathsOnly                  bool
}

// Report is the text for the user.
type Report struct{ Lines []string }

func (r Report) String() string { return strings.Join(r.Lines, "\n") + "\n" }

var perryHookRe = regexp.MustCompile(`(^|[/'"\s])perry['"]?\s+hook(\s+--paths-only)?\s*$`)

// HookCommand is the shell-quoted binary path plus the hook subcommand.
func HookCommand(exe string, pathsOnly bool) string {
	q := exe
	if !regexp.MustCompile(`^[A-Za-z0-9_@%+=:,./-]+$`).MatchString(exe) {
		q = "'" + strings.ReplaceAll(exe, "'", `'\''`) + "'"
	}
	if pathsOnly {
		return q + " hook --paths-only"
	}
	return q + " hook"
}

// Install plans both files, then writes them. Nothing is written on an error
// or in a dry run.
func Install(o Options) (Report, error) {
	doc, err := parseDoc(o.Doc)
	if err != nil {
		return Report{}, err
	}
	sf, err := loadFile(o.SettingsPath)
	if err != nil {
		return Report{}, err
	}
	mf, err := loadFile(o.ClaudeMDPath)
	if err != nil {
		return Report{}, err
	}
	sNotes, err := editSettings(sf, doc, o)
	if err != nil {
		return Report{}, fmt.Errorf("%s: %w", o.SettingsPath, err)
	}
	mNotes, err := editClaudeMD(mf, doc, o)
	if err != nil {
		return Report{}, fmt.Errorf("%s: %w", o.ClaudeMDPath, err)
	}

	var rep Report
	prefix := ""
	if o.DryRun {
		prefix = "(dry run) "
	}
	line := func(s string) { rep.Lines = append(rep.Lines, prefix+s) }
	for _, e := range []struct {
		f     *fileEdit
		notes []string
	}{{sf, sNotes}, {mf, mNotes}} {
		line(e.f.path)
		for _, n := range e.notes {
			line("  " + n)
		}
		if !e.f.changed() {
			line("  nothing to change")
			continue
		}
		if o.DryRun {
			continue
		}
		bak, err := e.f.write()
		if err != nil {
			return rep, err
		}
		if bak != "" {
			line("  backup: " + bak)
		}
	}
	if !o.DryRun && !o.Uninstall {
		if err := verify(o.Exe, doc.Probe); err != nil {
			return rep, err
		}
		line("verify: hook denies the credential-file probe")
	}
	return rep, nil
}

func verify(exe, probe string) error {
	home, _ := os.UserHomeDir()
	cmd := exec.Command(exe, "hook")
	cmd.Stdin = strings.NewReader(strings.ReplaceAll(probe, "/home/you", home))
	var out bytes.Buffer
	cmd.Stdout = &out
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("verify: hook probe failed to run: %w", err)
	}
	if !strings.Contains(out.String(), `"permissionDecision":"deny"`) {
		return errors.New("verify: hook did not deny the credential-file probe")
	}
	return nil
}

// ---- settings.json ----

func editSettings(f *fileEdit, doc docData, o Options) ([]string, error) {
	text := string(f.old)
	indent := detectIndent(text)
	root := newObj()
	if strings.TrimSpace(text) != "" {
		var err error
		if root, err = parseObj([]byte(text)); err != nil {
			return nil, fmt.Errorf("invalid settings JSON: %w", err)
		}
	}
	hooks, err := root.objAt("hooks")
	if err != nil {
		return nil, err
	}
	pre, err := hooks.arrAt("PreToolUse")
	if err != nil {
		return nil, fmt.Errorf("hooks: %w", err)
	}
	perm, err := root.objAt("permissions")
	if err != nil {
		return nil, err
	}
	deny, err := perm.arrAt("deny")
	if err != nil {
		return nil, fmt.Errorf("permissions: %w", err)
	}

	matcher := FullMatcher
	if o.PathsOnly {
		matcher = PathsOnlyMatcher
	}
	cmd := HookCommand(o.Exe, o.PathsOnly)
	var notes []string

	var pure, complexIdx []int
	for i, raw := range pre {
		switch classify(raw) {
		case entryPure:
			pure = append(pure, i)
		case entryComplex:
			complexIdx = append(complexIdx, i)
		}
	}

	if o.Uninstall {
		if len(pure) == 0 {
			notes = append(notes, "hook: not installed")
		} else {
			drop := map[int]bool{}
			for _, i := range pure {
				drop[i] = true
			}
			var keep []json.RawMessage
			for i, raw := range pre {
				if !drop[i] {
					keep = append(keep, raw)
				}
			}
			pre = keep
			notes = append(notes, "hook: removed")
		}
		if len(complexIdx) > 0 {
			notes = append(notes, "hook: an entry with extra fields or other hooks is left alone; remove it by hand")
		}
		notes = append(notes, "deny rules: left in place (perry cannot know which rules you added yourself)")
	} else {
		wanted := wantedEntry(matcher, cmd)
		switch {
		case len(pure) > 0:
			i := pure[0]
			if entryEquals(pre[i], matcher, cmd) {
				notes = append(notes, "hook: up to date")
			} else {
				pre[i] = wanted.render(indent, 3)
				notes = append(notes, fmt.Sprintf("hook: updated to %s (matcher %s)", cmd, matcher))
			}
			if len(pure) > 1 {
				notes = append(notes, "hook: duplicate perry entries left alone; remove them by hand")
			}
		case len(complexIdx) > 0:
			notes = append(notes, "hook: a perry entry with extra fields or other hooks exists and is left alone; edit it by hand")
		default:
			pre = append(pre, wanted.render(indent, 3))
			notes = append(notes, fmt.Sprintf("hook: added %s (matcher %s)", cmd, matcher))
		}
		have := map[string]bool{}
		for _, raw := range deny {
			var s string
			if json.Unmarshal(raw, &s) == nil {
				have[s] = true
			}
		}
		added := 0
		for _, r := range doc.Deny {
			if !have[r] {
				b, _ := json.Marshal(r)
				deny = append(deny, b)
				added++
			}
		}
		if added == 0 {
			notes = append(notes, "deny rules: up to date")
		} else {
			notes = append(notes, fmt.Sprintf("deny rules: added %d of %d", added, len(doc.Deny)))
		}
	}

	// Rebuild only what changed, keeping every other key and value as it was.
	if len(pre) > 0 {
		hooks.set("PreToolUse", renderArr(pre, indent, 2))
	} else {
		hooks.del("PreToolUse")
	}
	if len(hooks.keys) > 0 {
		root.set("hooks", hooks.render(indent, 1))
	} else if root.has("hooks") {
		root.del("hooks")
	}
	if len(deny) > 0 {
		perm.set("deny", renderArr(deny, indent, 2))
	}
	if len(perm.keys) > 0 {
		root.set("permissions", perm.render(indent, 1))
	}

	out := root.render(indent, 0)
	if string(f.old) == "" || strings.TrimSpace(string(f.old)) == "" {
		f.new = append(out, '\n')
	} else {
		f.new = out
		if strings.HasSuffix(text, "\n") {
			f.new = append(out, '\n')
		}
	}
	// An unchanged edit must not touch the bytes.
	if canonicalEqual(f.old, f.new) {
		f.new = f.old
	}
	return notes, nil
}

func canonicalEqual(a, b []byte) bool {
	var x, y any
	if json.Unmarshal(a, &x) != nil || json.Unmarshal(b, &y) != nil {
		return false
	}
	xa, _ := json.Marshal(x)
	ya, _ := json.Marshal(y)
	return string(xa) == string(ya)
}

type entryClass int

const (
	entryOther entryClass = iota
	entryPure
	entryComplex
)

func entryHooks(raw json.RawMessage) (*jobj, []*jobj, bool) {
	e, err := parseObj(raw)
	if err != nil {
		return nil, nil, false
	}
	arr, err := e.arrAt("hooks")
	if err != nil {
		return e, nil, true
	}
	var hs []*jobj
	for _, h := range arr {
		if ho, err := parseObj(h); err == nil {
			hs = append(hs, ho)
		}
	}
	return e, hs, true
}

func command(h *jobj) string {
	var s string
	json.Unmarshal(h.vals["command"], &s)
	return s
}

func classify(raw json.RawMessage) entryClass {
	e, hs, ok := entryHooks(raw)
	if !ok {
		return entryOther
	}
	perry := false
	for _, h := range hs {
		if perryHookRe.MatchString(command(h)) {
			perry = true
		}
	}
	if !perry {
		return entryOther
	}
	if len(e.keys) == 2 && e.has("matcher") && e.has("hooks") && len(hs) == 1 && len(hs[0].keys) == 2 &&
		hs[0].has("type") && hs[0].has("command") {
		return entryPure
	}
	return entryComplex
}

func entryEquals(raw json.RawMessage, matcher, cmd string) bool {
	e, hs, ok := entryHooks(raw)
	if !ok || len(hs) != 1 {
		return false
	}
	var m, t string
	json.Unmarshal(e.vals["matcher"], &m)
	json.Unmarshal(hs[0].vals["type"], &t)
	return m == matcher && t == "command" && command(hs[0]) == cmd
}

func wantedEntry(matcher, cmd string) *jobj {
	h := newObj()
	h.set("type", mustJSON("command"))
	h.set("command", mustJSON(cmd))
	e := newObj()
	e.set("matcher", mustJSON(matcher))
	e.set("hooks", json.RawMessage("[{\"type\":\"command\",\"command\":"+string(mustJSON(cmd))+"}]"))
	return e
}

func mustJSON(v any) json.RawMessage {
	b, _ := json.Marshal(v)
	return b
}

// ---- CLAUDE.md ----

func editClaudeMD(f *fileEdit, doc docData, o Options) ([]string, error) {
	text := string(f.old)
	block := beginMarker + "\n" + doc.Snippet + "\n" + endMarker + "\n"

	bi := strings.Index(text, "<!-- perry:begin")
	ei := strings.Index(text, endMarker)
	if (bi >= 0) != (ei >= 0) || (bi >= 0 && ei < bi) {
		return nil, errors.New("unbalanced perry markers; fix by hand")
	}
	f.new = f.old

	if bi >= 0 {
		end := ei + len(endMarker)
		if end < len(text) && text[end] == '\n' {
			end++
		}
		if o.Uninstall {
			rest := text[:bi] + text[end:]
			f.new = []byte(strings.TrimRight(rest, "\n"))
			if len(f.new) > 0 {
				f.new = append(f.new, '\n')
			}
			return []string{"CLAUDE.md: removed the perry block"}, nil
		}
		if text[bi:end] == block {
			return []string{"CLAUDE.md: up to date"}, nil
		}
		f.new = []byte(text[:bi] + block + text[end:])
		return []string{"CLAUDE.md: updated the perry block"}, nil
	}

	if hs, he, ok := findSection(text); ok {
		if o.Uninstall {
			return []string{"CLAUDE.md: the section is not marked; remove it by hand"}, nil
		}
		if sec := text[hs:he]; strings.TrimSpace(sec) == doc.Snippet {
			trailing := strings.TrimPrefix(sec[len(strings.TrimRight(sec, "\n")):], "\n")
			f.new = []byte(text[:hs] + block + trailing + text[he:])
			return []string{"CLAUDE.md: wrapped the existing section in markers"}, nil
		}
		return []string{"CLAUDE.md: a hand-written \"Credentials (perry)\" section differs from the snippet and is left alone; change it by hand"}, nil
	}

	if o.Uninstall {
		return []string{"CLAUDE.md: no perry block"}, nil
	}
	switch {
	case strings.TrimSpace(text) == "":
		f.new = []byte(block)
	default:
		f.new = []byte(strings.TrimRight(text, "\n") + "\n\n" + block)
	}
	return []string{"CLAUDE.md: added the perry block"}, nil
}

// findSection returns the byte range of a hand-written Credentials (perry)
// section: from the heading to the next heading of level 1 or 2, or the end.
func findSection(text string) (start, end int, ok bool) {
	pos := 0
	for _, l := range strings.SplitAfter(text, "\n") {
		if strings.TrimRight(l, "\r\n") == heading {
			start, ok = pos, true
			break
		}
		pos += len(l)
	}
	if !ok {
		return 0, 0, false
	}
	end = len(text)
	pos = start
	for i, l := range strings.SplitAfter(text[start:], "\n") {
		if i > 0 && (strings.HasPrefix(l, "## ") || strings.HasPrefix(l, "# ")) {
			end = pos
			break
		}
		pos += len(l)
	}
	return start, end, true
}

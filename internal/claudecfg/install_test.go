package claudecfg

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/benlrice/perry/docs"
)

// fakeExe is a shell script that denies like the real hook, so Install's
// verify step has something to run.
func fakeExe(t *testing.T) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "perry")
	os.WriteFile(p, []byte("#!/bin/sh\ncat >/dev/null\necho '{\"hookSpecificOutput\":{\"permissionDecision\":\"deny\"}}'\n"), 0o755)
	return p
}

func opts(t *testing.T) Options {
	dir := t.TempDir()
	return Options{
		SettingsPath: filepath.Join(dir, "settings.json"),
		ClaudeMDPath: filepath.Join(dir, "CLAUDE.md"),
		Exe:          fakeExe(t),
		Doc:          docs.ClaudeCode,
	}
}

func read(t *testing.T, p string) string {
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestDocMatcherMatchesConstant(t *testing.T) {
	if !strings.Contains(docs.ClaudeCode, `"matcher": "`+FullMatcher+`"`) {
		t.Error("FullMatcher differs from the doc")
	}
	d, err := parseDoc(docs.ClaudeCode)
	if err != nil || len(d.Deny) != 7 || !strings.HasPrefix(d.Snippet, "## Credentials (perry)") || !strings.Contains(d.Probe, "/home/you/") {
		t.Fatalf("parse: %+v %v", d, err)
	}
}

func TestInstallFreshAndRerun(t *testing.T) {
	o := opts(t)
	rep, err := Install(o)
	if err != nil {
		t.Fatal(err)
	}
	out := rep.String()
	for _, w := range []string{"hook: added", "deny rules: added 7 of 7", "CLAUDE.md: added the perry block", "verify: hook denies the credential-file probe"} {
		if !strings.Contains(out, w) {
			t.Errorf("missing %q in\n%s", w, out)
		}
	}
	var v map[string]any
	if err := json.Unmarshal([]byte(read(t, o.SettingsPath)), &v); err != nil {
		t.Fatalf("settings not JSON: %v\n%s", err, read(t, o.SettingsPath))
	}
	rep, err = Install(o)
	if err != nil {
		t.Fatal(err)
	}
	out = rep.String()
	for _, w := range []string{"hook: up to date", "deny rules: up to date", "CLAUDE.md: up to date", "nothing to change"} {
		if !strings.Contains(out, w) {
			t.Errorf("rerun missing %q in\n%s", w, out)
		}
	}
	if _, err := os.Stat(o.SettingsPath + ".bak"); err == nil {
		t.Error("backup written for a fresh file")
	}
}

func TestExistingSettingsKeptByteForByte(t *testing.T) {
	o := opts(t)
	orig := "{\n\t\"model\": \"opus\",\n\t\"env\":   {\"A\":  \"1\"},\n\t\"hooks\": {\n\t\t\"PostToolUse\": [{\"matcher\":\"x\",\"hooks\":[]}]\n\t},\n\t\"permissions\": {\"allow\": [\"Bash(ls)\"], \"deny\": [\"Read(./secret)\"]}\n}\n"
	os.WriteFile(o.SettingsPath, []byte(orig), 0o640)
	if _, err := Install(o); err != nil {
		t.Fatal(err)
	}
	got := read(t, o.SettingsPath)
	for _, keep := range []string{"{\"A\":  \"1\"}", "\"PostToolUse\": [{\"matcher\":\"x\",\"hooks\":[]}]", "\"allow\": [\"Bash(ls)\"]", "Read(./secret)"} {
		if !strings.Contains(got, keep) {
			t.Errorf("lost %q:\n%s", keep, got)
		}
	}
	if !strings.Contains(got, "\n\t\t\"") {
		t.Errorf("tab indent not reused:\n%s", got)
	}
	if read(t, o.SettingsPath+".bak") != orig {
		t.Error("backup differs from original")
	}
	st, _ := os.Stat(o.SettingsPath)
	if st.Mode().Perm() != 0o640 {
		t.Errorf("mode %v", st.Mode())
	}
	if strings.Index(got, "\"model\"") > strings.Index(got, "\"permissions\"") {
		t.Error("key order changed")
	}
}

func TestStaleEntryUpdatedInPlace(t *testing.T) {
	o := opts(t)
	old := `{"hooks":{"PreToolUse":[{"matcher":"Bash","hooks":[{"type":"command","command":"/old/bin/perry hook --paths-only"}]}]}}`
	os.WriteFile(o.SettingsPath, []byte(old), 0o600)
	rep, err := Install(o)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(rep.String(), "hook: updated to") {
		t.Errorf("not updated:\n%s", rep)
	}
	got := read(t, o.SettingsPath)
	if strings.Contains(got, "/old/bin") || strings.Count(got, `"matcher"`) != 1 {
		t.Errorf("entry not replaced in place:\n%s", got)
	}
}

func TestComplexEntryLeftAlone(t *testing.T) {
	o := opts(t)
	cx := `{"hooks":{"PreToolUse":[{"matcher":"Bash","extra":1,"hooks":[{"type":"command","command":"perry hook"},{"type":"command","command":"other"}]}]}}`
	os.WriteFile(o.SettingsPath, []byte(cx), 0o600)
	rep, err := Install(o)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(rep.String(), "left alone") || strings.Count(read(t, o.SettingsPath), `"matcher"`) != 1 {
		t.Errorf("complex entry touched:\n%s\n%s", rep, read(t, o.SettingsPath))
	}
}

func TestUninstallKeepsDenyRules(t *testing.T) {
	o := opts(t)
	if _, err := Install(o); err != nil {
		t.Fatal(err)
	}
	o.Uninstall = true
	rep, err := Install(o)
	if err != nil {
		t.Fatal(err)
	}
	got := read(t, o.SettingsPath)
	if strings.Contains(got, "PreToolUse") || !strings.Contains(got, "Read(~/.ssh/**)") {
		t.Errorf("uninstall result:\n%s", got)
	}
	if strings.Contains(read(t, o.ClaudeMDPath), "perry:begin") || !strings.Contains(rep.String(), "deny rules: left in place") {
		t.Errorf("md/report:\n%s", rep)
	}
}

func TestDryRunWritesNothing(t *testing.T) {
	o := opts(t)
	o.DryRun = true
	rep, err := Install(o)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(o.SettingsPath); err == nil {
		t.Error("settings written")
	}
	if _, err := os.Stat(o.ClaudeMDPath); err == nil {
		t.Error("CLAUDE.md written")
	}
	if !strings.HasPrefix(rep.Lines[0], "(dry run) ") || strings.Contains(rep.String(), "verify:") {
		t.Errorf("report:\n%s", rep)
	}
}

func TestInvalidInputsRefuseBeforeWriting(t *testing.T) {
	for name, body := range map[string]string{
		"invalid json":   `{"hooks":`,
		"non-object":     `[1]`,
		"hooks wrong":    `{"hooks":[]}`,
		"pretool wrong":  `{"hooks":{"PreToolUse":{}}}`,
		"permissions":    `{"permissions":[]}`,
		"deny wrong":     `{"permissions":{"deny":"x"}}`,
		"trailing bytes": `{} {}`,
	} {
		o := opts(t)
		os.WriteFile(o.SettingsPath, []byte(body), 0o600)
		if _, err := Install(o); err == nil {
			t.Errorf("%s: no error", name)
		}
		if _, err := os.Stat(o.ClaudeMDPath); err == nil {
			t.Errorf("%s: CLAUDE.md written despite error", name)
		}
		if read(t, o.SettingsPath) != body {
			t.Errorf("%s: settings modified", name)
		}
	}
	o := opts(t)
	os.WriteFile(o.ClaudeMDPath, []byte("<!-- perry:begin x -->\nno end\n"), 0o600)
	if _, err := Install(o); err == nil {
		t.Error("unbalanced markers accepted")
	}
	if _, err := os.Stat(o.SettingsPath); err == nil {
		t.Error("settings written despite unbalanced markers")
	}
}

func TestSymlinkedSettingsKeepLink(t *testing.T) {
	o := opts(t)
	real := filepath.Join(t.TempDir(), "real.json")
	os.WriteFile(real, []byte("{}\n"), 0o600)
	os.Symlink(real, o.SettingsPath)
	if _, err := Install(o); err != nil {
		t.Fatal(err)
	}
	if st, _ := os.Lstat(o.SettingsPath); st.Mode()&os.ModeSymlink == 0 {
		t.Error("symlink replaced")
	}
	if !strings.Contains(read(t, real), "PreToolUse") {
		t.Error("real file not updated")
	}
}

func TestClaudeMDHandWrittenSection(t *testing.T) {
	d, _ := parseDoc(docs.ClaudeCode)
	o := opts(t)
	os.WriteFile(o.ClaudeMDPath, []byte("# Mine\n\n"+d.Snippet+"\n\n## Other\ntext\n"), 0o600)
	if _, err := Install(o); err != nil {
		t.Fatal(err)
	}
	got := read(t, o.ClaudeMDPath)
	if !strings.Contains(got, "<!-- perry:begin") || strings.Count(got, "## Credentials (perry)") != 1 || !strings.Contains(got, "## Other\ntext") {
		t.Errorf("wrap failed:\n%s", got)
	}
	o2 := opts(t)
	os.WriteFile(o2.ClaudeMDPath, []byte("## Credentials (perry)\n\nmy own words\n"), 0o600)
	rep, err := Install(o2)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(rep.String(), "left alone") || strings.Contains(read(t, o2.ClaudeMDPath), "perry:begin") {
		t.Errorf("differing section changed:\n%s", rep)
	}
}

func TestStaleMarkedBlockUpdated(t *testing.T) {
	o := opts(t)
	os.WriteFile(o.ClaudeMDPath, []byte("top\n\n"+beginMarker+"\nold text\n"+endMarker+"\nbottom\n"), 0o600)
	rep, err := Install(o)
	if err != nil {
		t.Fatal(err)
	}
	got := read(t, o.ClaudeMDPath)
	if !strings.Contains(rep.String(), "updated the perry block") || strings.Contains(got, "old text") || !strings.HasPrefix(got, "top\n") || !strings.HasSuffix(got, "bottom\n") {
		t.Errorf("update:\n%s", got)
	}
}

func TestHookCommandQuoting(t *testing.T) {
	if got := HookCommand("/usr/bin/perry", false); got != "/usr/bin/perry hook" {
		t.Error(got)
	}
	if got := HookCommand("/my dir/it's/perry", true); got != `'/my dir/it'\''s/perry' hook --paths-only` {
		t.Error(got)
	}
	if !perryHookRe.MatchString(HookCommand("/my dir/it's/perry", true)) {
		t.Error("quoted command not recognised as perry's")
	}
}

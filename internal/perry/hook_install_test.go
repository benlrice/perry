package perry

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func hookInput(tool string, input map[string]any, cwd string) string {
	b, _ := json.Marshal(map[string]any{"cwd": cwd, "tool_name": tool, "tool_input": input})
	return string(b)
}

func denied(out string) bool { return strings.Contains(out, `"permissionDecision":"deny"`) }

func TestHookAcceptance(t *testing.T) {
	s := newSandbox(t)
	s.add(tok+"\n", "--host", "api.example.com", "--kind", "api", "--user", "")

	out, _, c := s.run(hookInput("Read", map[string]any{"file_path": s.home + "/.ssh/id_ed25519"}, s.home), "hook")
	if c != 0 || !denied(out) {
		t.Errorf("ssh key read: %d %q", c, out)
	}
	expect(t, "reason", out, "Use `perry run -- <cmd> {{perry:<host>}}` to inject secrets instead.")
	expect(t, "quoted match", out, `(matched \"`)
	if strings.Count(strings.TrimSpace(out), "\n") != 0 {
		t.Errorf("deny must be one JSON line: %q", out)
	}

	out, _, _ = s.run(hookInput("Bash", map[string]any{"command": "curl -H 'X: " + tok + "' x"}, s.home), "hook")
	if !denied(out) {
		t.Errorf("stored secret allowed: %q", out)
	}
	refuse(t, "deny reason", out, tok)

	commit := "git commit -F - <<'EOF'\nExplain why `perry unlock` is user-only\nEOF"
	if out, _, c = s.run(hookInput("Bash", map[string]any{"command": commit}, s.home), "hook"); c != 0 || out != "" {
		t.Errorf("heredoc commit: %d %q", c, out)
	}
	for _, cmd := range []string{"perry get api.example.com --reveal", "perry unlock", "perry rekey", "perry install claude", "keyctl show"} {
		if out, _, _ = s.run(hookInput("Bash", map[string]any{"command": cmd}, s.home), "hook"); !denied(out) {
			t.Errorf("%q allowed", cmd)
		}
	}
	if out, _, _ = s.run(hookInput("Bash", map[string]any{"command": "perry lock"}, s.home), "hook"); out != "" {
		t.Errorf("perry lock denied: %q", out)
	}
	// unparseable input is denied, exit 0
	out, _, c = s.run("not json", "hook")
	if c != 0 || !denied(out) {
		t.Errorf("garbage: %d %q", c, out)
	}
	expect(t, "unreadable", out, "blocked: unreadable hook input.")
	if _, _, c = s.run("", "hook", "--bogus"); c != 2 {
		t.Errorf("bad flag exit %d", c)
	}
	// paths-only does not read the store
	if out, _, _ = s.run(hookInput("Bash", map[string]any{"command": "echo " + tok}, s.home), "hook", "--paths-only"); out != "" {
		t.Errorf("paths-only scanned the store: %q", out)
	}
	if out, _, _ = s.run(hookInput("Bash", map[string]any{"command": "cat ~/.netrc"}, s.home), "hook", "--paths-only"); !denied(out) {
		t.Errorf("paths-only missed netrc: %q", out)
	}
}

func TestHookLockedFallsBackToPaths(t *testing.T) {
	s := newSandbox(t)
	s.add(tok+"\n", "--host", "api.example.com", "--kind", "api", "--user", "")
	p := s.with("PERRY_PASSPHRASE=pw")
	p.mustRun("", "keygen")
	p.mustRun("", "rekey")

	out, e, c := s.run(hookInput("Bash", map[string]any{"command": "echo hello"}, s.home), "hook")
	if c != 0 || out != "" || !strings.Contains(e, "perry hook: store locked; paths-only checks applied") {
		t.Errorf("locked allow: %d %q %q", c, out, e)
	}
	// the hook must never prompt: a PERRY_PASSPHRASE-less run must not hang or open a tty
	if out, _, _ = s.run(hookInput("Read", map[string]any{"file_path": s.home + "/.aws/credentials"}, s.home), "hook"); !denied(out) {
		t.Errorf("locked store must still apply path checks: %q", out)
	}
	// a secret in the input is not caught while locked (the store cannot be read)
	if out, _, _ = s.run(hookInput("Bash", map[string]any{"command": "echo " + tok}, s.home), "hook"); out != "" {
		t.Errorf("locked scan: %q", out)
	}
}

func TestHookStoreErrorFailsClosedForBash(t *testing.T) {
	s := newSandbox(t)
	s.add(tok+"\n", "--host", "api.example.com", "--kind", "api", "--user", "")
	os.Remove(filepath.Join(s.home, ".ssh", "id_ed25519"))
	out, _, _ := s.run(hookInput("Bash", map[string]any{"command": "ls"}, s.home), "hook")
	expect(t, "bash", out, "blocked: cannot verify command against the secret store.")
	if out, _, _ = s.run(hookInput("Grep", map[string]any{"pattern": "x"}, s.home), "hook"); out != "" {
		t.Errorf("non-bash tool denied: %q", out)
	}
}

func TestInstallEndToEnd(t *testing.T) {
	s := newSandbox(t)
	settings := filepath.Join(s.home, ".claude", "settings.json")
	md := filepath.Join(s.home, ".claude", "CLAUDE.md")

	out := s.mustRun("", "install", "claude", "--dry-run")
	if _, err := os.Stat(settings); err == nil {
		t.Error("dry run wrote settings")
	}
	expect(t, "dry run", out, "(dry run) ")

	out = s.mustRun("", "install", "claude")
	expect(t, "install", out, "verify: hook denies the credential-file probe")
	body, _ := os.ReadFile(settings)
	expect(t, "settings", string(body), "perry hook")
	expect(t, "settings matcher", string(body), "MultiEdit")
	expect(t, "deny rules", string(body), "Read(~/.kube/config)")
	mdBody, _ := os.ReadFile(md)
	expect(t, "CLAUDE.md", string(mdBody), "perry:begin")

	out = s.mustRun("", "install", "claude")
	expect(t, "rerun", out, "hook: up to date")
	expect(t, "rerun", out, "nothing to change")

	out = s.mustRun("", "install", "claude", "--paths-only")
	expect(t, "paths-only switch", out, "hook: updated to")
	out = s.mustRun("", "install", "claude")
	expect(t, "back to full", out, "hook: updated to")

	out = s.mustRun("", "install", "claude", "--uninstall")
	expect(t, "uninstall", out, "deny rules: left in place")
	body, _ = os.ReadFile(settings)
	refuse(t, "settings after uninstall", string(body), "PreToolUse")
	expect(t, "deny kept", string(body), "Read(~/.ssh/**)")

	if _, e, c := s.run("", "install"); c != 2 || !strings.Contains(e, "perry install claude") {
		t.Errorf("install without claude: %d %q", c, e)
	}
}

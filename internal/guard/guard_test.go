package guard

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/benlrice/perry/internal/vault"
	"golang.org/x/crypto/ssh"
)

// env makes a temp HOME with a plain ssh key so the store works unlocked.
func env(t *testing.T) string {
	t.Helper()
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(home, ".config"))
	t.Setenv("PERRY_IDENTITY", "")
	t.Setenv("PERRY_RECIPIENTS", "")
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	blk, _ := ssh.MarshalPrivateKey(priv, "")
	os.MkdirAll(filepath.Join(home, ".ssh"), 0o700)
	os.WriteFile(filepath.Join(home, ".ssh", "id_ed25519"), pem.EncodeToMemory(blk), 0o600)
	sp, _ := ssh.NewPublicKey(pub)
	os.WriteFile(filepath.Join(home, ".ssh", "id_ed25519.pub"), ssh.MarshalAuthorizedKey(sp), 0o644)
	return home
}

func input(t *testing.T, tool string, ti map[string]any) Input {
	t.Helper()
	b, _ := json.Marshal(ti)
	return Input{ToolName: tool, ToolInput: b}
}

func bash(t *testing.T, cmd string) Decision {
	return Decide(input(t, "Bash", map[string]any{"command": cmd}))
}

func expectDeny(t *testing.T, d Decision, want string) {
	t.Helper()
	if !d.Deny || !strings.Contains(d.Reason, want) {
		t.Errorf("want deny containing %q, got %+v", want, d)
	}
}

func expectAllow(t *testing.T, d Decision) {
	t.Helper()
	if d.Deny {
		t.Errorf("want allow, got %+v", d)
	}
}

func TestCredentialPaths(t *testing.T) {
	home := env(t)
	cases := []struct{ tool, key, val, label string }{
		{"Read", "file_path", home + "/.ssh/id_ed25519", "SSH private key"},
		{"Read", "file_path", home + "/.ssh/other_key", "SSH private key"},
		{"Read", "file_path", home + "/.aws/credentials", "AWS credentials"},
		{"Read", "file_path", home + "/.netrc", "netrc"},
		{"Read", "file_path", home + "/.config/gh/hosts.yml", "GitHub CLI token file"},
		{"Read", "file_path", home + "/.kube/config", "kubeconfig"},
		{"Read", "file_path", home + "/.tokens", "token file"},
		{"Read", "file_path", home + "/.config/perry/store.age", "perry store"},
		{"Glob", "path", home + "/.ssh", "SSH key directory"},
		{"Glob", "pattern", "~/.ssh/*", "SSH key directory"},
		{"Grep", "path", "$HOME/.ssh/", "SSH key directory"},
	}
	for _, c := range cases {
		expectDeny(t, Decide(input(t, c.tool, map[string]any{c.key: c.val})), "blocked access to "+c.label)
	}
	for _, ok := range []string{home + "/.ssh/config", home + "/.ssh/known_hosts", home + "/.ssh/id_ed25519.pub", home + "/project/main.go"} {
		expectAllow(t, Decide(input(t, "Read", map[string]any{"file_path": ok})))
	}
}

func TestDenyQuotesMatch(t *testing.T) {
	env(t)
	d := bash(t, "cat ~/.netrc")
	expectDeny(t, d, `(matched ".netrc").`)
}

func TestJqTokenFilterPassesButCatDenied(t *testing.T) {
	env(t)
	expectAllow(t, bash(t, "jq -r .tokens[0] data.json"))
	expectAllow(t, bash(t, "jq .tokens.x data.json"))
	expectDeny(t, bash(t, "cat ~/.tokens"), "token file")
	expectDeny(t, bash(t, "jq .tokens ~/.tokens"), "token file")
}

func TestProseNamingStoreFileIsNotAStorePath(t *testing.T) {
	env(t)
	expectAllow(t, bash(t, "cat internal/vault/recipients.go"))
	expectAllow(t, Decide(input(t, "Grep", map[string]any{"pattern": "recipientsPath"})))
	expectDeny(t, bash(t, "cat perry/store.age"), "perry store")
}

func TestRelativePaths(t *testing.T) {
	home := env(t)
	in := input(t, "Bash", map[string]any{"command": "cat id_ed25519"})
	in.CWD = home + "/.ssh"
	expectDeny(t, Decide(in), "SSH private key")
	in = input(t, "Bash", map[string]any{"command": "cd ~/.ssh && cat id_rsa.bak"})
	expectDeny(t, Decide(in), "SSH private key")
	in = input(t, "Bash", map[string]any{"command": "cd .ssh && cat key.pem"})
	in.CWD = home
	expectDeny(t, Decide(in), "SSH private key")
	in = input(t, "Bash", map[string]any{"command": "cat config"})
	in.CWD = home + "/.ssh"
	expectAllow(t, Decide(in))
	in = input(t, "Bash", map[string]any{"command": "cat store.age"})
	in.CWD = home + "/.config/perry"
	expectDeny(t, Decide(in), "perry store")
	// a project dir that is merely named perry
	os.MkdirAll(home+"/git/perry", 0o755)
	in = input(t, "Bash", map[string]any{"command": "cat store.age recipients"})
	in.CWD = home + "/git/perry"
	expectAllow(t, Decide(in))
	in = input(t, "Bash", map[string]any{"command": "cat .aws/credentials"})
	in.CWD = home
	expectDeny(t, Decide(in), "AWS credentials")
	in = input(t, "Bash", map[string]any{"command": "cd /tmp && cat id_rsa_x"})
	in.CWD = home
	expectDeny(t, Decide(in), "SSH private key") // algorithm basename rule
}

func TestUserOnlyCommands(t *testing.T) {
	env(t)
	expectDeny(t, bash(t, "perry get jira --reveal"), "`perry get` / --reveal")
	expectDeny(t, bash(t, "echo hi; perry unlock"), "`perry unlock`")
	expectDeny(t, bash(t, "perry -x rekey"), "`perry rekey`")
	expectDeny(t, bash(t, "perry install claude"), "`perry install`")
	expectDeny(t, bash(t, "keyctl show"), "`keyctl`")
	expectDeny(t, bash(t, "script -c 'perry get x' /dev/null"), "`perry get`")
	expectAllow(t, bash(t, "perry lock"))
	expectAllow(t, bash(t, "perry status"))
	expectAllow(t, bash(t, "perry unlock --help"))
	expectAllow(t, bash(t, "perry install claude -h"))
	expectAllow(t, bash(t, "perry get -h"))
	expectAllow(t, bash(t, "perry run -- curl https://example.com"))
}

func TestStripDataCommitMessages(t *testing.T) {
	env(t)
	heredoc := "git commit -F - <<'EOF'\nFix the `perry unlock` docs and keyctl text\nEOF"
	expectAllow(t, bash(t, heredoc))
	expectAllow(t, bash(t, "cat <<EOF > notes.txt\nrun perry rekey yourself\nEOF"))
	expectAllow(t, bash(t, "grep -rn 'perry unlock' docs/ 2>&1"))
	expectAllow(t, bash(t, "echo 'keyctl is blocked' | wc -l"))
	// fail closed
	expectDeny(t, bash(t, "bash <<EOF\nperry unlock\nEOF"), "`perry unlock`")
	expectDeny(t, bash(t, "cat <<EOF\n$(perry unlock)\nEOF"), "`perry unlock`")
	expectDeny(t, bash(t, "echo 'x' | sh -c 'perry unlock'"), "`perry unlock`")
	expectDeny(t, bash(t, "git commit -m \"$(perry unlock)\""), "`perry unlock`")
	unterminated := "cat <<'EOF'\nrun perry unlock\n"
	if stripData(unterminated) != unterminated {
		t.Error("unterminated heredoc must stay unchanged")
	}
	expectDeny(t, bash(t, unterminated), "`perry unlock`")
}

func TestRedirectionAmpersandIsNotASeparator(t *testing.T) {
	env(t)
	// 2>&1 must not turn the tail into a command with a non-reader head
	got := stripData("grep -rn 'perry unlock' docs/ 2>&1")
	if strings.Contains(got, "perry unlock") {
		t.Errorf("not stripped: %q", got)
	}
}

func TestStoredSecretDenied(t *testing.T) {
	env(t)
	err := vault.Update(func(d *vault.Data) error {
		d.Entries = append(d.Entries, vault.Entry{Host: "h.example.com", Kind: "jira", Secret: "tok-ABCDEF-123456", Created: "t", Updated: "t"})
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	expectDeny(t, bash(t, "curl -H 'Authorization: Bearer tok-ABCDEF-123456' x"), "stored secret")
	expectDeny(t, Decide(input(t, "WebFetch", map[string]any{"url": "https://x/?t=tok-ABCDEF-123456"})), "stored secret")
	expectDeny(t, Decide(input(t, "Write", map[string]any{"file_path": "/tmp/a", "content": "tok-ABCDEF-123456"})), "stored secret")
	expectAllow(t, bash(t, "perry run -- curl -H 'Authorization: Bearer {{perry:h.example.com}}' x"))
	// paths-only never opens the store
	in := input(t, "Bash", map[string]any{"command": "echo tok-ABCDEF-123456"})
	in.PathsOnly = true
	expectAllow(t, Decide(in))
}

func TestWriteToolsCheckPathFieldsOnly(t *testing.T) {
	home := env(t)
	prose := map[string]any{"file_path": home + "/notes.md", "content": "Do not read ~/.aws or ~/.netrc files"}
	expectAllow(t, Decide(input(t, "Write", prose)))
	expectAllow(t, Decide(input(t, "MultiEdit", map[string]any{"file_path": home + "/n.md", "edits": []any{map[string]any{"old_string": "a", "new_string": "~/.kube/config"}}})))
	expectDeny(t, Decide(input(t, "Write", map[string]any{"file_path": home + "/.netrc", "content": "x"})), "netrc")
	expectDeny(t, Decide(input(t, "NotebookEdit", map[string]any{"notebook_path": home + "/.aws/n.ipynb"})), "AWS credentials")
	// other tools still read everything
	expectDeny(t, Decide(input(t, "WebFetch", map[string]any{"prompt": "read ~/.netrc"})), "netrc")
}

func TestStoreErrorFailsClosedForBashOnly(t *testing.T) {
	home := env(t)
	if err := vault.Update(func(d *vault.Data) error { return nil }); err != nil {
		t.Fatal(err)
	}
	os.Remove(home + "/.ssh/id_ed25519") // identity gone: store unreadable, not locked
	expectDeny(t, bash(t, "ls"), "cannot verify command against the secret store")
	expectAllow(t, Decide(input(t, "Grep", map[string]any{"pattern": "x"})))
}

func TestPerryIdentityPathBlocked(t *testing.T) {
	home := env(t)
	t.Setenv("PERRY_IDENTITY", home+"/keys/mine.pem")
	expectDeny(t, bash(t, "cat "+home+"/keys/mine.pem"), "SSH private key")
}

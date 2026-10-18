package perry

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/pem"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

var binPath string

// TestMain builds the binary once with the perrytest tag. The black-box tests
// drive the public CLI only.
func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "perry-bin-")
	if err != nil {
		panic(err)
	}
	binPath = filepath.Join(dir, "perry")
	build := exec.Command("go", "build", "-tags", "perrytest", "-o", binPath, "github.com/benlrice/perry/cmd/perry")
	if out, err := build.CombinedOutput(); err != nil {
		os.Stderr.Write(out)
		os.RemoveAll(dir)
		os.Exit(1)
	}
	code := m.Run()
	os.RemoveAll(dir)
	os.Exit(code)
}

type sandbox struct {
	t    *testing.T
	home string
	env  []string
}

// newSandbox makes a temp HOME with a plain ed25519 key and a clean environment.
func newSandbox(t *testing.T) *sandbox {
	t.Helper()
	home := t.TempDir()
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	blk, _ := ssh.MarshalPrivateKey(priv, "")
	os.MkdirAll(filepath.Join(home, ".ssh"), 0o700)
	os.WriteFile(filepath.Join(home, ".ssh", "id_ed25519"), pem.EncodeToMemory(blk), 0o600)
	sp, _ := ssh.NewPublicKey(pub)
	os.WriteFile(filepath.Join(home, ".ssh", "id_ed25519.pub"), ssh.MarshalAuthorizedKey(sp), 0o644)
	s := &sandbox{t: t, home: home, env: []string{
		"HOME=" + home, "XDG_CONFIG_HOME=" + filepath.Join(home, ".config"),
		"PATH=" + os.Getenv("PATH"), "CLAUDE_CONFIG_DIR=" + filepath.Join(home, ".claude"),
	}}
	t.Cleanup(func() { s.run("", "lock") })
	return s
}

func (s *sandbox) with(kv ...string) *sandbox {
	c := *s
	c.env = append(append([]string(nil), s.env...), kv...)
	return &c
}

// run starts perry with no controlling tty and returns stdout, stderr and the exit code.
func (s *sandbox) run(stdin string, args ...string) (string, string, int) {
	s.t.Helper()
	cmd := exec.Command(binPath, args...)
	cmd.Env = s.env
	cmd.Dir = s.home
	cmd.Stdin = strings.NewReader(stdin)
	var o, e bytes.Buffer
	cmd.Stdout, cmd.Stderr = &o, &e
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	err := cmd.Run()
	code := 0
	if ee, ok := err.(*exec.ExitError); ok {
		code = ee.ExitCode()
	} else if err != nil {
		s.t.Fatal(err)
	}
	return o.String(), e.String(), code
}

func (s *sandbox) mustRun(stdin string, args ...string) string {
	s.t.Helper()
	o, e, c := s.run(stdin, args...)
	if c != 0 {
		s.t.Fatalf("perry %v: exit %d\nstdout: %s\nstderr: %s", args, c, o, e)
	}
	return o
}

func (s *sandbox) add(secret string, args ...string) {
	s.t.Helper()
	s.mustRun(secret, append([]string{"add"}, args...)...)
}

func expect(t *testing.T, what, got, want string) {
	t.Helper()
	if !strings.Contains(got, want) {
		t.Errorf("%s: want %q in:\n%s", what, want, got)
	}
}

func refuse(t *testing.T, what, got, bad string) {
	t.Helper()
	if strings.Contains(got, bad) {
		t.Errorf("%s: %q must not appear in:\n%s", what, bad, got)
	}
}

const tok = "tok-ABCDEF-123456"

func TestHelpTableMatchesDispatch(t *testing.T) {
	seen := map[string]bool{}
	for _, c := range cmdTable {
		seen[c.name] = true
		if _, ok := dispatch[c.name]; !ok {
			t.Errorf("%s in help table but not dispatch", c.name)
		}
	}
	for n := range dispatch {
		if !seen[n] {
			t.Errorf("%s in dispatch but not help table", n)
		}
	}
}

func TestHelpAndUsageExitCodes(t *testing.T) {
	s := newSandbox(t)
	if o, _, c := s.run("", "help", "run"); c != 0 || !strings.Contains(o, "usage: perry run") {
		t.Errorf("help run: %d %q", c, o)
	}
	if o, _, c := s.run("", "add", "-h"); c != 0 || !strings.Contains(o, "usage: perry add") {
		t.Errorf("add -h: %d %q", c, o)
	}
	if _, e, c := s.run(""); c != 2 || !strings.Contains(e, "usage: perry") {
		t.Errorf("no args: %d %q", c, e)
	}
	if _, e, c := s.run("", "bogus"); c != 2 || !strings.Contains(e, `perry: unknown command "bogus"; run `+"`perry help`"+` for the command list`) {
		t.Errorf("unknown: %d %q", c, e)
	}
	if _, _, c := s.run("", "add", "--nope"); c != 2 {
		t.Errorf("bad flag: %d", c)
	}
	// help never touches the store; -h after a literal -- is data for run
	if o, _, c := s.run("", "run", "--", "echo", "-h"); c != 0 || strings.TrimSpace(o) != "-h" {
		t.Errorf("run -- echo -h: %d %q", c, o)
	}
	if o, _, c := s.run("", "run", "echo", "-h"); c != 0 || strings.TrimSpace(o) != "-h" {
		t.Errorf("run echo -h: %d %q", c, o)
	}
}

func TestEntryLifecycle(t *testing.T) {
	s := newSandbox(t)
	s.add(tok+"\n", "--host", "jira.example.com", "--kind", "jira", "--user", "alice", "--auth", "basic", "--tag", "prod", "--notes", "main")
	store := filepath.Join(s.home, ".config", "perry", "store.age")
	st, err := os.Stat(store)
	if err != nil || st.Mode().Perm() != 0o600 {
		t.Fatalf("store: %v %v", st, err)
	}
	raw, _ := os.ReadFile(store)
	refuse(t, "store file", string(raw), "jira.example.com")
	refuse(t, "store file", string(raw), tok)

	out := s.mustRun("", "list")
	expect(t, "list", out, "jira.example.com\tjira\talice\tprod\tbasic")
	refuse(t, "list", out, tok)
	expect(t, "search", s.mustRun("", "search", "MAIN"), "jira.example.com")
	if o := s.mustRun("", "search", "zzz"); o != "" {
		t.Errorf("search miss printed %q", o)
	}
	show := s.mustRun("", "show", "jira")
	expect(t, "show", show, "user: alice")
	expect(t, "show", show, "usage: perry run -- curl -u '{{perry:jira.example.com:username}}:{{perry:jira.example.com}}' URL")
	refuse(t, "show", show, tok)
	expect(t, "show flag first", s.mustRun("", "show", "--kind", "jira", "jira.example.com"), "host: jira.example.com")

	if _, e, c := s.run(tok+"\n", "add", "--host", "jira.example.com", "--kind", "jira", "--user", "a"); c != 1 || !strings.Contains(e, "entry (jira.example.com, jira) exists; use --update to replace") {
		t.Errorf("dup: %d %q", c, e)
	}
	created := field(s.mustRun("", "show", "jira"), "created")
	s.add("newsecret-123456\n", "--host", "jira.example.com", "--kind", "jira", "--user", "alice", "--update")
	if got := field(s.mustRun("", "show", "jira"), "created"); got != created {
		t.Errorf("--update changed created: %s vs %s", got, created)
	}
	expect(t, "run after update", s.mustRun("", "run", "--", "echo", "{{perry:jira}}"), "«perry:jira»")

	expect(t, "edit", s.mustRun("", "edit", "jira", "--set-host", "jira2.example.com", "--add-tag", "x", "--set-auth", "bearer"), "edited: jira2.example.com jira")
	expect(t, "edited list", s.mustRun("", "list"), "jira2.example.com\tjira\talice\tx\tbearer")
	if _, e, c := s.run("", "edit", "jira"); c != 1 || !strings.Contains(e, "nothing to change") {
		t.Errorf("edit nothing: %d %q", c, e)
	}
	if _, e, c := s.run("", "edit", "jira", "--set-auth", "basic", "--set-user", ""); c != 1 || !strings.Contains(e, "auth basic needs a username") {
		t.Errorf("edit auth: %d %q", c, e)
	}
	s.mustRun("", "rm", "jira")
	if o := s.mustRun("", "list"); o != "" {
		t.Errorf("not removed: %q", o)
	}
	if _, e, c := s.run("", "rm", "jira"); c != 1 || !strings.Contains(e, `no entry matches "jira"`) {
		t.Errorf("rm missing: %d %q", c, e)
	}
}

func field(show, name string) string {
	for _, l := range strings.Split(show, "\n") {
		if strings.HasPrefix(l, name+": ") {
			return strings.TrimPrefix(l, name+": ")
		}
	}
	return ""
}

func TestAddValidation(t *testing.T) {
	s := newSandbox(t)
	if _, e, c := s.run("x\n", "add", "--host", "h"); c != 2 || !strings.Contains(e, "--host and --kind are required") {
		t.Errorf("missing kind: %d %q", c, e)
	}
	if _, e, c := s.run("\n", "add", "--host", "h", "--kind", "k"); c != 1 || !strings.Contains(e, "empty secret") {
		t.Errorf("empty: %d %q", c, e)
	}
	if _, e, c := s.run("x\n", "add", "--host", "h", "--kind", "k", "--auth", "basic"); c != 1 || !strings.Contains(e, "auth basic needs a username (set with: perry edit h --set-user U)") {
		t.Errorf("basic: %d %q", c, e)
	}
	if _, e, c := s.run("x\n", "add", "--host", "h", "--kind", "k", "--auth", "digest", "--user", "u"); c != 1 || !strings.Contains(e, `auth must be basic, bearer or token, got "digest"`) {
		t.Errorf("digest: %d %q", c, e)
	}
	// short secret warns; host leaking the secret is refused
	_, e, c := s.run("abc\n", "add", "--host", "other.example.com", "--kind", "k", "--user", "")
	if c != 0 || !strings.Contains(e, "warning: secret is shorter than 6") {
		t.Errorf("short: %d %q", c, e)
	}
	if _, e, c := s.run("sekret\n", "add", "--host", "sekret.example.com", "--kind", "k", "--user", ""); c != 1 || !strings.Contains(e, "host contains the secret") {
		t.Errorf("host leak: %d %q", c, e)
	}
	// piped add for a kind that wants a username warns but succeeds
	_, e, c = s.run(tok+"\n", "add", "--host", "j.example.com", "--kind", "jira")
	if c != 0 || !strings.Contains(e, "kind jira usually needs a username; entry has no username (set with: perry edit j.example.com --set-user U, or pass --user \"\" for token-only)") {
		t.Errorf("username warn: %d %q", c, e)
	}
	// bearer skips the warning
	_, e, _ = s.run(tok+"\n", "add", "--host", "b.example.com", "--kind", "jira", "--auth", "bearer")
	refuse(t, "bearer add", e, "usually needs a username")
}

func TestRunSubstitutionRedactionAndExit(t *testing.T) {
	s := newSandbox(t)
	s.add(tok+"\n", "--host", "api.example.com", "--kind", "api", "--user", "alice", "--auth", "basic")
	s = s.with("PERRY_SECRET_SETTING=leakme", "PERRY_IDENTITY=")

	// literal, base64 (echo | base64 style), url-escaped, on both streams
	b64 := base64.StdEncoding.EncodeToString([]byte(tok + "\n"))
	script := `echo "lit=$1"; echo "b64=$(printf '%s\n' "$1" | base64)"; echo "err=$1" >&2; echo "env=${PERRY_SECRET_SETTING-unset}"; exit 7`
	out, errOut, code := s.run("", "run", "--", "sh", "-c", script, "sh", "{{perry:api.example.com}}")
	if code != 7 {
		t.Errorf("exit code %d", code)
	}
	expect(t, "stdout", out, "lit=«perry:api.example.com»")
	expect(t, "stdout b64", out, "b64=«perry:api.example.com»")
	expect(t, "stderr", errOut, "err=«perry:api.example.com»")
	expect(t, "env stripped", out, "env=unset")
	refuse(t, "stdout", out, tok)
	refuse(t, "stdout", out, b64)

	// username field and basic-auth header form
	out = s.mustRun("", "run", "--", "echo", "{{perry:api:username}}")
	if strings.TrimSpace(out) != "alice" {
		t.Errorf("username field: %q", out)
	}
	out = s.mustRun("", "run", "echo", "Basic", base64.StdEncoding.EncodeToString([]byte("alice:"+tok)))
	expect(t, "unreferenced basic form", out, "«perry:api.example.com»")

	// signal exit: 128 + number
	if _, _, c := s.run("", "run", "--", "sh", "-c", "kill -TERM $$"); c != 128+15 {
		t.Errorf("signal exit %d", c)
	}
	// secret split across writes
	out = s.mustRun("", "run", "--", "sh", "-c", `a=$1; printf '%s' "${a%-123456}"; sleep 0.2; printf '%s\n' "-123456"`, "sh", "{{perry:api}}")
	refuse(t, "split output", out, "tok-AB")
	expect(t, "split output", out, "«perry:api»")
	// child that cannot start
	if _, e, c := s.run("", "run", "--", "/no/such/binary"); c != 1 || !strings.Contains(e, "perry: run:") {
		t.Errorf("start failure: %d %q", c, e)
	}
	// options before -- are an error
	if _, e, c := s.run("", "run", "--bogus", "echo"); c != 2 || !strings.Contains(e, "unknown option") {
		t.Errorf("run option: %d %q", c, e)
	}
}

func TestRunEmptyFieldStopsBeforeChild(t *testing.T) {
	s := newSandbox(t)
	s.add(tok+"\n", "--host", "a.example.com", "--kind", "api", "--user", "")
	marker := filepath.Join(s.home, "ran")
	_, e, c := s.run("", "run", "--", "sh", "-c", "touch "+marker, "sh", "{{perry:a.example.com:username}}", "{{perry:a.example.com:username}}", "{{perry:a.example.com:notes}}")
	if c != 1 {
		t.Errorf("exit %d", c)
	}
	if strings.Count(e, "has no username") != 1 {
		t.Errorf("not deduplicated: %q", e)
	}
	expect(t, "fix command", e, "perry edit a.example.com --set-user U")
	expect(t, "notes fix", e, "perry edit a.example.com --notes TEXT")
	if _, err := os.Stat(marker); err == nil {
		t.Error("child started")
	}
}

func TestRefErrors(t *testing.T) {
	s := newSandbox(t)
	s.add("one-secret-111\n", "--host", "a.example.com", "--kind", "jira", "--user", "")
	s.add("two-secret-222\n", "--host", "b.example.com", "--kind", "jira", "--user", "")
	s.add("port-secret-333\n", "--host", "g.example.com:8080", "--kind", "grafana", "--user", "")

	_, e, c := s.run("", "run", "--", "echo", "{{perry:jira}}")
	if c != 1 {
		t.Errorf("exit %d", c)
	}
	expect(t, "ambiguous", e, `ambiguous ref "jira"; candidates: a.example.com, b.example.com`)
	for _, sec := range []string{"one-secret", "two-secret"} {
		refuse(t, "ambiguity error", e, sec)
	}
	s.add("wiki-secret-444\n", "--host", "a.example.com", "--kind", "wiki", "--user", "")
	_, e, _ = s.run("", "show", "a.example.com")
	expect(t, "same host, two kinds", e, `ambiguous ref "a.example.com"; candidates: a.example.com`)
	expect(t, "narrowed by --kind", s.mustRun("", "show", "a.example.com", "--kind", "wiki"), "kind: wiki")
	out := s.mustRun("", "run", "--", "echo", "{{perry:g.example.com:8080}}")
	expect(t, "host:port", out, "«perry:g.example.com:8080»")
	_, e, _ = s.run("", "run", "--", "echo", "{{perry:b.example.com:bogus}}")
	expect(t, "unknown field", e, `unknown field "bogus"`)
}

func TestCurlHint(t *testing.T) {
	s := newSandbox(t)
	s.add(tok+"\n", "--host", "api.example.com", "--kind", "api", "--user", "alice")
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "curl"), []byte("#!/bin/sh\necho \"curl args: $*\"\n"), 0o755)
	s = s.with("PATH=" + dir + ":" + os.Getenv("PATH"))
	out, e, c := s.run("", "run", "--", "curl", "-u", "{{perry:api.example.com}}", "http://x")
	if c != 0 {
		t.Errorf("hint must not stop the command: %d", c)
	}
	expect(t, "hint", e, "perry: hint: curl -u needs user:token, but the value has no ':'. Use -u '{{perry:api.example.com:username}}:{{perry:api.example.com}}'")
	refuse(t, "hint", e, tok)
	expect(t, "redacted", out, "«perry:api.example.com»")
	_, e, _ = s.run("", "run", "--", "curl", "-u", "{{perry:api.example.com:username}}:{{perry:api.example.com}}", "http://x")
	refuse(t, "no hint with colon", e, "hint")
	_, e, _ = s.run("", "run", "--", "curl", "-u{{perry:api.example.com:secret}}", "http://x")
	expect(t, "hint drops :secret", e, "-u '{{perry:api.example.com:username}}:{{perry:api.example.com}}'")
}

func TestExec(t *testing.T) {
	s := newSandbox(t)
	s.add(tok+"\n", "--host", "api.example.com", "--kind", "api", "--user", "alice")
	out := s.mustRun("", "exec", "--env", "T=api", "-e", "U=api:username", "--", "sh", "-c", `echo "t=$T u=$U"; echo "$T" | base64`)
	expect(t, "exec", out, "t=«perry:api» u=alice")
	refuse(t, "exec", out, tok)
	expect(t, "exec b64", out, "«perry:api»")
	if _, e, c := s.run("", "exec", "--", "true"); c != 2 || !strings.Contains(e, "no --env") {
		t.Errorf("no specs: %d %q", c, e)
	}
	if _, e, c := s.run("", "exec", "--env", "NOEQ", "--", "true"); c != 2 || !strings.Contains(e, "VAR=REF") {
		t.Errorf("no eq: %d %q", c, e)
	}
	if _, e, c := s.run("", "exec", "--env", "=api", "--", "true"); c != 2 {
		t.Errorf("empty name: %d %q", c, e)
	}
	if _, _, c := s.run("", "exec", "--env=T=api", "--", "sh", "-c", "exit 4"); c != 4 {
		t.Errorf("exit pass-through %d", c)
	}
}

func TestGetRefusals(t *testing.T) {
	s := newSandbox(t)
	s.add(tok+"\n", "--host", "api.example.com", "--kind", "api", "--user", "")
	if o, e, c := s.run("", "get", "api"); c != 1 || !strings.Contains(e, "refusing; --reveal is required") || o != "" {
		t.Errorf("no reveal: %d %q %q", c, o, e)
	}
	o, e, c := s.run("", "get", "api", "--reveal")
	if c != 1 || !strings.Contains(e, "refusing; stdout is not a terminal") || strings.Contains(o, tok) {
		t.Errorf("not a tty: %d %q %q", c, o, e)
	}
}

func TestScan(t *testing.T) {
	s := newSandbox(t)
	s.add(tok+"\n", "--host", "api.example.com", "--kind", "api", "--user", "")
	if _, _, c := s.run("nothing here\n", "scan"); c != 0 {
		t.Errorf("clean: %d", c)
	}
	o, e, c := s.run("x "+base64.StdEncoding.EncodeToString([]byte(tok))+"\n", "scan")
	if c != 1 || !strings.Contains(e, "perry: scan: stored secret detected") {
		t.Errorf("found: %d %q", c, e)
	}
	refuse(t, "scan output", o+e, tok)
}

func TestLockedFlow(t *testing.T) {
	s := newSandbox(t)
	s.add(tok+"\n", "--host", "api.example.com", "--kind", "api", "--user", "")
	s = s.with("PERRY_PASSPHRASE=correct horse")

	rcpt := strings.TrimSpace(s.mustRun("", "keygen"))
	if !strings.HasPrefix(rcpt, "age1") {
		t.Fatalf("keygen output %q", rcpt)
	}
	if _, e, c := s.run("", "keygen"); c != 1 || !strings.Contains(e, "refusing to overwrite") {
		t.Errorf("keygen twice: %d %q", c, e)
	}
	idPath := filepath.Join(s.home, ".config", "perry", "identity.age")
	if st, err := os.Stat(idPath); err != nil || st.Mode().Perm() != 0o600 {
		t.Errorf("identity file: %v %v", st, err)
	}
	expect(t, "rekey", s.mustRun("", "rekey"), "rekeyed 1 entries to ")
	if _, err := os.Stat(filepath.Join(s.home, ".config", "perry", "store.age.bak")); err != nil {
		t.Error("no store.age.bak after rekey")
	}

	for _, args := range [][]string{{"list"}, {"run", "--", "echo", "{{perry:api}}"}, {"show", "api"}, {"status"}} {
		_, e, c := s.run("", args...)
		if c != 3 {
			t.Errorf("%v: want exit 3, got %d (%q)", args, c, e)
		}
	}
	if _, e, _ := s.run("", "list"); !strings.Contains(e, "locked — run `perry unlock` in your terminal") {
		t.Errorf("locked message: %q", e)
	}
	if _, _, c := s.with("PERRY_PASSPHRASE=wrong").run("", "unlock"); c != 1 {
		t.Errorf("wrong passphrase exit %d", c)
	}
	if _, _, c := s.run("", "list"); c != 3 {
		t.Error("wrong passphrase must not unlock")
	}
	expect(t, "unlock", s.mustRun("", "unlock", "--ttl", "1h"), "unlocked until ")
	expect(t, "status", s.mustRun("", "status"), "unlocked until ")
	expect(t, "list unlocked", s.mustRun("", "list"), "api.example.com")
	if _, e, c := s.run("", "unlock", "--ttl", "1h", "--until", "23:59"); c != 2 || !strings.Contains(e, "mutually exclusive") {
		t.Errorf("ttl+until: %d %q", c, e)
	}
	s.mustRun("", "lock")
	s.mustRun("", "lock") // already locked: still 0
	if o, _, c := s.run("", "status"); c != 3 || strings.TrimSpace(o) != "locked" {
		t.Errorf("status locked: %d %q", c, o)
	}
}

func TestRekeyDefaultsAndRefusals(t *testing.T) {
	s := newSandbox(t).with("PERRY_PASSPHRASE=pw")
	if _, e, c := s.run("", "rekey"); c != 1 || !strings.Contains(e, "no store to rekey") {
		t.Errorf("no store: %d %q", c, e)
	}
	s.add(tok+"\n", "--host", "api.example.com", "--kind", "api", "--user", "")
	if _, e, c := s.with("PERRY_RECIPIENTS="+filepath.Join(s.home, "r")).run("", "rekey"); c != 1 || !strings.Contains(e, "unset PERRY_RECIPIENTS") {
		t.Errorf("recipients env: %d %q", c, e)
	}
	s.mustRun("", "keygen")
	_, e, c := s.run("", "rekey", "--no-backup")
	if c != 0 {
		t.Fatalf("rekey: %d %q", c, e)
	}
	refuse(t, "no-backup warning", e, "warning")
	if _, err := os.Stat(filepath.Join(s.home, ".config", "perry", "store.age.bak")); err == nil {
		t.Error("--no-backup left a .bak")
	}
}

func TestPassphraseVariableIgnoredInReleaseBuilds(t *testing.T) {
	// The release build is built without the perrytest tag.
	bin := filepath.Join(t.TempDir(), "perry-release")
	if out, err := exec.Command("go", "build", "-o", bin, "github.com/benlrice/perry/cmd/perry").CombinedOutput(); err != nil {
		t.Fatalf("build: %v\n%s", err, out)
	}
	s := newSandbox(t).with("PERRY_PASSPHRASE=pw")
	cmd := exec.Command(bin, "keygen")
	cmd.Env = s.env
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	var e bytes.Buffer
	cmd.Stderr = &e
	if err := cmd.Run(); err == nil || !strings.Contains(e.String(), "no TTY available") {
		t.Errorf("release build used PERRY_PASSPHRASE: %v %q", err, e.String())
	}
}

func TestImport(t *testing.T) {
	s := newSandbox(t)
	file := filepath.Join(s.home, "creds.txt")
	body := "# comment\n" +
		"export JIRA_TOKEN=\"jiratoken-123456\"\n" +
		"Grafana prod (https://grafana.example.com:3000/d/x): grafanatoken-654321\n" +
		"gitlab: gitlabtoken-111111\n" +
		"Unknown thing: unknowntoken-222222\n" +
		"slack (leaky.example.com): leaky.example.com\n"
	os.WriteFile(file, []byte(body), 0o600)
	// answers: host for JIRA_TOKEN, host for gitlab, host for Unknown thing (blank)
	out, e, c := s.run("jira.example.com\ngitlab.example.com\n\n", "import", file)
	if c != 0 {
		t.Fatalf("import: %d %q", c, e)
	}
	expect(t, "imported jira", out, "imported: JIRA_TOKEN (jira.example.com, jira)")
	expect(t, "imported grafana", out, "imported: Grafana prod (grafana.example.com:3000, grafana)")
	expect(t, "imported gitlab", out, "imported: gitlab (gitlab.example.com, gitlab)")
	expect(t, "skipped", out, "skipped: Unknown thing")
	expect(t, "leak", out, "host resembles secret, skipped: slack")
	expect(t, "prompt", e, `Host for "JIRA_TOKEN" (blank to skip): `)
	refuse(t, "import output", out+e, "jiratoken-123456")
	// rerun: everything that was imported now exists
	out, _, _ = s.run("\n\n", "import", file)
	expect(t, "exists", out, "exists, skipped: Grafana prod (grafana.example.com:3000, grafana)")
}

func TestStoreUnlockedWhileChildRuns(t *testing.T) {
	s := newSandbox(t)
	s.add(tok+"\n", "--host", "api.example.com", "--kind", "api", "--user", "alice")
	started := filepath.Join(t.TempDir(), "started")
	child := exec.Command(binPath, "run", "--", "sh", "-c", "touch "+started+"; sleep 5")
	child.Env = s.env
	child.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	if err := child.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { child.Process.Kill(); child.Wait() }()
	for i := 0; i < 100; i++ {
		if _, err := os.Stat(started); err == nil {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	done := make(chan struct{})
	go func() {
		s.mustRun(tok+"\n", "add", "--host", "b.example.com", "--kind", "api", "--user", "")
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("add blocked while a run child was alive")
	}
}

package perry

import (
	"bufio"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/benlrice/perry/docs"
	"github.com/benlrice/perry/internal/claudecfg"
	"github.com/benlrice/perry/internal/guard"
	"github.com/benlrice/perry/internal/hook"
	"github.com/benlrice/perry/internal/leak"
	"github.com/benlrice/perry/internal/vault"
)

func cmdScan(args []string) error {
	if len(args) > 0 {
		return usageErrorf("scan takes no arguments")
	}
	text, err := io.ReadAll(stdin)
	if err != nil {
		return &exitError{2, err.Error()}
	}
	res := leak.Check(string(text))
	switch res.Verdict {
	case leak.Locked, leak.Unverifiable:
		return &exitError{2, res.Err.Error()}
	case leak.Leaked:
		return &exitError{1, "stored secret detected"}
	}
	return nil
}

func cmdHook(args []string) error {
	pathsOnly := false
	for _, a := range args {
		if a != "--paths-only" {
			return usageErrorf("usage: perry hook [--paths-only]")
		}
		pathsOnly = true
	}
	nonInteractive = true
	return hook.Serve(stdin, stdout, func(p hook.Payload) string {
		d := guard.Decide(guard.Input{CWD: p.CWD, ToolName: p.ToolName, ToolInput: p.ToolInput, PathsOnly: pathsOnly})
		if d.Locked {
			fmt.Fprintln(stderr, "perry hook: store locked; paths-only checks applied")
		}
		if d.Deny {
			return d.Reason
		}
		return ""
	})
}

func cmdInstall(args []string) error {
	if len(args) == 0 || args[0] != "claude" {
		return usageErrorf("usage: perry install claude [flags]")
	}
	fs := flagSet("install")
	dry := fs.Bool("dry-run", false, "")
	un := fs.Bool("uninstall", false, "")
	po := fs.Bool("paths-only", false, "")
	settings := fs.String("settings", "", "")
	md := fs.String("claude-md", "", "")
	pos, err := parseFlags(fs, args[1:])
	if err != nil {
		return err
	}
	if len(pos) > 0 {
		return usageErrorf("unexpected argument %q", pos[0])
	}
	dir := os.Getenv("CLAUDE_CONFIG_DIR")
	if dir == "" {
		home, _ := os.UserHomeDir()
		dir = filepath.Join(home, ".claude")
	}
	if *settings == "" {
		*settings = filepath.Join(dir, "settings.json")
	}
	if *md == "" {
		*md = filepath.Join(dir, "CLAUDE.md")
	}
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	if r, err := filepath.EvalSymlinks(exe); err == nil {
		exe = r
	}
	rep, err := claudecfg.Install(claudecfg.Options{
		SettingsPath: *settings, ClaudeMDPath: *md, Exe: exe, Doc: docs.ClaudeCode,
		DryRun: *dry, Uninstall: *un, PathsOnly: *po,
	})
	fmt.Fprint(stdout, rep.String())
	return err
}

// ---- import ----

var knownKinds = []string{"jira", "jenkins", "grafana", "github", "gitlab", "bitbucket", "artifactory", "confluence", "slack", "ghe"}

var (
	exportRe = regexp.MustCompile(`^export\s+([A-Za-z_][A-Za-z0-9_]*)=(.*)$`)
	hostedRe = regexp.MustCompile(`^(.+?)\s*\(([^)]*)\)\s*:\s*(.+)$`)
	plainRe  = regexp.MustCompile(`^([^:]+?)\s*:\s*(.+)$`)
)

type importLine struct{ label, host, kind, secret string }

func kindOf(label string) string {
	l := strings.ToLower(label)
	for _, k := range knownKinds {
		if strings.Contains(l, k) {
			return k
		}
	}
	return ""
}

// hostOf extracts the host (port kept) from a URL or host text.
func hostOf(s string) string {
	s = strings.TrimSpace(s)
	if strings.Contains(s, "://") {
		if u, err := url.Parse(s); err == nil && u.Host != "" {
			return u.Host
		}
	}
	h, _, _ := strings.Cut(s, "/")
	return h
}

func parseImportLine(line string) (importLine, bool) {
	line = strings.TrimSpace(line)
	if line == "" || strings.HasPrefix(line, "#") {
		return importLine{}, false
	}
	if m := exportRe.FindStringSubmatch(line); m != nil {
		v := strings.Trim(strings.TrimSpace(m[2]), `"'`)
		return importLine{label: m[1], kind: kindOf(m[1]), secret: v}, true
	}
	if m := hostedRe.FindStringSubmatch(line); m != nil {
		return importLine{label: strings.TrimSpace(m[1]), host: hostOf(m[2]), kind: kindOf(m[1]), secret: strings.TrimSpace(m[3])}, true
	}
	if m := plainRe.FindStringSubmatch(line); m != nil {
		return importLine{label: strings.TrimSpace(m[1]), kind: kindOf(m[1]), secret: strings.TrimSpace(m[2])}, true
	}
	return importLine{}, false
}

// hostLeaksSecret: the host holds the secret, or a 12-character window of it.
func hostLeaksSecret(host, secret string) bool {
	h, s := strings.ToLower(host), strings.ToLower(secret)
	if s == "" {
		return false
	}
	if strings.Contains(h, s) {
		return true
	}
	for i := 0; i+12 <= len(s); i++ {
		if strings.Contains(h, s[i:i+12]) {
			return true
		}
	}
	return false
}

func cmdImport(args []string) error {
	if len(args) != 1 || strings.HasPrefix(args[0], "-") {
		return usageErrorf("usage: perry import FILE")
	}
	f, err := os.Open(args[0])
	if err != nil {
		return err
	}
	defer f.Close()
	answers := bufio.NewReader(stdin)
	ask := func(prompt string) string {
		fmt.Fprint(stderr, prompt)
		l, _ := answers.ReadString('\n')
		return strings.TrimSpace(l)
	}

	var lines []importLine
	var skipped []string
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	for sc.Scan() {
		il, ok := parseImportLine(sc.Text())
		if !ok {
			continue
		}
		if il.host == "" {
			il.host = ask(fmt.Sprintf("Host for %q (blank to skip): ", il.label))
		}
		if il.host != "" && il.kind == "" {
			il.kind = ask(fmt.Sprintf("Kind for %q (blank to skip): ", il.label))
		}
		if il.host == "" || il.kind == "" {
			skipped = append(skipped, "skipped: "+il.label)
			continue
		}
		lines = append(lines, il)
	}
	if err := sc.Err(); err != nil {
		return err
	}

	report := skipped
	err = vault.Update(func(d *vault.Data) error {
		for _, il := range lines {
			switch {
			case hostLeaksSecret(il.host, il.secret):
				report = append(report, "host resembles secret, skipped: "+il.label)
			case d.Find(il.host, il.kind) >= 0:
				report = append(report, fmt.Sprintf("exists, skipped: %s (%s, %s)", il.label, il.host, il.kind))
			default:
				t := now()
				d.Entries = append(d.Entries, vault.Entry{Host: il.host, Kind: il.kind, Secret: il.secret, Created: t, Updated: t})
				report = append(report, fmt.Sprintf("imported: %s (%s, %s)", il.label, il.host, il.kind))
			}
		}
		return nil
	})
	if err != nil {
		return err
	}
	for _, r := range report {
		fmt.Fprintln(stdout, r)
	}
	return nil
}

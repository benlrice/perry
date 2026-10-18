package guard

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/benlrice/perry/internal/vault"
)

const (
	// preB: start of text, or a character that cannot continue a name.
	preB = "(?:^|[^A-Za-z0-9_.\\-])"
	// postB: end of text, whitespace, a quote, or a path/shell delimiter.
	postB = "(?:$|[\\s\"'`;|&)<>*?/\\\\])"
)

// Labels, in check order.
const (
	labelToken  = "token file"
	labelStore  = "perry store"
	labelSSHKey = "SSH private key"
	labelSSHDir = "SSH key directory"
	labelAWS    = "AWS credentials"
	labelNetrc  = "netrc"
	labelGH     = "GitHub CLI token file"
	labelKube   = "kubeconfig"
)

type finder struct {
	label string
	find  func(text string) (string, bool)
}

type pathChecker struct {
	home    string
	cfgDir  string
	finders []finder
}

var jqRe = regexp.MustCompile(`((?:^|[^A-Za-z0-9_.\-])(?:jq|yq|gojq)(?:\s+-\S*)*\s+)\.tokens`)

func newPathChecker() *pathChecker {
	home, _ := os.UserHomeDir()
	c := &pathChecker{home: home, cfgDir: vault.ConfigDir()}
	hp := `(?:~|\$HOME|\$\{HOME\}`
	if home != "" {
		hp += "|" + regexp.QuoteMeta(home)
	}
	hp += ")"
	re := func(pattern string) *regexp.Regexp { return regexp.MustCompile(pattern) }
	plain := func(r *regexp.Regexp) func(string) (string, bool) {
		return func(t string) (string, bool) {
			if m := r.FindString(t); m != "" {
				return m, true
			}
			return "", false
		}
	}
	add := func(label string, f func(string) (string, bool)) {
		c.finders = append(c.finders, finder{label, f})
	}

	tokens := re(preB + `\.tokens` + postB)
	add(labelToken, func(t string) (string, bool) { return plain(tokens)(jqRe.ReplaceAllString(t, "${1}FILTER")) })

	var names []string
	for _, n := range vault.ConfigFiles() {
		names = append(names, regexp.QuoteMeta(n))
	}
	for _, r := range []*regexp.Regexp{
		re(preB + `\.config/perry` + postB),
		re(preB + `\$\{?XDG_CONFIG_HOME\}?/perry` + postB),
		re(preB + `perry/(?:` + strings.Join(names, "|") + `)(?:\.bak)?(?:$|[^A-Za-z0-9_.\-])`),
	} {
		add(labelStore, plain(r))
	}
	for i, p := range vault.ProtectedPaths() {
		label := labelStore
		if i > 0 {
			label = labelSSHKey
		}
		add(label, plain(re(`(?:^|[^A-Za-z0-9_.\-])`+regexp.QuoteMeta(p)+postB)))
	}
	sshFile := re(preB + hp + `/\.ssh/([^\s"'` + "`" + `;|&)<>*?/\\\[\]{}]+)`)
	add(labelSSHKey, func(t string) (string, bool) {
		for _, m := range sshFile.FindAllStringSubmatch(t, -1) {
			switch name := m[1]; {
			case strings.HasSuffix(name, ".pub"), name == "config", name == "known_hosts", name == "known_hosts.old":
			default:
				return m[0], true
			}
		}
		return "", false
	})
	algo := re(preB + `id_(?:rsa|dsa|ecdsa|ed25519)[A-Za-z0-9_.\-]*`)
	add(labelSSHKey, func(t string) (string, bool) {
		for _, m := range algo.FindAllString(t, -1) {
			if !strings.HasSuffix(m, ".pub") {
				return m, true
			}
		}
		return "", false
	})

	dirEnd := re(preB + hp + `/\.ssh/?(?:$|[\s"'*?\[{;|&)])`)
	dirGlob := re(preB + hp + `/\.ssh/[*?\[{]`)
	add(labelSSHDir, plain(dirEnd))
	add(labelSSHDir, plain(dirGlob))

	add(labelAWS, plain(re(preB+`\.aws`+postB)))
	add(labelNetrc, plain(re(preB+`\.netrc`+postB)))
	add(labelGH, plain(re(preB+`\.config/gh/hosts\.yml`+postB)))
	add(labelKube, plain(re(preB+`\.kube/config`+postB)))
	return c
}

// check returns the first credential label whose pattern matches text.
// With rel set the perry-store patterns are skipped; the caller checks the real
// config dir instead, so a project dir named perry does not trip them.
func (c *pathChecker) check(text string, rel bool) (label, match string, ok bool) {
	for _, f := range c.finders {
		if rel && f.label == labelStore {
			continue
		}
		if m, ok := f.find(text); ok {
			return f.label, trimMatch(m), true
		}
	}
	return "", "", false
}

const boundaryChars = " \t\r\n\"'`;|&)<>*?/\\([{"

func trimMatch(m string) string {
	m = strings.Trim(m, boundaryChars)
	if len(m) > 80 {
		m = m[:80] + "..."
	}
	return m
}

// relative tracks the current dir of a Bash command (relative to home) and
// checks relative tokens as if they were written under ~/.
func (c *pathChecker) relative(cwd, cmd string) (label, match string, ok bool) {
	if c.home == "" {
		return
	}
	cur, tracked := c.relOf(cwd, "")
	if cwd == "" {
		tracked = false
	}
	segs := strings.FieldsFunc(cmd, func(r rune) bool { return strings.ContainsRune(";&|\n()", r) })
	for _, seg := range segs {
		fields := strings.Fields(seg)
		if len(fields) == 0 {
			continue
		}
		if fields[0] == "cd" || fields[0] == "pushd" {
			if len(fields) == 1 {
				cur, tracked = "", true
			} else {
				target := unquote(fields[len(fields)-1])
				if target == "-" {
					cur, tracked = "", false
				} else if cur, tracked = c.relOf(target, cur); !tracked {
					cur = ""
				}
			}
			continue
		}
		for _, f := range fields[1:] {
			tok := strings.TrimLeft(unquote(f), "<>")
			if tok == "" || strings.HasPrefix(tok, "-") {
				continue
			}
			var rel string
			var ok2 bool
			if tracked {
				rel, ok2 = c.relOf(tok, cur)
			} else {
				rel, ok2 = c.relOf(tok, "")
				ok2 = ok2 && hasHomePrefix(tok, c.home)
			}
			if !ok2 {
				continue
			}
			if l, m, hit := c.checkRel(rel, tok); hit {
				return l, m, true
			}
		}
	}
	return
}

func hasHomePrefix(tok, home string) bool {
	for _, p := range []string{"~", "$HOME", "${HOME}", home} {
		if tok == p || strings.HasPrefix(tok, p+"/") {
			return true
		}
	}
	return false
}

func unquote(s string) string { return strings.Trim(s, `"'`) }

// relOf resolves tok against cur (a home-relative dir). The result is a clean
// home-relative path. ok is false when the path leaves home.
func (c *pathChecker) relOf(tok, cur string) (string, bool) {
	for _, p := range []string{"${HOME}", "$HOME", "~", c.home} {
		if p == "" {
			continue
		}
		if tok == p {
			return "", true
		}
		if strings.HasPrefix(tok, p+"/") {
			return cleanRel(strings.TrimPrefix(tok, p+"/"))
		}
	}
	if strings.HasPrefix(tok, "/") || strings.HasPrefix(tok, "~") || strings.HasPrefix(tok, "$") {
		return "", false
	}
	return cleanRel(filepath.Join(cur, tok))
}

func cleanRel(p string) (string, bool) {
	p = filepath.Clean(p)
	if p == "." {
		return "", true
	}
	if p == ".." || strings.HasPrefix(p, "../") {
		return "", false
	}
	return p, true
}

func keyLike(name string) bool {
	if strings.HasSuffix(name, ".pub") {
		return false
	}
	return strings.ContainsAny(name, "*?[{") || strings.HasPrefix(name, "id_") ||
		strings.HasSuffix(name, ".pem") || strings.HasSuffix(name, ".key") || name == "authorized_keys"
}

func (c *pathChecker) checkRel(rel, tok string) (label, match string, ok bool) {
	if strings.HasPrefix(rel, ".ssh/") && keyLike(strings.TrimPrefix(rel, ".ssh/")) {
		return labelSSHKey, trimMatch(tok), true
	}
	if label, _, ok := c.check("~/"+rel, true); ok {
		return label, trimMatch(tok), true
	}
	abs := filepath.Join(c.home, rel)
	if abs == c.cfgDir || strings.HasPrefix(abs, c.cfgDir+"/") {
		return labelStore, trimMatch(tok), true
	}
	return "", "", false
}

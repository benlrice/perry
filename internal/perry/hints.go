package perry

import (
	"path/filepath"
	"regexp"
	"strings"
)

var placeholderRe = regexp.MustCompile(`\{\{perry:([^{}]+)\}\}`)

// stripField removes a trailing :secret or :username from a ref.
func stripField(ref string) string {
	for _, f := range []string{":secret", ":username"} {
		if strings.HasSuffix(ref, f) {
			return strings.TrimSuffix(ref, f)
		}
	}
	return ref
}

// curlUserHint warns when curl -u gets a placeholder with no ':' outside the
// placeholders, which sends the token as the username. It sees the argv before
// substitution, so it never holds a value.
func curlUserHint(argv []string) string {
	if len(argv) == 0 || filepath.Base(argv[0]) != "curl" {
		return ""
	}
	for i := 1; i < len(argv); i++ {
		var val string
		switch a := argv[i]; {
		case a == "-u" || a == "--user":
			if i+1 < len(argv) {
				val = argv[i+1]
			}
		case strings.HasPrefix(a, "--user="):
			val = strings.TrimPrefix(a, "--user=")
		case strings.HasPrefix(a, "-u") && !strings.HasPrefix(a, "--") && len(a) > 2:
			val = a[2:]
		}
		m := placeholderRe.FindStringSubmatch(val)
		if m == nil || strings.Contains(placeholderRe.ReplaceAllString(val, "X"), ":") {
			continue
		}
		ref := stripField(m[1])
		return "perry: hint: curl -u needs user:token, but the value has no ':'. Use -u '{{perry:" + ref + ":username}}:{{perry:" + ref + "}}'"
	}
	return ""
}

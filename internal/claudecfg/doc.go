package claudecfg

import (
	"encoding/json"
	"errors"
	"strings"
)

// docData is what the installer reads from docs/claude-code.md.
type docData struct {
	Snippet string
	Deny    []string
	Probe   string // JSON on stdin for the verify probe, with /home/you in it
}

type fence struct{ lang, body string }

func fences(doc string) []fence {
	var out []fence
	var cur *fence
	var body []string
	for _, l := range strings.Split(doc, "\n") {
		switch {
		case cur == nil && strings.HasPrefix(l, "```"):
			cur = &fence{lang: strings.TrimSpace(strings.TrimPrefix(l, "```"))}
			body = nil
		case cur != nil && strings.HasPrefix(l, "```"):
			cur.body = strings.Join(body, "\n")
			out = append(out, *cur)
			cur = nil
		case cur != nil:
			body = append(body, l)
		}
	}
	return out
}

func parseDoc(doc string) (docData, error) {
	var d docData
	for _, f := range fences(doc) {
		switch {
		case f.lang == "markdown" && d.Snippet == "" && strings.Contains(f.body, "## Credentials (perry)"):
			d.Snippet = strings.TrimSpace(f.body)
		case f.lang == "json" && d.Deny == nil && strings.Contains(f.body, `"permissions"`):
			var v struct {
				Permissions struct {
					Deny []string `json:"deny"`
				} `json:"permissions"`
			}
			if err := json.Unmarshal([]byte(f.body), &v); err != nil {
				return d, errors.New("doc: bad permissions block: " + err.Error())
			}
			d.Deny = v.Permissions.Deny
		case f.lang == "" && d.Probe == "":
			for _, l := range strings.Split(f.body, "\n") {
				if strings.Contains(l, "| perry hook") && strings.Contains(l, "/home/you") {
					a, b := strings.Index(l, "'"), strings.LastIndex(l, "'")
					if a >= 0 && b > a {
						d.Probe = l[a+1 : b]
					}
				}
			}
		}
	}
	switch {
	case d.Snippet == "":
		return d, errors.New("doc: no CLAUDE.md snippet found")
	case len(d.Deny) == 0:
		return d, errors.New("doc: no deny rules found")
	case d.Probe == "":
		return d, errors.New("doc: no verify probe found")
	}
	return d, nil
}

package guard

import (
	"regexp"
	"strings"
)

// stripData removes the text that a shell treats as data, so a commit message
// or a search pattern that mentions a blocked command is not read as the
// command. It fails closed: when anything could run or expand the text, it
// returns the command unchanged and the strict path applies.
func stripData(cmd string) string {
	body, ok := stripHeredocs(cmd)
	if !ok {
		return cmd
	}
	segs, ok := splitSegments(body)
	if !ok {
		return cmd
	}
	var b strings.Builder
	for _, s := range segs {
		text := s.text
		if strings.TrimSpace(text) != "" {
			head := firstWord(text)
			if !readerHeads[head] {
				return cmd
			}
			if singleQuoteHeads[head] {
				var ok bool
				if text, ok = blankSingleQuotes(text); !ok {
					return cmd
				}
			}
		}
		b.WriteString(text)
		b.WriteString(s.sep)
	}
	out := b.String()
	for _, bad := range []string{"$(", "`", "<(", ">("} {
		if strings.Contains(out, bad) {
			return cmd
		}
	}
	return out
}

var (
	heredocHeads = set("cat", "git", "gh", "tee", "echo", "printf")
	// singleQuoteHeads may have single-quoted words emptied.
	singleQuoteHeads = set("echo", "printf", "rg", "grep", "egrep", "fgrep", "ag")
	// readerHeads keeps `| sh`, eval, bash -c and xargs on the strict path.
	readerHeads = set("cat", "git", "gh", "tee", "echo", "printf", "rg", "grep", "egrep", "fgrep", "ag",
		"head", "tail", "wc", "sort", "uniq", "cut", "tr", "ls", "cd", "pwd", "diff", "true", "false",
		"mkdir", "touch", "go", "make")
	heredocRe = regexp.MustCompile(`<<(-?)[ \t]*(?:'([^']*)'|"([^"]*)"|([A-Za-z_][A-Za-z0-9_]*))`)
)

func set(words ...string) map[string]bool {
	m := make(map[string]bool, len(words))
	for _, w := range words {
		m[w] = true
	}
	return m
}

func firstWord(s string) string {
	f := strings.Fields(s)
	if len(f) == 0 {
		return ""
	}
	return f[0]
}

// stripHeredocs drops heredoc bodies when the command word is a known writer.
// ok is false when the command must stay unchanged.
func stripHeredocs(cmd string) (string, bool) {
	if !strings.Contains(cmd, "<<") {
		return cmd, true
	}
	if strings.Contains(cmd, "<<<") {
		return "", false
	}
	lines := strings.Split(cmd, "\n")
	var out []string
	for i := 0; i < len(lines); i++ {
		line := lines[i]
		out = append(out, line)
		if !strings.Contains(line, "<<") {
			continue
		}
		m := heredocRe.FindStringSubmatch(line)
		if m == nil {
			return "", false
		}
		// every heredoc operator on the line must be well formed
		if strings.Count(line, "<<") != len(heredocRe.FindAllString(line, -1)) {
			return "", false
		}
		delim, quoted := m[2], true
		switch {
		case m[2] != "" || strings.Contains(m[0], "'"):
		case m[3] != "" || strings.Contains(m[0], `"`):
			delim = m[3]
		default:
			delim, quoted = m[4], false
		}
		if delim == "" {
			return "", false
		}
		before := line[:strings.Index(line, "<<")]
		if !heredocHeads[commandWordBefore(before)] {
			return "", false
		}
		dash := m[1] == "-"
		end := -1
		for j := i + 1; j < len(lines); j++ {
			l := lines[j]
			if dash {
				l = strings.TrimLeft(l, "\t")
			}
			if l == delim {
				end = j
				break
			}
		}
		if end < 0 {
			return "", false
		}
		if !quoted {
			for _, l := range lines[i+1 : end] {
				if strings.Contains(l, "$(") || strings.Contains(l, "`") {
					return "", false
				}
			}
		}
		i = end
	}
	return strings.Join(out, "\n"), true
}

// commandWordBefore returns the first word of the last command in s.
func commandWordBefore(s string) string {
	cut := strings.LastIndexAny(s, ";&|(\n")
	return firstWord(s[cut+1:])
}

type segment struct{ text, sep string }

// splitSegments splits on ; & | newline ( ) outside quotes. An & that is part
// of 2>&1, >&2 or &> is a redirection. ok is false on an unterminated quote.
func splitSegments(s string) ([]segment, bool) {
	var segs []segment
	start := 0
	var inS, inD bool
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case inS:
			if c == '\'' {
				inS = false
			}
		case inD:
			if c == '\\' {
				i++
			} else if c == '"' {
				inD = false
			}
		case c == '\\':
			i++
		case c == '\'':
			inS = true
		case c == '"':
			inD = true
		case c == ';' || c == '|' || c == '\n' || c == '(' || c == ')' || c == '&':
			if c == '&' && (i > 0 && s[i-1] == '>' || i+1 < len(s) && s[i+1] == '>') {
				continue
			}
			segs = append(segs, segment{s[start:i], string(c)})
			start = i + 1
		}
	}
	if inS || inD {
		return nil, false
	}
	return append(segs, segment{s[start:], ""}), true
}

// blankSingleQuotes empties each single-quoted word. ok is false on an
// unterminated quote or when the command word is itself quoted.
func blankSingleQuotes(s string) (string, bool) {
	var b strings.Builder
	var inD bool
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case inD:
			b.WriteByte(c)
			if c == '\\' && i+1 < len(s) {
				i++
				b.WriteByte(s[i])
			} else if c == '"' {
				inD = false
			}
		case c == '"':
			inD = true
			b.WriteByte(c)
		case c == '\\' && i+1 < len(s):
			b.WriteByte(c)
			i++
			b.WriteByte(s[i])
		case c == '\'':
			end := strings.IndexByte(s[i+1:], '\'')
			if end < 0 {
				return "", false
			}
			b.WriteString("''")
			i += end + 1
		default:
			b.WriteByte(c)
		}
	}
	return b.String(), true
}

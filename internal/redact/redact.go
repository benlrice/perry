// Package redact finds and scrubs the encoded forms of stored secrets.
package redact

import (
	"encoding/base64"
	"io"
	"net/url"
	"sort"
	"strings"
	"sync"
)

// MinLen is the shortest secret (in bytes) that gets encoded forms and
// unreferenced redaction.
const MinLen = 6

// Item is one stored secret. Label is set when a command references the entry;
// an empty Label means the entry is only scanned for.
type Item struct {
	Host, Kind, Secret, Username string
	Label                        string
}

// Forms returns every form of the secret to look for, literal first, without
// duplicates or empty strings.
func Forms(secret, username string) []string {
	forms := []string{secret}
	if len(secret) >= MinLen {
		inputs := []string{secret}
		if username != "" {
			inputs = append(inputs, username+":"+secret)
		}
		for _, in := range inputs {
			forms = append(forms, middles([]byte(in))...)
			b := []byte(in)
			forms = append(forms,
				base64.StdEncoding.EncodeToString(b),
				base64.URLEncoding.EncodeToString(b),
				base64.RawStdEncoding.EncodeToString(b),
				base64.RawURLEncoding.EncodeToString(b),
			)
		}
		forms = append(forms, url.QueryEscape(secret), url.PathEscape(secret))
	}
	seen := make(map[string]bool, len(forms))
	out := forms[:0]
	for _, f := range forms {
		if f == "" || seen[f] {
			continue
		}
		seen[f] = true
		out = append(out, f)
	}
	return out
}

// middles returns the base64 text that a secret produces when it sits inside a
// larger stream at any of the three byte alignments. Characters that depend on
// neighbouring bytes are dropped.
func middles(in []byte) []string {
	var out []string
	for k := 0; k < 3; k++ {
		buf := make([]byte, k+len(in)+2)
		copy(buf[k:], in)
		buf = buf[:len(buf)-len(buf)%3]
		lo, hi := k, k+len(in)
		first, last := -1, -1
		for i := 0; i < (len(buf)*8+5)/6; i++ {
			b0, b1 := i*6/8, (i*6+5)/8
			if b0 >= lo && b1 < hi {
				if first < 0 {
					first = i
				}
				last = i
			}
		}
		if first < 0 {
			continue
		}
		for _, enc := range []*base64.Encoding{base64.RawStdEncoding, base64.RawURLEncoding} {
			out = append(out, enc.EncodeToString(buf)[first:last+1])
		}
	}
	return out
}

type pattern struct {
	text, label string
}

// Redactor replaces secret forms with «perry:LABEL» marks.
type Redactor struct {
	patterns []pattern
}

// New builds a Redactor. A referenced item is redacted under its Label. An
// unreferenced item is redacted only when its secret is at least MinLen bytes,
// under its host (or kind when the host is empty).
func New(items []Item) *Redactor {
	r := &Redactor{}
	for _, it := range items {
		label := it.Label
		if label == "" {
			if len(it.Secret) < MinLen {
				continue
			}
			label = it.Host
			if label == "" {
				label = it.Kind
			}
		}
		if it.Secret == "" {
			continue
		}
		for _, f := range Forms(it.Secret, it.Username) {
			r.patterns = append(r.patterns, pattern{f, label})
		}
	}
	sort.SliceStable(r.patterns, func(i, j int) bool {
		return len(r.patterns[i].text) > len(r.patterns[j].text)
	})
	return r
}

func mark(label string) string { return "«perry:" + label + "»" }

// replace scans s left to right. Unless final is set, it stops at the first
// position whose rest could still grow into a pattern and returns the held
// bytes as rest.
func (r *Redactor) replace(s string, final bool) (out, rest string) {
	var b strings.Builder
	i := 0
scan:
	for i < len(s) {
		rem := s[i:]
		if !final {
			for _, p := range r.patterns {
				if len(p.text) > len(rem) && strings.HasPrefix(p.text, rem) {
					break scan
				}
			}
		}
		for _, p := range r.patterns {
			if strings.HasPrefix(rem, p.text) {
				b.WriteString(mark(p.label))
				i += len(p.text)
				continue scan
			}
		}
		b.WriteByte(s[i])
		i++
	}
	return b.String(), s[i:]
}

// Scrub replaces every secret form in s.
func (r *Redactor) Scrub(s string) string {
	out, _ := r.replace(s, true)
	return out
}

// Writer is a streaming scrubber. Call Flush at EOF.
type Writer struct {
	mu   sync.Mutex
	r    *Redactor
	w    io.Writer
	held string
}

// Writer returns a scrubbing writer on top of w.
func (r *Redactor) Writer(w io.Writer) *Writer { return &Writer{r: r, w: w} }

// Write reports len(p) written when the underlying write succeeds.
func (w *Writer) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	out, rest := w.r.replace(w.held+string(p), false)
	w.held = rest
	if out != "" {
		if _, err := io.WriteString(w.w, out); err != nil {
			return 0, err
		}
	}
	return len(p), nil
}

// Flush writes the held bytes, scrubbed. Call it once at EOF.
func (w *Writer) Flush() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	out, _ := w.r.replace(w.held, true)
	w.held = ""
	if out == "" {
		return nil
	}
	_, err := io.WriteString(w.w, out)
	return err
}

// Contains reports whether text holds any form of the secret. A secret shorter
// than MinLen matches only as a whole word. It never returns the match.
func Contains(text, secret, username string) bool {
	if secret == "" {
		return false
	}
	if len(secret) < MinLen {
		return containsWord(text, secret)
	}
	for _, f := range Forms(secret, username) {
		if strings.Contains(text, f) {
			return true
		}
	}
	return false
}

func isWord(c byte) bool {
	return c == '_' || c >= '0' && c <= '9' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z'
}

func containsWord(text, w string) bool {
	for from := 0; ; {
		i := strings.Index(text[from:], w)
		if i < 0 {
			return false
		}
		i += from
		end := i + len(w)
		if (i == 0 || !isWord(text[i-1])) && (end == len(text) || !isWord(text[end])) {
			return true
		}
		from = i + 1
	}
}

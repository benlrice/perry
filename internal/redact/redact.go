// Package redact finds and scrubs the encoded forms of stored secrets.
package redact

import (
	"encoding/base64"
	"io"
	"net/url"
	"sort"
	"strings"
	"sync"

	"github.com/benlrice/perry/internal/vault"
)

// MinLen is the shortest secret (in bytes) that gets encoded forms. A shorter
// secret has only its literal form, and that form matches only as a whole word.
const MinLen = 6

// forms returns every form of the secret to look for, literal first, without
// duplicates or empty strings.
func forms(secret, username string) []string {
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
	word        bool // matches only as a whole word
}

// Set is the secret set built from the stored entries. It scrubs strings and
// streams, and reports whether texts hold a form of any stored secret.
type Set struct {
	patterns []pattern
}

// New builds a Set from the stored entries and the resolved refs (empty for
// the Leak check). An entry a ref resolved to is redacted under the ref label.
// Any other entry is redacted under its host (or kind when the host is empty).
func New(entries []vault.Entry, refs []vault.Ref) *Set {
	r := &Set{}
	type key struct{ host, kind string }
	labels := map[key]string{}
	var all []vault.Entry
	for _, ref := range refs {
		e := ref.Entry
		all = append(all, e)
		labels[key{e.Host, e.Kind}] = ref.Label
	}
	for _, e := range entries {
		if _, ok := labels[key{e.Host, e.Kind}]; !ok {
			all = append(all, e)
		}
	}
	for _, e := range all {
		if e.Secret == "" {
			continue
		}
		label, ok := labels[key{e.Host, e.Kind}]
		if !ok {
			label = e.Host
			if label == "" {
				label = e.Kind
			}
		}
		short := len(e.Secret) < MinLen
		for _, f := range forms(e.Secret, e.Username) {
			r.patterns = append(r.patterns, pattern{f, label, short})
		}
	}
	sort.SliceStable(r.patterns, func(i, j int) bool {
		return len(r.patterns[i].text) > len(r.patterns[j].text)
	})
	return r
}

func mark(label string) string { return "«perry:" + label + "»" }

func isWord(c byte) bool {
	return c == '_' || c >= '0' && c <= '9' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z'
}

// replace scans s left to right; prevWord says whether the byte before s is a
// word character. Unless final is set, it stops at the first position whose
// rest could still grow into a pattern, or whose whole-word match still needs
// the next byte, and returns the held bytes as rest. hit reports whether any
// pattern matched.
func (r *Set) replace(s string, prevWord, final bool) (out, rest string, hit bool) {
	var b strings.Builder
	i := 0
scan:
	for i < len(s) {
		rem := s[i:]
		before := prevWord
		if i > 0 {
			before = isWord(s[i-1])
		}
		if !final {
			for _, p := range r.patterns {
				if len(p.text) > len(rem) && strings.HasPrefix(p.text, rem) {
					break scan
				}
			}
		}
		for _, p := range r.patterns {
			if !strings.HasPrefix(rem, p.text) {
				continue
			}
			if p.word {
				if before {
					continue
				}
				if end := i + len(p.text); end < len(s) {
					if isWord(s[end]) {
						continue
					}
				} else if !final {
					break scan
				}
			}
			b.WriteString(mark(p.label))
			i += len(p.text)
			hit = true
			continue scan
		}
		b.WriteByte(s[i])
		i++
	}
	return b.String(), s[i:], hit
}

// Scrub replaces every secret form in s.
func (r *Set) Scrub(s string) string {
	out, _, _ := r.replace(s, false, true)
	return out
}

// Writer is a streaming scrubber. Call Flush at EOF.
type Writer struct {
	mu   sync.Mutex
	r    *Set
	w    io.Writer
	held string
	prev bool // the last byte before held is a word character
}

// Writer returns a scrubbing writer on top of w.
func (r *Set) Writer(w io.Writer) *Writer { return &Writer{r: r, w: w} }

// Write reports len(p) written when the underlying write succeeds.
func (w *Writer) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	in := w.held + string(p)
	out, rest, _ := w.r.replace(in, w.prev, false)
	if n := len(in) - len(rest); n > 0 {
		w.prev = isWord(in[n-1])
	}
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
	out, _, _ := w.r.replace(w.held, w.prev, true)
	w.held = ""
	if out == "" {
		return nil
	}
	_, err := io.WriteString(w.w, out)
	return err
}

// Contains reports whether any text holds a form of a stored secret: exactly
// when Scrub would change it. It never returns the match.
func (r *Set) Contains(texts ...string) bool {
	for _, t := range texts {
		if _, _, hit := r.replace(t, false, true); hit {
			return true
		}
	}
	return false
}

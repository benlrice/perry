package redact

import (
	"bytes"
	"encoding/base64"
	"net/url"
	"strings"
	"testing"

	"github.com/benlrice/perry/internal/vault"
)

const secret = "s3cr3t-Tok/en+value"

func entry(host, kind, sec string) vault.Entry {
	return vault.Entry{Host: host, Kind: kind, Secret: sec, Username: "alice"}
}

// refd returns a Set where the single entry is referenced under label.
func refd(label, sec string) *Set {
	e := entry("h.example.com", "jira", sec)
	return New([]vault.Entry{e}, []vault.Ref{{Entry: e, Label: label}})
}

func TestWriterHoldsBackSplitSecret(t *testing.T) {
	r := refd("h", secret)
	var out bytes.Buffer
	w := r.Writer(&out)
	for i := 0; i < len(secret); i += 3 {
		end := min(i+3, len(secret))
		n, err := w.Write([]byte(secret[i:end]))
		if err != nil || n != end-i {
			t.Fatalf("write: %d %v", n, err)
		}
	}
	if strings.Contains(out.String(), "s3cr3t") {
		t.Fatalf("leak before flush: %q", out.String())
	}
	if err := w.Flush(); err != nil {
		t.Fatal(err)
	}
	if out.String() != "«perry:h»" {
		t.Errorf("got %q", out.String())
	}
}

func TestWriterFlushesPartialPrefixAtEOF(t *testing.T) {
	r := refd("h", secret)
	var out bytes.Buffer
	w := r.Writer(&out)
	w.Write([]byte("hello s3cr"))
	w.Flush()
	if out.String() != "hello s3cr" {
		t.Errorf("got %q", out.String())
	}
}

func TestScrubAndContainsAgree(t *testing.T) {
	enc := func(e *base64.Encoding, in string) string { return e.EncodeToString([]byte(in)) }
	mk := "«perry:h.example.com»"
	unref := New([]vault.Entry{entry("h.example.com", "jira", secret)}, nil)
	ref := refd("h.example.com", secret)
	cases := []struct {
		name string
		set  *Set
		text string
		want string // scrubbed text; equal to text when nothing matches
	}{
		{"literal", ref, "x " + secret + " y", "x " + mk + " y"},
		{"std", ref, enc(base64.StdEncoding, secret), mk},
		{"url", ref, enc(base64.URLEncoding, secret), mk},
		{"rawstd", ref, enc(base64.RawStdEncoding, secret), mk},
		{"rawurl", ref, enc(base64.RawURLEncoding, secret), mk},
		{"basic-auth", ref, enc(base64.StdEncoding, "alice:"+secret), mk},
		{"query", ref, url.QueryEscape(secret), mk},
		{"path", ref, url.PathEscape(secret), mk},
		{"unreferenced long", unref, "x " + secret, "x " + mk},
		{"unrelated", ref, "unrelated", "unrelated"},
		{"short whole word referenced", refd("h", "cat"), "a cat sat", "a «perry:h» sat"},
		{"short whole word unreferenced", New([]vault.Entry{entry("s.example.com", "web", "cat")}, nil), "a cat sat", "a «perry:s.example.com» sat"},
		{"short inside a word", refd("h", "cat"), "category", "category"},
		{"short after underscore", refd("h", "cat"), "snake_cat", "snake_cat"},
		{"short at both ends", refd("h", "cat"), "cat", "«perry:h»"},
		{"label falls back to kind", New([]vault.Entry{entry("", "slack", "zzzzzzzz")}, nil), "zzzzzzzz", "«perry:slack»"},
		{"longest form wins", New([]vault.Entry{entry("a", "k", "password1"), entry("b", "k", "password12")}, nil), "password12", "«perry:b»"},
		{"empty secret ignored", New([]vault.Entry{entry("h", "k", "")}, nil), "anything", "anything"},
	}
	for _, c := range cases {
		got := c.set.Scrub(c.text)
		if got != c.want {
			t.Errorf("%s: scrub got %q want %q", c.name, got, c.want)
		}
		if has := c.set.Contains(c.text); has != (got != c.text) {
			t.Errorf("%s: Contains %v but scrub changed text: %v", c.name, has, got != c.text)
		}
	}
	for k := 0; k < 3; k++ {
		text := enc(base64.StdEncoding, strings.Repeat("Z", k)+secret+"tail!")
		if got := ref.Scrub(text); !strings.Contains(got, "«perry:h.example.com»") || !ref.Contains(text) {
			t.Errorf("alignment %d: not scrubbed or detected: %q", k, got)
		}
	}
	if !ref.Contains("hello", "x "+secret) || ref.Contains() || New(nil, nil).Contains(secret) {
		t.Error("multiple or empty texts")
	}
}

func TestWriterShortSecret(t *testing.T) {
	cases := []struct {
		name   string
		writes []string
		want   string
	}{
		{"split across writes", []string{"a c", "at sat"}, "a «perry:h» sat"},
		{"runs into a word character", []string{"a cat", "egory"}, "a category"},
		{"boundary after a held match", []string{"a cat", " sat"}, "a «perry:h» sat"},
		{"word before the chunk", []string{"s", "cat"}, "scat"},
		{"match at EOF settled by flush", []string{"a cat"}, "a «perry:h»"},
	}
	for _, c := range cases {
		var out bytes.Buffer
		w := refd("h", "cat").Writer(&out)
		for _, p := range c.writes {
			w.Write([]byte(p))
		}
		w.Flush()
		if out.String() != c.want {
			t.Errorf("%s: got %q want %q", c.name, out.String(), c.want)
		}
	}
}

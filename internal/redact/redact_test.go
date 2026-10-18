package redact

import (
	"bytes"
	"encoding/base64"
	"net/url"
	"strings"
	"testing"
)

const secret = "s3cr3t-Tok/en+value"

func item(label string) Item {
	return Item{Host: "h.example.com", Kind: "jira", Secret: secret, Username: "alice", Label: label}
}

func TestScrubLiteralAndEncodings(t *testing.T) {
	r := New([]Item{item("h.example.com")})
	mark := "«perry:h.example.com»"
	cases := map[string]string{
		"literal":     secret,
		"std":         base64.StdEncoding.EncodeToString([]byte(secret)),
		"url":         base64.URLEncoding.EncodeToString([]byte(secret)),
		"rawstd":      base64.RawStdEncoding.EncodeToString([]byte(secret)),
		"rawurl":      base64.RawURLEncoding.EncodeToString([]byte(secret)),
		"query":       url.QueryEscape(secret),
		"path":        url.PathEscape(secret),
		"basic-auth":  base64.StdEncoding.EncodeToString([]byte("alice:" + secret)),
		"echo|base64": base64.StdEncoding.EncodeToString([]byte(secret + "\n")),
	}
	for name, form := range cases {
		got := r.Scrub("x " + form + " y")
		if strings.Contains(got, form) {
			t.Errorf("%s: form not scrubbed: %q", name, got)
		}
		if !strings.Contains(got, mark) {
			t.Errorf("%s: no mark in %q", name, got)
		}
	}
}

func TestScrubEmbeddedBase64AtEveryAlignment(t *testing.T) {
	r := New([]Item{item("h")})
	for k := 0; k < 3; k++ {
		in := strings.Repeat("Z", k) + secret + "tail!"
		enc := base64.StdEncoding.EncodeToString([]byte(in))
		if got := r.Scrub(enc); !strings.Contains(got, "«perry:h»") {
			t.Errorf("alignment %d: not scrubbed: %q", k, got)
		}
	}
}

func TestUnreferencedLabelsAndShortSecrets(t *testing.T) {
	r := New([]Item{
		{Host: "long.example.com", Kind: "jira", Secret: "abcdefgh"},
		{Host: "", Kind: "slack", Secret: "zzzzzzzz"},
		{Host: "short.example.com", Kind: "jira", Secret: "cat"},
	})
	got := r.Scrub("abcdefgh zzzzzzzz cat")
	want := "«perry:long.example.com» «perry:slack» cat"
	if got != want {
		t.Errorf("got %q want %q", got, want)
	}
}

func TestReferencedShortSecretIsScrubbedLiteralOnly(t *testing.T) {
	r := New([]Item{{Host: "h", Kind: "k", Secret: "cat", Label: "h"}})
	if got := r.Scrub("a cat sat"); got != "a «perry:h» sat" {
		t.Errorf("got %q", got)
	}
}

func TestLongestPatternWins(t *testing.T) {
	r := New([]Item{
		{Host: "a", Kind: "k", Secret: "password1", Label: "a"},
		{Host: "b", Kind: "k", Secret: "password12", Label: "b"},
	})
	if got := r.Scrub("password12"); got != "«perry:b»" {
		t.Errorf("got %q", got)
	}
}

func TestWriterHoldsBackSplitSecret(t *testing.T) {
	r := New([]Item{item("h")})
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
	r := New([]Item{item("h")})
	var out bytes.Buffer
	w := r.Writer(&out)
	w.Write([]byte("hello s3cr"))
	w.Flush()
	if out.String() != "hello s3cr" {
		t.Errorf("got %q", out.String())
	}
}

func TestContains(t *testing.T) {
	if !Contains("curl "+secret, secret, "") {
		t.Error("literal not detected")
	}
	if !Contains(base64.StdEncoding.EncodeToString([]byte(secret)), secret, "") {
		t.Error("base64 not detected")
	}
	if Contains("unrelated", secret, "") {
		t.Error("false positive")
	}
	if Contains("category", "cat", "") {
		t.Error("short secret matched inside a word")
	}
	if !Contains("the cat sat", "cat", "") {
		t.Error("short secret whole word not detected")
	}
	if Contains("snake_cat", "cat", "") {
		t.Error("underscore should count as word char")
	}
}

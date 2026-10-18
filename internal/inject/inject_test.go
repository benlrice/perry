package inject

import (
	"bytes"
	"strings"
	"testing"

	"github.com/benlrice/perry/internal/vault"
)

const tok = "tok-Abc123xyz789"

func store() *vault.Data {
	return &vault.Data{Version: 1, Entries: []vault.Entry{
		{Host: "api.example.com", Kind: "api", Username: "alice", Secret: tok},
		{Host: "a.example.com", Kind: "web", Secret: "aaaaaa-secret"},
		{Host: "b.example.com", Kind: "web", Secret: "bbbbbb-secret"},
		{Host: "empty.example.com", Kind: "api", Secret: ""},
	}}
}

func run(t *testing.T, p *Plan) (string, string, int) {
	t.Helper()
	var out, errb bytes.Buffer
	code, err := p.Run(Streams{In: strings.NewReader(""), Out: &out, Err: &errb})
	if err != nil {
		t.Fatal(err)
	}
	return out.String(), errb.String(), code
}

func TestPlaceholdersAreSubstitutedAndOutputScrubbed(t *testing.T) {
	p, err := Prepare(store(), Request{ExpandArgv: true,
		Argv: []string{"sh", "-c", `echo "$0:$1"; echo oops >&2; exit 4`, "{{perry:api.example.com}}", "{{perry:api.example.com:username}}"}})
	if err != nil {
		t.Fatal(err)
	}
	out, e, code := run(t, p)
	if out != "«perry:api.example.com»:alice\n" || e != "oops\n" || code != 4 {
		t.Errorf("out=%q err=%q code=%d", out, e, code)
	}
}

func TestExpandArgvOffLeavesPlaceholdersAlone(t *testing.T) {
	p, err := Prepare(store(), Request{Argv: []string{"echo", "{{perry:nothing}}"}})
	if err != nil || p.Argv[1] != "{{perry:nothing}}" {
		t.Fatalf("%v %v", p, err)
	}
}

func TestEnvSpecsAndPerryVariablesStripped(t *testing.T) {
	t.Setenv("PERRY_IDENTITY", "/should/not/leak")
	p, err := Prepare(store(), Request{Argv: []string{"sh", "-c", `echo "[$T] [$PERRY_IDENTITY]"`},
		Env: []EnvSpec{{"T", "api.example.com"}}})
	if err != nil {
		t.Fatal(err)
	}
	if out, _, _ := run(t, p); out != "[«perry:api.example.com»] []\n" {
		t.Errorf("got %q", out)
	}
}

func TestErrorsAreDedupedJoinedAndScrubbed(t *testing.T) {
	_, err := Prepare(store(), Request{ExpandArgv: true,
		Argv: []string{"x", "{{perry:web}}", "{{perry:web}}", "{{perry:empty.example.com}}", "{{perry:api.example.com:bogus}}"}})
	if err == nil {
		t.Fatal("want error")
	}
	m := err.Error()
	if strings.Count(m, "ambiguous ref") != 1 {
		t.Errorf("not deduped: %q", m)
	}
	for _, want := range []string{"candidates: a.example.com, b.example.com", "entry empty.example.com has an empty secret", `unknown field "bogus"`, "; "} {
		if !strings.Contains(m, want) {
			t.Errorf("missing %q in %q", want, m)
		}
	}
}

func TestErrorTextNeverCarriesASecret(t *testing.T) {
	d := store()
	d.Entries = append(d.Entries, vault.Entry{Host: tok + ".example.com", Kind: "api", Secret: tok})
	_, err := Prepare(d, Request{ExpandArgv: true, Argv: []string{"x", "{{perry:" + tok + ".example.com:bogus}}"}})
	if err == nil || strings.Contains(err.Error(), tok) {
		t.Errorf("leak: %v", err)
	}
}

func TestSplitWritesAreScrubbed(t *testing.T) {
	p, err := Prepare(store(), Request{ExpandArgv: true,
		Argv: []string{"sh", "-c", `printf %s "${0%%?????}"; sleep 0.1; printf %s "${0#"${0%%?????}"}"; echo`, "{{perry:api.example.com}}"}})
	if err != nil {
		t.Fatal(err)
	}
	if out, _, _ := run(t, p); out != "«perry:api.example.com»\n" {
		t.Errorf("got %q", out)
	}
}

func TestSignalExitIs128Plus(t *testing.T) {
	p, _ := Prepare(store(), Request{Argv: []string{"sh", "-c", "kill -TERM $$"}})
	if _, _, code := run(t, p); code != 128+15 {
		t.Errorf("code %d", code)
	}
}

func TestCurlHintOnlyWhenExpanding(t *testing.T) {
	argv := []string{"curl", "-u", "{{perry:api.example.com}}", "http://x"}
	p, err := Prepare(store(), Request{ExpandArgv: true, Argv: argv})
	if err != nil || !strings.Contains(p.Hint, "curl -u needs user:token") || strings.Contains(p.Hint, tok) {
		t.Errorf("hint %q err %v", p.Hint, err)
	}
	if p, _ = Prepare(store(), Request{Argv: argv}); p.Hint != "" {
		t.Errorf("unexpected hint %q", p.Hint)
	}
}

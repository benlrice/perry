package hook

import (
	"bytes"
	"strings"
	"testing"
)

func serve(in string, decide func(Payload) string) string {
	var out bytes.Buffer
	if err := Serve(strings.NewReader(in), &out, decide); err != nil {
		panic(err)
	}
	return out.String()
}

func TestAllowWritesNothing(t *testing.T) {
	var got Payload
	out := serve(`{"cwd":"/w","tool_name":"Bash","tool_input":{"command":"ls"}}`, func(p Payload) string { got = p; return "" })
	if out != "" || got.CWD != "/w" || got.ToolName != "Bash" || string(got.ToolInput) != `{"command":"ls"}` {
		t.Errorf("out=%q payload=%+v", out, got)
	}
}

func TestDenyIsOneUnescapedJSONLine(t *testing.T) {
	out := serve(`{"tool_name":"Read","tool_input":{}}`, func(Payload) string { return `blocked access to x (matched "<a&b>").` })
	if strings.Count(out, "\n") != 1 || !strings.HasSuffix(out, "\n") {
		t.Errorf("not one line: %q", out)
	}
	for _, want := range []string{`"hookEventName":"PreToolUse"`, `"permissionDecision":"deny"`, `(matched \"<a&b>\")`,
		"perry: blocked access", "Use `perry run -- <cmd> {{perry:<host>}}` to inject secrets instead."} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in %q", want, out)
		}
	}
	if !IsDeny([]byte(out)) {
		t.Error("IsDeny false for own reply")
	}
}

func TestUnreadableInputIsDeniedWithoutAskingDecide(t *testing.T) {
	for _, in := range []string{"", "not json", `{"tool_name":"Bash"}`} {
		called := false
		out := serve(in, func(Payload) string { called = true; return "" })
		if called || !IsDeny([]byte(out)) || !strings.Contains(out, "blocked: unreadable hook input.") {
			t.Errorf("%q: called=%v out=%q", in, called, out)
		}
	}
}

func TestIsDeny(t *testing.T) {
	cases := map[string]bool{
		`{"hookSpecificOutput":{"permissionDecision":"deny"}}`:                 true,
		"{ \"hookSpecificOutput\" : { \"permissionDecision\" : \"deny\" } }\n": true,
		`{"hookSpecificOutput":{"permissionDecision":"allow"}}`:                false,
		`{"permissionDecision":"deny"}`:                                        false,
		``:                                                                     false,
		`garbage "permissionDecision":"deny"`:                                  false,
	}
	for in, want := range cases {
		if got := IsDeny([]byte(in)); got != want {
			t.Errorf("%q: got %v", in, got)
		}
	}
}

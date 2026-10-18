// Package hook speaks the Claude Code PreToolUse hook wire format.
package hook

import (
	"encoding/json"
	"io"
)

// Payload is the part of the hook input that perry reads.
type Payload struct {
	CWD       string          `json:"cwd"`
	ToolName  string          `json:"tool_name"`
	ToolInput json.RawMessage `json:"tool_input"`
}

type reply struct {
	EventName string `json:"hookEventName"`
	Decision  string `json:"permissionDecision"`
	Reason    string `json:"permissionDecisionReason"`
}

// Serve reads one payload from r and asks decide for a deny reason. An empty
// reason allows the tool call and writes nothing. Input that cannot be read is
// denied. A deny goes to w as one JSON line.
func Serve(r io.Reader, w io.Writer, decide func(Payload) string) error {
	var p Payload
	raw, err := io.ReadAll(r)
	reason := "blocked: unreadable hook input."
	if err == nil && json.Unmarshal(raw, &p) == nil && len(p.ToolInput) > 0 {
		reason = decide(p)
	}
	if reason == "" {
		return nil
	}
	return writeDeny(w, reason)
}

func writeDeny(w io.Writer, reason string) error {
	msg := "perry: " + reason + " Use `perry run -- <cmd> {{perry:<host>}}` to inject secrets instead."
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	return enc.Encode(map[string]reply{"hookSpecificOutput": {"PreToolUse", "deny", msg}})
}

// IsDeny reports whether output is a hook reply that denies the tool call.
func IsDeny(output []byte) bool {
	var v struct {
		Out struct {
			Decision string `json:"permissionDecision"`
		} `json:"hookSpecificOutput"`
	}
	return json.Unmarshal(output, &v) == nil && v.Out.Decision == "deny"
}

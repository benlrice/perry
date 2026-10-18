// Package docs embeds the Claude Code integration doc. The installer parses it at run time.
package docs

import _ "embed"

//go:embed claude-code.md
var ClaudeCode string

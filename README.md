# perry

Keep secrets out of your Claude Code transcripts. Perry is an age-encrypted
credential store for one Linux user. A command uses a secret through a
placeholder, and perry scrubs the output. A PreToolUse hook blocks tool calls
that touch credential files or contain a stored secret.

## Use

    perry add --host jira.example.com --kind jira
    perry run -- curl -u '{{perry:jira.example.com:username}}:{{perry:jira.example.com}}' URL

## Build

    make ci

## More

- `docs/claude-code.md`: Claude Code setup. `perry install claude` reads this file.
- `perry help`: command reference.

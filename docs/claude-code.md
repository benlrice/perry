# Claude Code integration

## 0. Automatic install

Run this command in your own terminal. The hook denies it for Claude.

```
perry install claude --dry-run    # show what would change
perry install claude              # apply
```

The command does section 1, section 2 and the deny rules of section 3a. It
reads these parts from this file. This file is the source of what the command
installs.

### What the command changes

The command changes only the entries that belong to perry:

- the `PreToolUse` hook entry, with the absolute path of the perry binary
- the deny rules that are missing
- a CLAUDE.md block between the markers `perry:begin` and `perry:end`

The command does not change any other setting, any other hook or any other
text.

### Safety

- The command writes `<file>.bak` before it changes a file.
- The command keeps symlinks and file modes.
- The command writes no file if a file is not valid JSON, has an unexpected
  shape, or has unbalanced markers.
- The command ends with the check from section 2.

### Run it again

Run the command again to check the state. The command shows each part as
`added`, `updated` or `up to date`.

- The command updates a stale hook entry in place. A hook entry is stale when
  it has an old binary path, the paths-only mode or an old matcher.
- The command updates a stale marked CLAUDE.md block in place.
- The command does not change a hook entry that has extra fields or other
  hooks. It tells you to change the entry by hand.
- The command does not change a hand-written "Credentials (perry)" section if
  the text is different from the snippet. It tells you to change the section
  by hand. If the text is the same as the snippet, the command adds the
  markers.

### Options

- `--dry-run` shows the changes. It writes no file.
- `--paths-only` installs the lightweight hook of section 3b.
- `--uninstall` removes the hook entry and the CLAUDE.md block. It keeps the
  deny rules. Perry cannot know which rules you added yourself.

The sections below give the same steps for manual setup.

## 1. CLAUDE.md snippet

Add this text to `~/.claude/CLAUDE.md`:

```markdown
## Credentials (perry)

Credentials live in the `perry` store; reach them only through perry. Hard
guardrail: never read, print, grep, or ask for credential files
(`~/.tokens*`, `~/.config/perry/*`, `~/.ssh/*`) or secret values.

- Find an entry (metadata only): `perry search <keyword>` / `perry list`.
- Fix metadata: `perry edit <ref> --set-host NEW ...`.
- Use a secret: `perry run -- <cmd> ... {{perry:<host-or-kind>[:field]}}`
  or `perry exec --env VAR=<ref> -- <cmd>`. Output is redacted.
- Ambiguous ref: narrow with the host name or `--kind`.
- User-terminal commands (`perry get --reveal`, `perry unlock`, `perry rekey`,
  `keyctl`): hand the user the command to run.
- Hook block: switch to `perry run`.
- "locked" error: ask the user to run `perry unlock` in their own terminal,
  then retry.
```

## 2. PreToolUse hook

Add this text to `~/.claude/settings.json`. Merge it with an existing `hooks`
key if one exists.

```json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Read|Bash|Grep|Glob|Edit|Write|MultiEdit|NotebookEdit|WebFetch|mcp__.*",
        "hooks": [
          { "type": "command", "command": "perry hook" }
        ]
      }
    ]
  }
}
```

### Requirements

- `perry` must be on PATH in the environment where Claude Code runs. If it is
  not, use an absolute path, for example
  `"command": "/home/you/go/bin/perry hook"`.

### What the hook denies

- The hook denies tool calls that touch the token file, the perry store, the
  perry config directory, SSH private keys or `~/.ssh`.
- The hook denies tool input that contains a stored secret. It also checks the
  base64 and URL-encoded forms.
- The block messages do not contain secret values. They tell the agent to use
  `perry run`.
- The hook denies Bash commands that run `perry get` or use `--reveal`. Without
  this rule, an agent can wrap the command in a pty, for example with `script`.
  Reveal secrets only from your own terminal.
- The hook denies Bash commands that run `perry unlock`, `perry rekey` or
  `keyctl`. You unlock from your own terminal. `keyctl` can print the cached
  identity.
- The hook denies Bash commands that run `perry install`. That command edits
  the settings that hold these guard rails.
- The hook allows `perry lock`, `perry status`, `perry unlock --help` and
  `perry install --help`.

### Coverage

`perry hook` scans the `tool_input` of each tool that calls it. The matcher
sets the coverage.

Warning: The matcher `Read|Bash|Grep|Glob` does not cover Edit, Write, MultiEdit,
NotebookEdit, WebFetch and MCP tools. These tools can carry or send a secret
out. Use the wider matcher shown above.

### Short secrets

A secret shorter than 6 characters has no encoded forms. It matches only as a
whole word in `hook` and `scan`, and perry removes it from output only as a
whole word. This holds whether or not the command references it. `perry add`
shows a warning for short secrets.

### Locked store

The store is locked when the identity has a passphrase and the cache is absent
or expired. In this state:

- The hook does only the path and regex checks. This is the same as
  `--paths-only`.
- The hook prints a note on stderr.
- The hook skips the stored-secret scan. Perry cannot give out secrets while it
  is locked.

### Other failures

- The hook never asks for a passphrase. It never opens `/dev/tty`.
- If the store is unreadable for a reason other than locked (missing key or
  decrypt error), the hook denies all Bash calls. It allows other tools. The
  path checks still apply.
- The hook denies input that it cannot parse.

### Verify the installation

Run this command:

```
echo '{"tool_name":"Read","tool_input":{"file_path":"/home/you/.ssh/id_ed25519"}}' | perry hook
```

The output must contain `permissionDecision":"deny"`.

## 3. Lightweight alternative: permission deny rules and `--paths-only` hook

Use this option to protect credential files when perry must not decrypt
anything in the hook. This option has these limits:

- It does not open the store.
- It does not scan for secret values.
- It does not fail closed on store errors.
- It does only path and regex checks.

### 3a. Deny rules

Add this text to `~/.claude/settings.json`. Merge it with an existing
`permissions` key if one exists.

```json
{
  "permissions": {
    "deny": [
      "Read(~/.ssh/**)",
      "Read(~/.tokens*)",
      "Read(~/.config/perry/**)",
      "Read(~/.aws/**)",
      "Read(~/.netrc)",
      "Read(~/.config/gh/hosts.yml)",
      "Read(~/.kube/config)"
    ]
  }
}
```

Path forms in a rule (source: https://code.claude.com/docs/en/permissions):

- `//path` is an absolute path.
- `~/path` is relative to the home directory.
- `/path` is relative to the settings source.
- `./path` or `path` is relative to the current directory.
- A pattern uses gitignore syntax, for example `Read(**/.env)`.

Coverage of a deny rule:

- It blocks the Read tool. It also blocks Edit and Write on the same path.
- It checks Grep and Glob on a best-effort basis. The coverage is partial.
- It checks Bash redirections and recognized file commands (`cat`, `head`,
  `tail`, `sed`, `tee`) that name the file.
- It does not check other Bash commands, for example `grep -r pattern .`, or
  scripts that open the file. Use the hook in 3b or the sandbox in 3c.

### 3b. PreToolUse hook on Bash

```json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Bash",
        "hooks": [
          { "type": "command", "command": "perry hook --paths-only" }
        ]
      }
    ]
  }
}
```

`perry hook --paths-only` uses the same stdin and stdout contract and the same
deny output as `perry hook`. It never opens or decrypts the store. It never
opens `/dev/tty`.

Both modes deny access to these items:

- `.tokens`
- the perry config directory
- SSH private keys, and each `~/.ssh/<file>` except `config`,
  `known_hosts[.old]` and `*.pub`
- `.aws` (the whole directory)
- `.netrc`
- `.config/gh/hosts.yml`
- `.kube/config`

The `~/.ssh` directory itself and globs of it are also denied.

The hook recognizes these path forms: `~`, `$HOME`, `${HOME}` and the absolute
home path. It also recognizes relative files after `cd <dir> &&`, and relative
files when the `cwd` of the hook is under the home directory.

### 3c. Sandbox (OS-level enforcement)

The sandbox is the only option here that blocks every process that Bash
starts. Add this text to `~/.claude/settings.json`:

```json
{
  "sandbox": {
    "enabled": true,
    "filesystem": {
      "denyRead": ["~/.ssh", "~/.aws", "~/.netrc", "~/.config/perry"]
    }
  }
}
```

- The paths use the same prefixes as the deny rules.
- The sandbox applies to Bash commands and their child processes. It does not
  apply to the Claude file tools. Keep the deny rules from 3a for those tools.
- It does not apply to MCP servers or hooks.
- It runs on macOS (Seatbelt) and on Linux and WSL2 (bubblewrap). It does not
  run on native Windows.
- Source: https://code.claude.com/docs/en/sandboxing. A sandbox blocks `perry`
  too when `denyRead` includes `~/.config/perry`. Test your setup before you
  rely on it.

### Limits of the hook

The hook uses regular expressions. It is not a shell parser. It does not find
these forms:

- indirection, for example `cd "$(echo ~)"`
- variables
- symlinks
- `eval`
- `gh auth token`
- `aws configure export-credentials`
- a relative `cd` outside home, then `..`

The hook denies a bare `.netrc`, `.aws` or `.tokens` token anywhere in a
command. This includes an unrelated project directory. The hook is a guard
rail. It is not a sandbox.

# perry

**Keep secrets out of your Claude Code transcripts.**

[![Go](https://img.shields.io/badge/go-1.26-00ADD8?logo=go&logoColor=white)](go.mod)
![Platform: Linux](https://img.shields.io/badge/platform-linux-lightgrey)

[Overview](#overview) • [Install](#install) • [Quick start](#quick-start) • [How it works](#how-it-works) • [Short secrets](#short-secrets) • [Commands](#commands) • [Development](#development)

## Overview

An agent that runs commands for you sees what those commands print, and what
it sees ends up in the transcript. Perry lets the agent use a credential
without seeing it.

- **Encrypted store.** Credentials live in one [age](https://age-encryption.org)
  file for one Linux user.
- **Placeholders.** A command names a secret as `{{perry:REF}}`. Perry puts the
  value in just before the command starts.
- **Scrubbed output.** Perry replaces every stored secret in the command output
  with a `«perry:LABEL»` mark, including its base64 and URL-escaped forms.
- **Guard hook.** A Claude Code `PreToolUse` hook denies tool calls that touch
  credential files, reveal secrets, or contain a stored secret.

## Install

Perry needs Go 1.26 and Linux. It caches the unlocked identity in the kernel
keyring.

```sh
go install github.com/benlrice/perry/cmd/perry@latest
```

Then, in your own terminal, set up Claude Code:

```sh
perry install claude --dry-run   # show what would change
perry install claude             # apply
```

This adds the hook, the deny rules and a CLAUDE.md block. See
[docs/claude-code.md](docs/claude-code.md) for what it changes and for manual
setup.

> [!IMPORTANT]
> Run `perry install`, `perry unlock`, `perry rekey` and `perry get --reveal`
> in your own terminal. The hook denies them for the agent.

## Quick start

Pick an identity. Perry uses `~/.ssh/id_ed25519` by default. For a
passphrase-protected age identity instead:

```sh
perry keygen          # writes identity.age in ~/.config/perry
perry unlock --ttl 8h # cache the unlocked identity
```

Store a credential. The secret comes from a hidden prompt or from stdin, never
from the command line:

```sh
perry add --host jira.example.com --kind jira --user alice --auth basic
```

Use it, from your terminal or from the agent:

```sh
perry run -- curl -u '{{perry:jira.example.com:username}}:{{perry:jira.example.com}}' \
  https://jira.example.com/rest/api/2/myself

perry exec --env GH_TOKEN=github -- gh api user
```

Find entries without revealing anything:

```sh
perry list
perry search jira
perry show jira.example.com
```

## How it works

| Term | Meaning |
| --- | --- |
| **Entry** | One stored credential, keyed by host and kind. |
| **Ref** | `<host-or-kind>[:field]`. Fields are `secret` (the default), `username`, `host`, `kind` and `notes`. |
| **Placeholder** | A ref written as `{{perry:REF}}` in a `perry run` command. |
| **Plan** | The command with all refs resolved: argv, child environment and a Scrubber. |
| **Form** | One way a secret can appear in text: its literal value and, for longer secrets, its encodings. |
| **Scrubber** | Replaces every Form of every stored secret in child output with `«perry:LABEL»`. |
| **Leak check** | Tests whether text holds any Form of a stored secret. It matches exactly what the Scrubber would replace. |
| **Deny reply** | The JSON line the hook writes to stop a tool call. It never contains a secret. |

The full definitions are in [GLOSSARY.md](GLOSSARY.md).

### Scrubbing

`perry run` and `perry exec` scrub the child's stdout and stderr as they
stream. The mark for a referenced entry shows the ref you wrote. The mark for
any other entry shows its host, or its kind when the host is empty. Perry also
removes `PERRY_*` variables from the child environment.

A secret of 6 or more bytes has these Forms, and each matches anywhere in the
text:

- the literal value
- base64 in the standard, URL-safe and unpadded variants, also inside a longer
  base64 stream at any byte alignment
- base64 of `username:secret`, as in an HTTP Basic header
- the URL query and path escapes

### The hook

`perry hook` reads the Claude Code hook JSON on stdin and denies the tool call
when:

- the call touches a protected path: the perry config dir, `~/.ssh`, `.tokens`,
  `.aws`, `.netrc`, `gh` hosts or `.kube/config`
- a Bash command runs `perry get`, `--reveal`, `perry unlock`, `perry rekey`,
  `perry install` or `keyctl`
- the Leak check finds a stored secret in the tool input

When the store is locked, the hook does only the path checks. When the store
is unreadable for another reason, it denies all Bash calls. `perry hook
--paths-only` never opens the store.

> [!WARNING]
> The hook uses regular expressions, not a shell parser. It is a guard rail,
> not a sandbox. Variables, `eval`, symlinks and similar indirection get past
> it. [docs/claude-code.md](docs/claude-code.md#3c-sandbox-os-level-enforcement)
> shows how to add OS-level enforcement.

## Short secrets

A secret shorter than 6 bytes has only its literal Form, and that Form matches
only as a whole word. A word character is a letter, a digit or an underscore.
The Scrubber and the Leak check use the same rule, whether or not the command
references the entry.

For a stored secret `cat`:

| Text | Scrubbed and detected? |
| --- | --- |
| `cat` | yes |
| `the cat sat` | yes |
| `category`, `snake_cat` | no |
| base64 of `cat` | no |

`perry add` warns when you store one:

```
perry: add: warning: secret is shorter than 6 characters; perry finds it only as a whole word and not in encoded forms
```

> [!CAUTION]
> A short secret that is a common word, such as `test`, is scrubbed from every
> command's output, and the hook denies every tool call that contains it.

## Commands

| Command | Purpose |
| --- | --- |
| `add`, `edit`, `rm` | Store, change or remove an entry. `edit` never touches the secret. |
| `list`, `search`, `show` | Read entry metadata, never secrets. |
| `run`, `exec` | Run a command with secrets in placeholders or environment variables. Output is scrubbed. |
| `get --reveal` | Print one field. Terminal only. |
| `import FILE` | Import `export KEY=value`, `label: secret` or `label (url): secret` lines. Terminal only. |
| `scan` | Check stdin for a stored secret. Exits 1 when it finds one. |
| `keygen`, `unlock`, `lock`, `status`, `rekey` | Manage the identity and its unlock cache. |
| `hook`, `install claude` | Claude Code integration. |

Run `perry help COMMAND` for options and examples.

### Files

| Path | Holds |
| --- | --- |
| `~/.config/perry/store.age` | The encrypted store. `$XDG_CONFIG_HOME` is honoured. |
| `~/.config/perry/recipients` | The age recipients the store is encrypted to. Without it, perry uses `~/.ssh/id_ed25519.pub`. |
| `~/.config/perry/identity.age` | The passphrase-wrapped identity from `perry keygen`. |

`PERRY_IDENTITY` overrides the identity file and `PERRY_RECIPIENTS` the
recipients file.

## Development

```sh
make ci   # gofmt, go vet, go mod tidy check, build, tests
```

The binary is written to `bin/perry`. Issues and specs are tracked in
[GitHub Issues](https://github.com/benlrice/perry/issues).

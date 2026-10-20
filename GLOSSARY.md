# Glossary

**Entry**: one stored credential, keyed by host and kind.

**Ref**: text that names an entry and a field, as `<host-or-kind>[:field]`.

**Placeholder**: a ref written as `{{perry:REF}}` in a command. Perry replaces it with the field value before it starts the command.

**Plan**: a command with all refs resolved. It holds the argv, the child environment, and a scrubber. It does not need the store to run.

**Form**: one way a stored secret can appear in text that perry treats as the secret itself. A secret has its literal value as a form, plus its base64 and URL-escaped encodings and the base64 of `username:secret`. A short secret (under six characters) has only its literal form, and that form matches only as a whole word.

**Scrubber**: the redactor that replaces every form of every stored secret in the child output with a `«perry:LABEL»` mark.

**Leak check**: a test of whether text holds any form of a stored secret. It matches exactly what the scrubber would replace. It gives one verdict: clean, leaked, locked, or unverifiable. It never says which entry matched.

**Deny reply**: the one JSON line that the hook writes to stop a tool call. It has a reason, and the same closing sentence on every deny. Unreadable hook input also gets a deny reply.

**Protected path**: a path that holds or points to secret material, such as the config dir or the file named by `PERRY_IDENTITY`. The vault lists them, and the guard denies tool calls that touch them.

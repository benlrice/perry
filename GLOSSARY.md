# Glossary

**Entry**: one stored credential, keyed by host and kind.

**Ref**: text that names an entry and a field, as `<host-or-kind>[:field]`.

**Placeholder**: a ref written as `{{perry:REF}}` in a command. Perry replaces it with the field value before it starts the command.

**Plan**: a command with all refs resolved. It holds the argv, the child environment, and a scrubber. It does not need the store to run.

**Scrubber**: the redactor that replaces every form of a stored secret in the child output with a `«perry:LABEL»` mark.

**Leak check**: a test of whether text holds any stored secret, in any form perry redacts. It gives one verdict: clean, leaked, locked, or unverifiable. It never says which entry matched.

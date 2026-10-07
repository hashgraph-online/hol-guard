# Native gws Gmail command input

`guard_command::business_gws_command::GwsGmailSendCommandInputV1` prepares a
narrow POSIX inline command using the existing native command parser and
`GmailSendWireInputV1`. It owns the original command and immutable decoded wire
input. Preparation does not authenticate an executable, account or endpoint,
validate MIME semantics, evaluate policy, create a grant or send a message.

The supported spelling is `gws gmail users messages send` with exactly one
inline `--params` and one inline `--json`. Options can be reordered and use
separate values or `--name=value`. This follows the actual gws v0.22.5 command
builder at source `705fb0ecac6f4249679958f6325b809b63fdde17`; the underlying
Gmail schema pin and wire-field bounds are documented in
[Gmail wire input](gmail-wire-input.md).

All other options and routes are unsupported, including output/upload,
pagination, dry-run, format, sanitization, aliases, explicit API versions and
absolute/relative executable paths. This profile does not override or disable
Model Armor: sanitization options need a separately qualified execution path.
Environment assignments, wrappers, redirects, pipelines, compound commands,
active shell expansion and uncertain native parsing are rejected. Single-quoted
JSON retains literal characters. Double-quoted JSON preserves ordinary JSON
escapes such as `\u0061` and `\n`; unsupported escaped shell expansion and line
continuation are rejected. Unquoted backslashes remain unsupported on Windows,
where the general native parser preserves path separators. Neither paths nor
stdin are read, and no target process is executed.

The generic matcher parser does not evaluate shell variables. A literal-input
preflight therefore rejects active expansion before treating its tokens as
provider bytes. These refusals are preparation errors, not a new enforcing
policy engine. Native producers must retain the existing strongest policy
floor and stop unsupported writes instead of interpreting an error as no match.

The command is bounded to the existing 32 KiB native input limit before parsing.
Its preparation binding hashes `hol-guard.gws-gmail-command-input.v1\0`, an
unsigned 64-bit big-endian command length, the exact UTF-8 command bytes, and
the ASCII wire-input binding. Source formatting changes this identity even
when recovered JSON bytes are unchanged. This is not a review capability.

A trusted producer must pin the resolved binary/schema/endpoint, resolve the
effective provider principal and tenant, extract complete MIME/audience facts,
inspect private content and bind the current native review context. A managed
executor must consume frozen provider bytes. Executing the original shell text
after approval does not establish credential isolation or exact dispatch.
These values have no Debug, Serialize, Clone or mutable interface and must
remain local; Cloud receives only the separately reviewed minimal metadata.

Nine native tests cover quoting/order/assignment spellings, preserved JSON
escapes with continuing resource validation, strict wire-field
delegation, duplicate/missing options, overrides and extra flags, compound and
wrapper contexts, variable/glob expansion, bounded errors, size limits and
source substitutions. They make zero provider calls and do not qualify an
installed runtime, harness, managed connector or live business operation.

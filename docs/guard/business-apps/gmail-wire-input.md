# Native Gmail send wire input

`guard_command::business_gmail_wire::GmailSendWireInputV1` owns the original
parameter/body JSON and decodes the private MIME bytes for subsequent native
semantic extraction. It follows the exported gws v0.22.5
`gmail.users.messages.send` route: POST `gmail/v1/users/{userId}/messages/send`.
The recorded route/schema export SHA-256 is
`4c3fb4da34519808a4fff1428b742edb66b220543aa7eabccadd3708cbdd581d`.
The exact export is committed at
`contracts/business-policy/providers/gws-v0.22.5-gmail-send.schema.json`.
Tests hash those bytes, verify the route/parameter/raw/thread field shapes and
confirm other exported Message fields remain rejected. The export came from
`gws schema gmail.users.messages.send` with no provider credential, using
source `705fb0ecac6f4249679958f6325b809b63fdde17`. Discovery can change independently
of the CLI version; re-exporting does not silently replace this pinned artifact.
The version/digest constants identify the intended interpretation; they do not
verify the caller's executable, endpoint, schema or credential principal.

The current decoder requires an explicit `userId: "me"` parameter, required
base64url `raw` content and an optional nonempty, bounded `threadId`. These are
private source claims. `me` does not authenticate an account or tenant, and a
thread string does not prove resource ownership or revision. Other principal
selectors need explicit authenticated resolution before they are supported.
Remaining Message or query fields are rejected until their semantics are
covered; unknown, duplicate, missing and null fields are never silently dropped.
MIME validity, sender/recipient expansion, reply semantics, attachments, labels
and content inspection remain required before complete business facts exist.

Parameters are bounded to 4 KiB and combined parameter/body wire bytes to
256 KiB before JSON parsing or base64 allocation. Decoded MIME is independently
bounded to 256 KiB. Canonical padded and unpadded URL-safe encodings are accepted;
malformed padding, nonzero trailing bits, mixed alphabets and whitespace inside
the encoding are rejected. The exact source bytes remain owned and immutable.
There is no Debug, Serialize, Clone or mutable interface for this private value.
Errors contain bounded categories rather than raw request details.

The preparation binding hashes `hol-guard.gmail-send-wire-input.v1\0`, the ASCII
schema-export digest, then each parameter/body buffer framed by an unsigned
64-bit big-endian length. Body, thread and parameter substitutions change the
binding. JSON whitespace changes also change it, because this commits exact
wire bytes rather than a canonical policy representation. A managed executor
must consume the frozen bytes and bind its authenticated account, endpoint,
policy, actor and approval context separately.

This decoder cannot authorize, create a review grant, dispatch a provider
request or attest a protected route. It does not read files/stdin, execute a
target process or make network requests. Integrate it into the existing native
parser/private-review/controlled-executor path after those authority checks;
do not turn parse success into an allow or send the private bytes to Cloud.

Validation uses fixed Python-produced base64url and framed SHA-256 vectors,
malformed and duplicate/escaped JSON fields, private binary byte preservation,
positive/negative size boundaries, resource bounds and substitution tests.
These are native synthetic input checks, not provider, host or runtime proof.

The decoder pins base64 0.22.1 in both production and the build-only crate that
compiles the same source. The root Cargo lockfile records the one added package.
See the [pinned decoder source](https://github.com/marshallpierce/rust-base64/tree/v0.22.1)
and [Gmail send reference](https://developers.google.com/workspace/gmail/api/reference/rest/v1/users.messages/send).

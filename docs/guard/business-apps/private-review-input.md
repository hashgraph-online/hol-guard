# Private business review input

The existing native workspace review request can bind an optional private business
input. This protocol preserves frozen bytes for a future managed dispatcher; it
does not authenticate a provider account or authorize provider execution.

The request's `action.action_envelope.business_context` carries the strict schema
`guard.private-business-review.v1`, version 1, a `prepared_input_binding` and a
`snapshot_digest`. Both digests are lowercase SHA-256. The native origin receipt's
optional `business_review_binding` authenticates these digests together with the
request ID, policy generation, policy digest, rule digest and runtime identity.
The existing origin MAC covers the receipt. Business binding also changes the
decision ID. Ordinary pre-tool and post-tool producers omit this field.

The canonical private JSON file lives in the existing private state root at
`workspace-review-business-inputs/<snapshot_digest>.json`. Its strict
`guard.private-business-input.v1` schema, version 1, contains typed `facts`,
`primary_base64` and ordered `attachments_base64`. Encoding uses canonical padded
standard base64. Combined decoded bytes cannot exceed 256 KiB; the file cannot
exceed 512 KiB. Existing private file helpers enforce ownership, permissions and
symlink protections. The raw file must equal canonical JSON and match its digest.

Loading verifies the current authenticated business policy and the receipt's
policy/runtime identity, then prepares owned primary and attachment buffers using
the existing business input validator. Account, tenant, tool/schema, audience,
content, target revision, field diff, batch and counts are part of that prepared
binding. The current business evaluator cannot turn an intrinsic block or sandbox
requirement into a human exception. Mutation of the file after loading does not
change retained buffers; a later load rejects changed bytes.

Missing, null, stripped, mismatched, copied or stale business context fails closed.
An admitted business policy requires an authenticated native origin for every
review request, including generic requests. Its request ID and policy/runtime
identity must match the current store. Removing the whole envelope or both
business provenance fields therefore cannot reopen an unsigned legacy request.
When both business fields are absent, authenticated generic reviews remain
available. The business policy is opt-in; stores without it retain the existing
legacy request provenance behavior.
The input has no diagnostic or serialization implementation; generic request
diagnostics report only whether private material is present. Bodies and attachments
do not enter the public review context or receipt.

The existing decision RPC refuses these business requests with
`native_workspace_review_business_dispatch_unavailable` before consuming a claim.
It cannot safely return a grant to a mutable command retry. No producer currently
emits business-bound receipts, and no managed dispatcher, isolated credential
owner, provider identity verification or real-agent qualification is included.
Tests create synthetic signed local inputs; their opaque identity values are not
proof of Google identity or tenant membership. Clients that reject new receipt
fields need a coordinated update before a future producer enables this protocol.

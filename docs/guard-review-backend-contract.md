# Guard Review Backend Contract

Date: 2026-08-24
Scope: local Guard daemon and command runtime

## Local ownership

Guard Local remains the live interrupt owner.

Local owns:

- pending approval queue creation
- exact live request resolution
- signed/verified remote approval acceptance

Cloud must not bypass the local queue by posting loose metadata.

## Cloud Review transport

Cloud Review accepts one signed decision through the versioned exact command
route: `/api/guard/review/v2/commands`.

The sole review command operation is `guard.review.resolveExact`. Its payload
must include:

- signed `remoteApproval`
- optional expected `harness`

Local validates:

- request id
- approval id
- workspace id
- machine installation id
- machine id
- device id
- harness id
- action envelope hash
- source claim hash
- policy version
- expiry
- signature and trusted verification key
- replay receipt

If any check fails, Local rejects the decision and writes no policy or memory.

Persistent policy memory uses the separate `guard.review.syncPolicyMemory`
operation. It requires its own command capability and local confirmation before
Local applies a signed `decisionMemoryBundle`.

Reusable command memory additionally requires `guard.exact-command.v1` with
SHA-256 of the entire original UTF-8 command, including whitespace. Missing or
malformed selectors never fall back to artifact-wide matching. Persisted
memory retains the signed original bundle and reconstructs its immutable
projection before native publication.

`cloud-workspace:<id>` is an enrolled OAuth workspace binding, not a filesystem
path. Exact command/harness rules are admitted only for that current binding;
changing or disconnecting it fences the old generation and clears its rules.
Remembered allows cannot lower native critical/review floors, create approval,
or provide physical UP+UV. Storage/application acknowledgements alone do not
prove a native hook consequence or fleet qualification.

## Local persistence behavior

- resolves exactly one pending queue item
- records claimed remote receipt
- does not upsert reusable policy or decision memory

Policy-memory synchronization is not a request resolution. It applies only
after its separate authorization and local confirmation complete.

## Runtime and daemon touchpoints

- `src/codex_plugin_scanner/guard/review_contracts.py`
- `src/codex_plugin_scanner/guard/runtime/exact_cloud_review.py`
- `src/codex_plugin_scanner/guard/runtime/exact_cloud_review_executor.py`
- `src/codex_plugin_scanner/guard/runtime/exact_cloud_review_transport.py`
- `src/codex_plugin_scanner/guard/runtime/review_policy_memory_executor.py`

## Proof suites

- `tests/test_guard_exact_cloud_review.py`
- `tests/test_guard_exact_cloud_review_transport.py`
- `tests/test_guard_cloud_review_contract.py`

## Explicit reusable-source disclosure

A native origin query may return `command_sha256`, computed from the protected
immutable original hook journal under current enrolled authority and consent.
It returns no raw command bytes and never modifies an existing signed claim or
challenge. Old origins without that optional commitment remain usable for their
existing exact review purpose, but are not reusable-source proof.

Source upload additionally requires an explicit local workspace resolution,
existing `receipt_redaction_level = "none"` opt-in, separate policy-memory
permission, and the same current OAuth device/machine/workspace/grant plus native
consent revision/epoch captured in the immutable request. Backlog and retry sends
recheck the native origin and current authority immediately before sending.
Unavailable, disabled, rebound, pruned, or tombstoned sources have no disclosure
fallback; management preview remains source-unavailable.

Signed memory rule `target.machineIds` identifies enrolled OAuth machines. The
command job and structured acknowledgement retain the separately verified
server `targetMachineInstallationId` UUID as transport ownership. Neither an
acknowledgement nor the exact-support capability is native hook/UP+UV evidence.

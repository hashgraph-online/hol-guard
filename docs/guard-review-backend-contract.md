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

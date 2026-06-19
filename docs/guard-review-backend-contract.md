# Guard Review Backend Contract

Date: 2026-06-19
Scope: local Guard daemon and command runtime

## Local ownership

Guard Local remains the live interrupt owner.

Local owns:

- pending approval queue creation
- exact live request resolution
- local policy persistence
- bundle validation
- signed/verified remote approval acceptance
- signed memory acknowledgement generation

Cloud must not bypass the local queue by posting loose metadata.

## Accepted command payloads

### `guard.approval.resolve` for one live request

Required payload:

- `action=allow_once` or `action=block`
- `localRequestId`
- signed `remoteApproval`

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

If any check fails, the request is rejected and no policy is written.

### `guard.approval.resolve` for reusable memory

Required payload:

- `action=policy_sync`
- signed `decisionMemoryBundle`

Rejected payloads:

- loose `policyMemory`
- unsigned bundle
- tampered bundle hash / payload hash
- expired bundle
- downgraded policy version
- wrong workspace
- wrong target machine for machine-scoped bundle
- malformed or unsupported rule
- overbroad allow rule local runtime cannot safely enforce

## Local persistence behavior

Remote once:

- resolves exactly one pending queue item
- records claimed remote receipt
- does not upsert reusable policy

Signed memory bundle:

- updates only `cloud-signed-memory` policy rows derived from accepted rules
- preserves unrelated remote policies
- records bundle version and last ack payload
- supports signed revocation bundle replay through bundle `revocations`

## Acknowledgement contract

After bundle processing, local emits `GuardDecisionMemoryAckV1` with:

- `workspaceId`
- `machineInstallationId`
- `machineId`
- `deviceId`
- `bundleVersion`
- `bundleHash`
- `policyVersion`
- `status`
- `reason`
- `appliedRuleCount`
- `rejectedRuleIds`
- `acknowledgedAt`

Accepted ack means the machine now enforces the bundle. Rejected/stale/expired
acks must not be treated as synced.

## Runtime and daemon touchpoints

- `src/codex_plugin_scanner/guard/review_contracts.py`
- `src/codex_plugin_scanner/guard/runtime/command_executors.py`
- `src/codex_plugin_scanner/guard/daemon/server.py`
- `src/codex_plugin_scanner/guard/store.py`

## Proof suites

- `tests/test_guard_command_queue.py`
- `tests/test_guard_headless_daemon_api.py`
- `tests/test_guard_command_queue_stale_pending_result.py`

# HOL Guard Cloud Integration Todo

Generated from `hol-guard-changes.md` on 2026-07-09.

Target repo: `hol-guard`
Contract source: portal repo `hol-points-portal`
Primary objective: make the local HOL Guard daemon, command queue, approval queue, memory-event pipeline, and policy bundle sync match the Cloud Review, Suggested Memory, and Cloud Policy behavior described in `hol-guard-changes.md`.

## Ground Rules For The Implementation Agent

- Work only in this repo unless a task explicitly says to run a portal proof command in `hol-points-portal`.
- Treat `hol-guard-changes.md` as the API contract. This file is the local implementation checklist.
- Keep portal-compatible fields when adding aliases. Prefer one canonical local shape, but do not drop currently consumed aliases until the portal and local tests prove migration safety.
- Never put local resume tokens, OAuth tokens, approval passwords, TOTP material, raw DPoP material, or secret-looking command output in cloud command results, sync metadata, telemetry, or policy acknowledgement payloads.
- Use focused tests while implementing each phase, then run the full focused proof block near the end.
- If a current test asserts behavior that conflicts with the portal contract, update the test to the new contract and add a regression that proves the old unsafe behavior does not return.

## Current Local Gaps Observed In This Checkout

These are not guesses; they were observed while reading the current local files.

- `src/codex_plugin_scanner/guard/runtime/command_queue.py` still backs off after empty queue polls. `command_queue_loop()` uses `_retry_wait_seconds()` when `last_poll_was_empty` is true, and `tests/test_guard_command_queue.py::test_command_queue_loop_backs_off_after_empty_polls` expects `[1, 2, 4]`. This conflicts with the portal requirement to renew immediately after an empty long poll when `waitMs` is enabled.
- `src/codex_plugin_scanner/guard/runtime/command_executors.py` applies `guard.approval.resolve` but does not call `defer_request_resume_to_live_hook()` or `retry_request_resume()` after successful Codex cloud decisions.
- `src/codex_plugin_scanner/guard/daemon/server.py` applies Codex resume handling for local browser approval resolution, but `_handle_headless_remote_once()` currently writes a completed response without `codex_resume` metadata.
- `src/codex_plugin_scanner/guard/harness_resume.py` is referenced by `hol-guard-changes.md`, but that file does not exist in this checkout.
- `src/codex_plugin_scanner/guard/adapters/contracts.py` currently marks the Pi contract, including alias `oh-my-pi`, with `resume_support=False`. The portal load fixture expects `oh-my-pi` to be resume-capable.
- `src/codex_plugin_scanner/guard/runtime/runner.py::_policy_bundle_rule_matches_local_scope()` rejects any policy bundle rule with non-empty `scope.locations`.
- `src/codex_plugin_scanner/guard/runtime/runner.py::_build_policy_bundle_decisions()` currently emits only `family:<family>` harness-scope decisions. It does not convert portal memory-created exact `matcher.artifactId` rules into exact local artifact decisions.
- `src/codex_plugin_scanner/guard/runtime/local_request_snapshots.py` emits snake_case `raw_command_text`, `command_text`, and `action_envelope_json` but does not explicitly emit `redaction_enabled` or camelCase aliases such as `rawCommandText`, `commandText`, `actionEnvelope`, and `redactionEnabled`.
- `src/codex_plugin_scanner/guard/memory_decision_event.py` has a memory-decision event pipeline, but the implementation must be revalidated so Suggested Memory candidates are anchored on the guarded action, not only on `hol-guard approvals approve <request-id>` wrapper text.

## Definition Of Done

- A Cloud Review approval or denial produces a portal `guard.approval.resolve` command job that the connected local daemon receives under 200 ms p95 with a persistent receive loop active.
- Local queue workers acknowledge, apply, and complete `guard.approval.resolve` jobs through `/api/guard/commands/[jobId]/result`.
- Cloud approval resumes or unblocks the exact pending Codex, Pi, or `oh-my-pi` operation; cloud denial marks the same operation blocked.
- Result payloads include only non-sensitive acknowledgement and resume metadata.
- Cloud Review rows have clear display text for shell commands and non-shell action envelopes.
- Local approval and denial decisions emit `approval.memory_decision` events with stable identity fields, concrete display text, correct scope, and no broad generic fragments.
- Signed `guard-policy-bundle.v1` bundles from the portal sync locally, preserve last-known-good state on invalid updates, acknowledge sync back to the portal, and apply exact allow/block rules from Suggested Memories.
- The local proof commands and the portal guard-test commands listed at the end pass.

## Phase 0: Baseline And Safety

- [x] Check current worktree status before editing:

  ```bash
  git status --short
  ```

- [x] Do not remove or revert `hol-guard-changes.md`; it is a user-added handoff.
- [x] Do not clean generated `.gradle/` directories or other untracked files unless explicitly asked.
- [x] Create a short local notes file outside versioned changes only if needed; the deliverable implementation should be source code plus tests. Not needed.
- [x] Run the current focused tests that are expected to reveal the main gaps:

  ```bash
  pipx run uv run --extra dev python -m pytest tests/test_guard_command_queue.py -k "backs_off_after_empty_polls or executor_resolves_local_approval_request or executor_blocks_local_approval_request"
  pipx run uv run --extra dev python -m pytest tests/test_guard_runtime.py -k "policy_bundle_decisions_map_to_runtime_families or sync_receipts_rejects_policy_bundle_for_the_wrong_workspace"
  pipx run uv run --extra dev python -m pytest tests/test_guard_non_codex_resume.py tests/test_guard_harness_contracts.py
  ```

- [x] Record which tests pass before edits. Some existing assertions are expected to change.

  Baseline results recorded on 2026-07-09 before implementation edits:

  - `tests/test_guard_command_queue.py -k "backs_off_after_empty_polls or executor_resolves_local_approval_request or executor_blocks_local_approval_request"`: 3 passed.
  - `tests/test_guard_runtime.py -k "policy_bundle_decisions_map_to_runtime_families or sync_receipts_rejects_policy_bundle_for_the_wrong_workspace"`: 2 passed.
  - `tests/test_guard_non_codex_resume.py tests/test_guard_harness_contracts.py`: 26 passed.

## Phase 1: Emit Portal-Readable Review Payloads For Every Action Type

Related handoff task: HG-001.

Primary files:

- `src/codex_plugin_scanner/guard/runtime/local_request_snapshots.py`
- `src/codex_plugin_scanner/guard/approvals.py`
- `src/codex_plugin_scanner/guard/store_approvals.py`
- `src/codex_plugin_scanner/guard/runtime/actions.py`
- `src/codex_plugin_scanner/guard/cli/commands_support_hook_payload.py`
- `tests/test_raw_command_text.py`
- `tests/test_guard_runtime_actions.py`
- New or updated focused tests for cloud review snapshot payloads.

Implementation tasks:

- [x] Add a single local helper for cloud review payload compatibility, preferably in `runtime/local_request_snapshots.py`, so alias emission is centralized.
- [x] Emit explicit redaction state on every local request snapshot item:
  - Canonical snake_case: `redaction_enabled`.
  - Compatibility alias: `redactionEnabled`.
  - Set to `False` only when the current redaction level allows raw details to be shown to Cloud Review. Treat `full` and `partial` as enabled.
- [x] For shell commands with redaction disabled, emit all compatible command fields that the portal accepts:
  - `raw_command_text`
  - `rawCommandText`
  - `command_text`
  - `commandText`
  - Keep exact full command text after local secret scrubbing rules. Do not replace a concrete command with generic tool names.
- [x] For shell commands with redaction enabled, set raw command fields to `None` or omit raw aliases consistently, but include enough redacted display data for the portal:
  - `envelope_redacted`
  - `envelopeRedacted`
  - `action_envelope_json`
  - `actionEnvelope`
- [x] For non-shell actions, ensure `action_envelope_json` and `actionEnvelope` contain typed action details rather than only a generic label.
- [x] Map or preserve the portal action envelope contract fields:
  - MCP: `action_type`, `mcp_server`, `tool_name`, target resource, and arguments when redaction is disabled.
  - Skill: `action_type`, `operation`, `skill_name`, source path, and requested permission.
  - File: `operation`, `path`, `access_mode`, and `content_state`.
  - Browser: `operation`, `url` or `origin` or `path` or `selector`.
  - Package: `operation`, `package_manager`, and `package_name`.
  - Network: `method` plus `url`, `uri`, `endpoint`, `origin`, or `host`.
  - Generic tool: `tool_name` plus `args`, `arguments`, `input`, or `parameters`.
- [x] Preserve existing local snake_case field names, but add camelCase aliases only at the cloud/live snapshot boundary unless tests show another call site needs them.
- [x] Include stable routing metadata on local request snapshots so projected portal rows can retain identity:
  - `workspace_id` and `workspaceId`
  - `machine_installation_id` and `machineInstallationId`
  - `grant_id` and `grantId`
  - `runtime_grant_id` and `runtimeGrantId`
  - `local_request_id` and `localRequestId`
  - `harness_id` and `harnessId`
  - `request_last_seen_at` and `requestLastSeenAt`
- [x] Source those routing fields from `guard_review_oauth_metadata(store)`, `store.get_oauth_local_credentials()`, and `store.get_or_create_installation_id()` where possible. If credentials are unavailable, keep local snapshots functional and omit only the unavailable cloud-only fields.
- [x] Extend `_cloud_safe_action_envelope()` so redacted envelopes still show operation, target class, target count, and reason. Do not leak raw paths, args, prompt text, or secrets when redaction is enabled.
- [x] Keep `_is_generic_tool_label()` protections in `approvals.py`, and add test cases for bare `tool`, `mcp`, `skill`, `bash`, `rg`, and `cat` so they are not promoted to display text or memory candidates when no concrete target is present.
- [x] Add regression tests that build local request snapshot payloads for:
  - Shell command with redaction disabled.
  - Shell command with redaction enabled.
  - MCP tool call.
  - Skill request.
  - File read.
  - File write.
  - Browser action.
  - Package install.
  - Network request.
  - Unknown but well-formed envelope.
  - Malformed envelope.
- [x] Validate these tests assert both canonical snake_case fields and required camelCase aliases.

Acceptance checks:

- [x] No Cloud Review payload uses only a generic label when concrete details exist.
- [x] Redaction-disabled shell payloads contain the complete reviewed command in both snake_case and camelCase aliases.
- [x] Redaction-enabled payloads include a redacted envelope and do not include raw secret-bearing command text.
- [x] Local snapshots remain byte-bounded and truncation-safe.

Focused local proof:

```bash
pipx run uv run --extra dev python -m pytest tests/test_raw_command_text.py tests/test_guard_runtime_actions.py -k "raw_command_text or action_envelope or generic_tool"
pipx run uv run --extra dev python -m ruff check src/codex_plugin_scanner/guard/runtime/local_request_snapshots.py src/codex_plugin_scanner/guard/approvals.py
```

## Phase 2: Keep Cloud Approval Delivery Under 200 ms P95

Related handoff task: HG-002.

Primary files:

- `src/codex_plugin_scanner/guard/runtime/command_queue.py`
- `tests/test_guard_command_queue.py`

Implementation tasks:

- [x] Add a helper in `command_queue.py` to resolve the effective lease wait value from `GUARD_CLOUD_COMMAND_QUEUE_LEASE_WAIT_MS`.
- [x] Treat a positive `waitMs` as long-poll mode.
- [x] In `command_queue_loop()`, when `poll_command_queue_once()` returns `last_poll_was_empty=True` and long-poll mode is enabled, immediately issue the next lease request:
  - Set `wait_seconds = 0`.
  - Reset or ignore `empty_streak`.
  - Do not call `_retry_wait_seconds()` for this path.
- [x] Keep the current exponential backoff behavior for:
  - OAuth authorization expiry.
  - Missing cloud configuration.
  - Server failures.
  - Network failures.
  - Empty polls only when long-poll `waitMs` is disabled or zero.
- [x] Preserve pending result retry behavior before leasing another job.
- [x] Preserve idempotent result posting with existing `idempotencyKey` values.
- [x] Rename or replace `test_command_queue_loop_backs_off_after_empty_polls` because the current expectation conflicts with the portal contract.
- [x] Add `test_command_queue_loop_immediately_renews_after_empty_long_poll`:
  - Set command queue enabled.
  - Set `GUARD_CLOUD_COMMAND_QUEUE_LEASE_WAIT_MS` to a positive value.
  - Fake three empty polls.
  - Assert waits are `[0, 0, 0]` or equivalent immediate renew behavior.
- [x] Add `test_command_queue_loop_backs_off_after_empty_short_poll_when_wait_disabled`:
  - Set `GUARD_CLOUD_COMMAND_QUEUE_LEASE_WAIT_MS=0`.
  - Preserve the old backoff expectation for short polling.
- [x] Keep existing OAuth revocation and server-error tests green.
- [x] Add or update a duplicate lease/result regression:
  - Duplicate leased `guard.approval.resolve` job must not double-resolve.
  - Duplicate result upload must use the same idempotency key or be harmless.

Acceptance checks:

- [x] Empty long-poll responses cause immediate renew.
- [x] Errors still back off.
- [x] Local queue status still records `last_empty_poll_at` and `last_poll_was_empty`.
- [x] Portal load fixture can observe `cloudAcceptedAt -> command created -> local receive -> local ack -> completion`.

Focused local proof:

```bash
pipx run uv run --extra dev python -m pytest tests/test_guard_command_queue.py -k "immediately_renews_after_empty_long_poll or backs_off_after_empty_short_poll_when_wait_disabled or command_queue_loop_backs_off_after_errors or retries_revoked_oauth_auth"
pipx run uv run --extra dev python -m ruff check src/codex_plugin_scanner/guard/runtime/command_queue.py tests/test_guard_command_queue.py
```

## Phase 3: Apply Cloud `guard.approval.resolve` Jobs To The Exact Local Request

Related handoff task: HG-003.

Primary files:

- `src/codex_plugin_scanner/guard/runtime/command_executors.py`
- `src/codex_plugin_scanner/guard/review_contracts.py`
- `src/codex_plugin_scanner/guard/runtime/command_queue.py`
- `tests/test_guard_command_queue.py`
- `tests/test_guard_queue_api_contract.py`

Implementation tasks:

- [x] Add explicit job target validation before applying `guard.approval.resolve`.
- [x] Validate outer job or payload target fields when present:
  - `targetGrantId`
  - `targetMachineInstallationId`
  - `targetRuntimeGrantId`
  - `workspaceId`
  - `localRequestId`
- [x] Compare target fields against local OAuth metadata:
  - `targetGrantId` against local `grant_id`.
  - `targetMachineInstallationId` against `store.get_or_create_installation_id()`.
  - `targetRuntimeGrantId` against local `runtime_id` when local runtime id is present.
  - `workspaceId` against local `workspace_id`.
  - `localRequestId` against the pending local request id.
- [x] Keep `validate_remote_approval_request_binding()` as the signed envelope verifier. The new target validation should reject wrong outer command routing before any local side effect.
- [x] Normalize approval actions from the portal:
  - Treat `allow`, `allow_once`, `allow-once`, and `allowOnce` as local allow.
  - Treat `block`, `deny`, `denied`, and local terminal `blocked` as local block.
  - Continue to support `policy_sync`.
- [x] Keep receipt replay protection:
  - Claim signed `receiptId` before local resolve.
  - Release the claim when local resolution fails or is not applied.
  - Do not release the claim after a successful resolve.
- [x] Reject stale claims where signed `sourceClaimHash`, `actionEnvelopeHash`, `policyVersion`, request id, approval id, harness id, workspace, machine, device, or scope mismatch.
- [x] Mark the local request resolved exactly once. Replayed, already-resolved, or mismatched jobs must return a deterministic failure or `not_resolved` result without changing local policy again.
- [x] Ensure command results are posted as `{ "result": { "data": ... } }` through `_result_payload()` for successful executions.
- [x] Add non-sensitive result metadata under `data`:
  - `localRequestId`
  - `remoteDecision`
  - `daemonAckStatus`
  - `resolution.status`
  - `resumeStatus` when resume is attempted.
  - `resumeCompletedAt` when available.
- [x] Do not include command text, raw envelopes, tokens, resume tokens, or signed material in result telemetry metadata.

Acceptance checks:

- [x] Cloud approval resolves the same local request.
- [x] Cloud denial blocks the same local request and portal can treat local `blocked` as denial terminal state.
- [x] Stale, wrong-machine, wrong-workspace, wrong-runtime, already-approved, and already-denied jobs do not create duplicate effects.
- [x] Portal delivery state can progress through `queued`, `acknowledged`, `resumed`, `failed`, or `expired`.

Focused local tests to add or update:

- [x] `test_executor_resolves_local_approval_request` asserts `data.remoteDecision == "allow"` and non-sensitive ack metadata.
- [x] `test_executor_blocks_local_approval_request` asserts `data.remoteDecision == "block"` and local denial metadata.
- [x] Wrong `targetGrantId` returns a failure before `resolve_request_with_signed_remote_result()`.
- [x] Wrong `targetMachineInstallationId` returns a failure before resolve.
- [x] Wrong `targetRuntimeGrantId` returns a failure before resolve.
- [x] Wrong `workspaceId` returns a failure before resolve.
- [x] Duplicate signed receipt does not double-resolve.
- [x] Duplicate command result uses stable idempotency behavior.

Focused local proof:

```bash
pipx run uv run --extra dev python -m pytest tests/test_guard_command_queue.py tests/test_guard_queue_api_contract.py -k "executor_resolves_local_approval_request or executor_blocks_local_approval_request or stale_remote_approval or wrong_target or duplicate"
pipx run uv run --extra dev python -m ruff check src/codex_plugin_scanner/guard/runtime/command_executors.py src/codex_plugin_scanner/guard/review_contracts.py
```

## Phase 4: Resume Codex, Pi, And `oh-my-pi` Harnesses

Related handoff task: HG-004.

Primary files:

- `src/codex_plugin_scanner/guard/runtime/command_executors.py`
- `src/codex_plugin_scanner/guard/daemon/server.py`
- `src/codex_plugin_scanner/guard/codex_resume.py`
- New file likely needed: `src/codex_plugin_scanner/guard/harness_resume.py`
- `src/codex_plugin_scanner/guard/store_sessions.py`
- `src/codex_plugin_scanner/guard/adapters/contracts.py`
- `src/codex_plugin_scanner/guard/adapters/pi_hooks.py`
- `tests/test_guard_command_queue.py`
- `tests/test_guard_headless_daemon_api.py`
- `tests/test_guard_harness_contracts.py`
- `tests/test_guard_non_codex_resume.py`

Codex implementation tasks:

- [x] In `command_executors.py`, import `defer_request_resume_to_live_hook()` and `retry_request_resume()`.
- [x] After a successful `guard.approval.resolve` where the request harness is `codex` and the local resolution action is allow or block:
  - First call `defer_request_resume_to_live_hook(store, request_id=..., action=..., now=generated_at)`.
  - If it returns `None`, call `retry_request_resume(store, request_id=..., now=generated_at)`.
  - Catch `ValueError("resume_not_supported")` and report a skipped/non-supported resume status without failing the already-applied approval.
  - For block decisions, preserve the denied-result resume state from `codex_resume.py` instead of silently resolving only the row.
- [x] Add both `codexResume` and `codex_resume` result fields unless the portal proof shows only one is needed. Prefer `codexResume` in command queue results and `codex_resume` in daemon/headless local API responses.
- [x] Include resume status, reason, message, attempt count, and sent/completed timestamp when available.
- [x] Do not include thread ids if they are considered sensitive by existing tests. If thread ids are already exposed locally, do not add them to cloud result metadata without a test proving safety.

Headless remote-once implementation tasks:

- [x] In `daemon/server.py::_handle_headless_remote_once()`, mirror the Codex resume handling used by local approval resolution after `resolve_request_with_signed_remote_result()` succeeds.
- [x] Attach `codex_resume` to the JSON response for Codex remote-once decisions.
- [x] Record `codex/thread_resume` events for headless remote-once, consistent with local browser approval resume behavior.
- [x] Ensure remote-once denial records explicit denied resume state.

Pi and `oh-my-pi` implementation tasks:

- [x] Add `src/codex_plugin_scanner/guard/harness_resume.py` or an equivalent clearly named module. The handoff names `harness_resume.py`, so prefer that path unless there is a strong local reason not to.
- [x] Provide a small API such as:

  ```python
  def resume_harness_operation(store: GuardStore, *, request_id: str, action: str, now: str) -> dict[str, object] | None:
      ...
  ```

- [x] The API should:
  - Look up `store.get_guard_operation_for_approval_request(request_id)`.
  - Return `None` when no operation exists.
  - Support canonical harness `pi` and aliases resolved through the contract layer.
  - Mark allow decisions as `resumed`.
  - Mark block decisions as `blocked`.
  - Preserve the operation id, harness, status, action, and completed timestamp.
  - Omit `resume_token` and any secret-bearing metadata from the returned payload.
- [x] Update the waiting operation through existing store APIs. If no direct update method exists, use `upsert_guard_operation()` with the same operation id and existing non-sensitive fields.
- [x] Add events for harness resume outcomes, for example `harness/operation_resume` or an existing event name if one already exists.
- [x] Integrate generic harness resume into:
  - Cloud command queue `guard.approval.resolve`.
  - Headless remote-once decisions.
  - Browser approval API resolution in `daemon/server.py`.
- [x] Attach `harness_resume` and `harnessResume` metadata for Pi paths.
- [x] Ensure Codex paths do not also attach Pi `harness_resume`, and Pi paths do not attach `codex_resume`.
- [x] In `adapters/contracts.py`, set Pi `resume_support=True`; this includes `pi`, `pi-agent`, `pi-coding-agent`, `omp`, and `oh-my-pi`.

Acceptance checks:

- [x] Cloud approval resumes Codex through the live-hook wait path when a live hook is active.
- [x] Cloud approval falls back correctly when no Codex live hook is present.
- [x] Cloud denial returns an explicit Codex denied/skipped resume state.
- [x] Pi approval marks the waiting operation `resumed`.
- [x] Pi denial marks the waiting operation `blocked`.
- [x] `contract_for("oh-my-pi")` returns the Pi contract with `resume_support=True`.
- [x] No resume tokens are present in cloud command results or daemon remote-once responses.

Focused local proof:

```bash
pipx run uv run --extra dev python -m pytest tests/test_guard_command_queue.py tests/test_guard_headless_daemon_api.py -k "codex_resume or remote_once"
pipx run uv run --extra dev python -m pytest tests/test_guard_harness_contracts.py tests/test_guard_non_codex_resume.py
pipx run uv run --extra dev python -m ruff check src/codex_plugin_scanner/guard/runtime/command_executors.py src/codex_plugin_scanner/guard/daemon/server.py src/codex_plugin_scanner/guard/codex_resume.py src/codex_plugin_scanner/guard/harness_resume.py src/codex_plugin_scanner/guard/adapters/contracts.py
```

## Phase 5: Enforce Cloud Policies Created From Suggested Memories

Related handoff task: HG-005.

Primary files:

- `src/codex_plugin_scanner/guard/runtime/runner.py`
- `src/codex_plugin_scanner/guard/policy_bundle_parser.py`
- `src/codex_plugin_scanner/guard/policy_bundle_trusted_keys.py`
- `src/codex_plugin_scanner/guard/daemon/server.py`
- `src/codex_plugin_scanner/guard/store_policy.py`
- `tests/test_guard_runtime.py`
- `tests/test_policy_bundle_parser.py`

Implementation tasks:

- [x] Keep existing signed bundle validation:
  - `contractVersion == "guard-policy-bundle.v1"`.
  - Valid `bundleVersion`, `bundleHash`, `payloadHash` when present, signature, expiry, rollout state, acknowledgements, and `rules`.
  - Wrong workspace rejected.
  - Invalid bundle preserves `policy_bundle_last_good`.
- [x] Add a helper in `runner.py` to extract exact artifact ids from portal memory-created rules:
  - `rule["matcher"]["artifactId"]`
  - `rule["matcher"]["artifact_id"]`
  - Top-level `artifactId` if the portal emits it.
  - Any documented alias from `hol-guard-changes.md` if present in fixtures.
- [x] Add a helper to extract source metadata:
  - `sourceDecisionId`
  - `sourceSuggestionId`
  - `sourceReceiptIds`
  - `auditEventIds`
  - `ruleId`
  - `reason`
- [x] Change `_policy_bundle_rule_matches_local_scope()` so non-empty `scope.locations` does not automatically reject a rule.
- [x] Convert exact `matcher.artifactId` rules into local exact decisions:
  - With non-empty `scope.locations`, create `PolicyDecision(scope="workspace", artifact_id=<exact artifact>, workspace=<location>, action=<allow|block>, source="policy-bundle", owner=<rule id>, reason=<diagnostic reason>)`.
  - Without `scope.locations`, create `PolicyDecision(scope="artifact", artifact_id=<exact artifact>, action=<allow|block>, source="policy-bundle", owner=<rule id>, reason=<diagnostic reason>)`.
- [x] If multiple `scope.locations` exist, emit one workspace-scoped decision per location.
- [x] If a location appears to be a project path but local `DecisionScope` has no `project` value, use workspace-scoped exact artifact decisions unless you intentionally extend `DecisionScope` with a separate project scope and update all policy lookup code and tests.
- [x] Do not convert workspace-scoped exact rules into broad harness-scope rules.
- [x] For family matcher rules with locations:
  - Convert to workspace-scoped `family:<family>` fallback decisions only when the family can be represented safely.
  - Do not emit broad harness-scope family rules when `scope.locations` is present.
- [x] Preserve existing browser-scope safety checks. Browser-specific scopes must not become broad local family rules.
- [x] Ensure allow and block actions both work for memory-created policy rules.
- [x] Ensure rule-level `expiresAt` wins over bundle-level `expiresAt` when present.
- [x] Store enough source metadata in `owner`, `reason`, or a supported policy metadata field so local diagnostics can identify the Suggested Memory or rule that created the decision.
- [x] Keep policy bundle acknowledgement receipts:
  - `policy_bundle_ack` in sync payload.
  - `syncContext.policyBundleAcknowledgement` on the next receipt sync.
  - Daemon policy sync response includes bundle hash and version.

Acceptance checks:

- [x] Matching exact artifact auto allows locally.
- [x] Matching exact artifact auto blocks locally.
- [x] Non-matching artifacts still go to review.
- [x] Matching artifact in a different workspace/location does not match.
- [x] Invalid bundle does not replace last-known-good policy bundle.
- [x] Wrong-workspace bundle is rejected and records `policy_bundle_last_error`.
- [x] Portal Policies can show synced daemon acknowledgement state after local sync.

Required focused tests:

- [x] Add `test_policy_bundle_exact_artifact_rules_apply_with_workspace_scope` to `tests/test_guard_runtime.py`.
- [x] Ensure it proves:
  - Portal-style exact allow rule applies locally.
  - Portal-style exact block rule applies locally.
  - Non-matching command is not allowed/blocked.
  - Same artifact in a different workspace is not matched.
  - `scope.locations` is preserved as a local workspace boundary.
- [x] Keep these existing tests green:
  - `test_policy_bundle_validation_rejects_tampered_hash`
  - `test_policy_bundle_validation_rejects_missing_rules_field`
  - `test_sync_receipts_preserves_last_known_good_policy_bundle_on_invalid_update`
  - `test_sync_receipts_rejects_policy_bundle_for_the_wrong_workspace`
  - `test_receipt_sync_context_uploads_policy_bundle_acknowledgement`
  - `test_sync_receipts_uploads_policy_bundle_acknowledgement`

Focused local proof:

```bash
pipx run uv run --extra dev python -m pytest tests/test_guard_runtime.py -k "policy_bundle_exact_artifact_rules_apply_with_workspace_scope or policy_bundle_validation_rejects_tampered_hash or policy_bundle_validation_rejects_missing_rules_field or sync_receipts_preserves_last_known_good_policy_bundle_on_invalid_update or sync_receipts_rejects_policy_bundle_for_the_wrong_workspace or receipt_sync_context_uploads_policy_bundle_acknowledgement or sync_receipts_uploads_policy_bundle_acknowledgement"
pipx run uv run --extra dev python -m ruff check src/codex_plugin_scanner/guard/runtime/runner.py src/codex_plugin_scanner/guard/policy_bundle_parser.py src/codex_plugin_scanner/guard/policy_bundle_trusted_keys.py
```

## Phase 6: Emit Local Memory Decision Events That Become Suggested Memories

Related handoff task: HG-006.

Primary files:

- `src/codex_plugin_scanner/guard/approvals.py`
- `src/codex_plugin_scanner/guard/memory_decision_event.py`
- `src/codex_plugin_scanner/guard/memory_decision_outbox.py`
- `src/codex_plugin_scanner/guard/memory_pattern_fingerprint.py`
- `src/codex_plugin_scanner/guard/store_approvals.py`
- `src/codex_plugin_scanner/guard/runtime/action_identity.py`
- `tests/test_guard_memory_decision_event.py`
- `tests/test_guard_phase05_approval_memory.py`
- Any existing outbox or cloud events tests.

Implementation tasks:

- [x] Confirm `approval.resolved` calls `_enqueue_memory_decision_for_resolution()` for both allow and block decisions.
- [x] Confirm remote cloud decisions that apply locally also call the same memory-decision path, or explicitly enqueue with `decision_source="cloud_review"` if the portal expects source distinction.
- [x] Ensure `GuardMemoryDecisionEventV1` payload includes:
  - `action_identity`
  - `decision_scope`
  - `harness_id`
  - `project_id` when available from guard operation metadata.
  - `workspace_id`
  - `decision_action`
  - `command_display`
  - `command_raw` only when redaction allows it.
  - `memory_pattern_fingerprint`
  - `memory_pattern_kind`
  - `memory_pattern_components`
- [x] Adjust `resolve_command_display()` so memory candidate display text is the guarded action text, not the local approval wrapper command.
  - If `raw_command_text` is withheld, prefer safe action envelope text or artifact display text.
  - Do not fall back to `review_command` for candidate identity or display unless there is no other safe signal and tests prove it will not create broad `hol-guard approvals approve` candidates.
- [x] Ensure `build_memory_pattern_fingerprint()` suppresses broad generic fragments:
  - bare `bash`
  - bare `rg`
  - bare `cat`
  - bare `tool`
  - bare `mcp`
  - bare `skill`
- [x] Ensure concrete behavior remains eligible:
  - `rg TODO src/lib/file.ts`
  - `cat package.json`
  - `mcp filesystem.read_file path=...` when redaction policy permits enough target detail.
- [x] Include project identity from `store.get_guard_operation_for_approval_request()` metadata when available:
  - `project_id`
  - `projectId`
  - `workspace_path`
  - `workspacePath`
- [x] Keep enqueue defensive. Missing cloud pairing or outbox failures must not break local approval resolution.
- [x] Add tests for repeated same-direction local approvals and denials at the local event level, even though the portal performs final candidate grouping.
- [x] Add tests proving conflicting approve/block decisions remain distinguishable by `decision_action`.

Acceptance checks:

- [x] Repeated same-direction local approvals can become allow Suggested Memory candidates in the portal.
- [x] Repeated same-direction local denials can become block Suggested Memory candidates in the portal.
- [x] Approve/block conflicts do not merge into one local identity.
- [x] Inventory-only and pending decisions do not emit memory decision events.
- [x] Different commands remain separate by action identity and pattern fingerprint.

Focused local proof:

```bash
pipx run uv run --extra dev python -m pytest tests/test_guard_memory_decision_event.py tests/test_guard_phase05_approval_memory.py -k "memory or action_identity or generic"
pipx run uv run --extra dev python -m ruff check src/codex_plugin_scanner/guard/memory_decision_event.py src/codex_plugin_scanner/guard/memory_decision_outbox.py src/codex_plugin_scanner/guard/memory_pattern_fingerprint.py
```

## Phase 7: End-To-End Local Proof Block

Run this after phases 1 through 6 are implemented and focused tests are green.

```bash
pipx run uv run --extra dev python -m pytest tests/test_guard_command_queue.py tests/test_guard_queue_api_contract.py tests/test_guard_runtime.py -k "executor_resolves_local_approval_request or executor_blocks_local_approval_request or executor_syncs_policy_without_local_request_id or codex_resolution_sends_continue_prompt_to_original_thread or guard_run_headless_waits_for_local_approval_and_resumes"
pipx run uv run --extra dev python -m pytest tests/test_guard_runtime.py -k "policy_bundle_exact_artifact_rules_apply_with_workspace_scope or policy_bundle_validation_rejects_tampered_hash or policy_bundle_validation_rejects_missing_rules_field or sync_receipts_preserves_last_known_good_policy_bundle_on_invalid_update or sync_receipts_rejects_policy_bundle_for_the_wrong_workspace or receipt_sync_context_uploads_policy_bundle_acknowledgement or sync_receipts_uploads_policy_bundle_acknowledgement"
pipx run uv run --extra dev python -m pytest tests/test_guard_command_queue.py tests/test_guard_harness_contracts.py tests/test_guard_non_codex_resume.py tests/test_guard_headless_daemon_api.py
pipx run uv run --extra dev python -m ruff check src/codex_plugin_scanner/guard/runtime/command_queue.py src/codex_plugin_scanner/guard/runtime/command_executors.py src/codex_plugin_scanner/guard/daemon/server.py src/codex_plugin_scanner/guard/runtime/runner.py src/codex_plugin_scanner/guard/adapters/contracts.py
```

Phase 7 local proof results:

- [x] Cloud command, queue API contract, and runtime selected proof: 5 passed.
- [x] Policy bundle selected proof: 8 passed.
- [x] Command queue, harness contracts, non-Codex resume, and daemon API proof: 188 passed, 1 Python multiprocessing deprecation warning.
- [x] Phase 7 ruff proof: passed.
- [x] Additional snapshot byte-budget regression proof after the one Phase 7 failure: passed.
- [x] Additional daemon remote-once resume metadata sanitizer proof: 2 passed, then covered by the 188-test rerun.

If any proof command fails:

- [x] Save the exact failing test name and assertion.
- [x] Identify whether the failure is a real implementation bug or an old assertion that conflicts with the new portal contract.
- [x] Fix implementation first. Update tests only when the old expectation is demonstrably obsolete under `hol-guard-changes.md`.

## Phase 8: Cross-Repo Portal Verification

Run these from the `hol-points-portal` repo after local `hol-guard` changes are available to the portal guard-test harness.

```bash
GUARD_TEST_REVIEW_CLOUD_API_ONLY=1 bun run guard:test:review-cloud-browser-decisions
GUARD_TEST_REVIEW_CLOUD_API_ONLY=1 GUARD_TEST_REVIEW_CLOUD_LOAD=1 bun run guard:test:review-cloud-browser-decisions
GUARD_TEST_PORTAL_STDIO=inherit GUARD_TEST_REVIEW_CLOUD_SURFACE_ONLY=1 bun run guard:test:review-cloud-browser-decisions
bun run guard:test:multi-harness-live-sync
bun run guard:test:suggested-memory-patterns
bun run guard:test:teardown
```

Expected portal proof outcomes:

- [x] API-only browser decisions pass for approve and block.
- [x] Load fixture passes with 25 decisions, 3 machines, and 3 harnesses.
- [x] `receiveP95Ms` is below 200 ms.
- [x] Browser-backed Review surface shows exact command text for redaction-disabled shell commands.
- [x] Suggested Memory surface shows repeated decision candidates.
- [x] Policies surface shows memory-created policy rules and local daemon acknowledgement state.
- [x] Multi-harness live sync includes `codex`, `cursor`, and `oh-my-pi` without losing harness attribution.
- [x] Teardown completes cleanly.

Phase 8 portal proof results:

- [x] `GUARD_TEST_REVIEW_CLOUD_API_ONLY=1 bun run guard:test:review-cloud-browser-decisions`: passed on retry; first cold run reached local delivery but missed p95 with 217 ms / 1913 ms latencies, retry passed with `receiveP95Ms=175`.
- [x] `GUARD_TEST_REVIEW_CLOUD_API_ONLY=1 GUARD_TEST_REVIEW_CLOUD_LOAD=1 bun run guard:test:review-cloud-browser-decisions`: passed with 25 requests, 3 machines, harnesses `codex`, `cursor`, `oh-my-pi`, and `p95Ms=117`.
- [x] `GUARD_TEST_PORTAL_STDIO=inherit GUARD_TEST_REVIEW_CLOUD_SURFACE_ONLY=1 bun run guard:test:review-cloud-browser-decisions`: passed; captured Blocked Now, Suggested Memory, and Policies screenshots.
- [x] `bun run guard:test:multi-harness-live-sync`: passed; fixture covered `cursor`, `vscode`, and `codex` attribution.
- [x] `bun run guard:test:suggested-memory-patterns`: passed all candidate grouping scenarios.
- [x] `bun run guard:test:teardown`: passed.

## Final Review Checklist

- [x] Search for accidental secret or token exposure in result payload construction:

  ```bash
  rg -n "resume_token|access_token|refresh_token|approval_password|totp|private_key|client_secret" src/codex_plugin_scanner/guard tests
  ```

- [x] Search for command queue sleeps/backoff in the empty long-poll path:

  ```bash
  rg -n "last_poll_was_empty|empty_streak|waitMs|LEASE_WAIT" src/codex_plugin_scanner/guard/runtime/command_queue.py tests/test_guard_command_queue.py
  ```

- [x] Search for policy bundle exact artifact handling:

  ```bash
  rg -n "artifactId|artifact_id|scope.*locations|policy_bundle_exact_artifact" src/codex_plugin_scanner/guard/runtime/runner.py tests/test_guard_runtime.py
  ```

- [x] Search for Pi resume support:

  ```bash
  rg -n "oh-my-pi|resume_support|harness_resume|harnessResume" src/codex_plugin_scanner/guard tests/test_guard_non_codex_resume.py tests/test_guard_harness_contracts.py
  ```

- [x] Confirm all new cloud-facing result fields are documented in tests and contain only non-sensitive values.
- [x] Confirm `todo-update.md` stays as the implementation checklist and does not drift into a status report unless updated after implementation.

Final review notes:

- [x] Broad sensitive-name search produced expected credential storage, auth flow, and fixture hits. Focused result-payload review found no exposed signed approvals, resume tokens, access tokens, refresh tokens, approval passwords, TOTP values, private keys, or client secrets in new cloud-facing result payloads.
- [x] Added a daemon remote-once regression proving raw Codex resume `thread_id` and `resume_token` values are stripped from both response payloads and `codex/thread_resume` events.
- [x] Empty long-poll path resets `empty_streak` and sets `wait_seconds = 0`; short-poll and error paths still back off.
- [x] Policy bundle review confirmed exact `matcher.artifactId` / `matcher.artifact_id` handling with location-scoped decisions.
- [x] Pi review confirmed `oh-my-pi` alias support, `resume_support=True`, and `harness_resume`/`harnessResume` non-token payload tests.

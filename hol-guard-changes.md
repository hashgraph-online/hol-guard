# HOL Guard Cross-Repo Integration Handoff

Date: 2026-07-08
Portal repo: `hol-points-portal`
Local repo: `hol-guard`
Purpose: implementation handoff for the `hol-guard` Codex agent so local Guard integrates cleanly with the Cloud Review, Suggested Memory, and Cloud Policy behavior now present in the portal.

## How To Use This Handoff

1. Work in the `hol-guard` repo for the local implementation tasks below.
2. Treat the "Portal Contract" section as the authoritative API and payload shape expected by `hol-points-portal`.
3. Implement the tasks in order. Each task includes the local behavior, portal expectation, and proof command to run.
4. Keep existing portal-compatible fields even when adding new aliases. The portal intentionally accepts snake_case and camelCase for several fields, but local `hol-guard` should emit one stable shape consistently.
5. After local changes, run the local proof commands in this file and then run the portal guard-test commands from `hol-points-portal` to verify cross-repo behavior.

## Likely `hol-guard` Files To Inspect First

- `src/codex_plugin_scanner/guard/runtime/command_queue.py`: command lease loop, long-poll renewal, result posting, backoff behavior.
- `src/codex_plugin_scanner/guard/runtime/command_executors.py`: `guard.approval.resolve` application, local request resolution, Codex resume.
- `src/codex_plugin_scanner/guard/daemon/server.py`: headless remote decision handling and daemon response payloads.
- `src/codex_plugin_scanner/guard/runtime/runner.py`: local policy bundle conversion and local auto-decision matching.
- `src/codex_plugin_scanner/guard/harness_resume.py`: non-Codex harness resume behavior, especially Pi and `oh-my-pi`.
- `src/codex_plugin_scanner/guard/adapters/contracts.py`: harness contract metadata and `resume_support`.
- `tests/test_guard_command_queue.py`: command queue, approval resolve, duplicate/stale behavior, and resume proofs.
- `tests/test_guard_runtime.py`: policy bundle validation and local auto-decision proofs.
- `tests/test_guard_headless_daemon_api.py`: headless daemon decision and resume evidence.
- `tests/test_guard_harness_contracts.py` and `tests/test_guard_non_codex_resume.py`: non-Codex harness resume proof.

## Definition Of Done For The Local Agent

- Cloud Review approval reaches a connected local daemon in under 200 ms p95 under the portal 25-request load fixture.
- Cloud Review denial reaches the same local request and records a local blocked terminal state.
- Local daemon result posts are accepted by portal `/api/guard/commands/[jobId]/result` and include non-sensitive ack/resume metadata.
- Codex, Pi, and `oh-my-pi` requests resume or block through their harness-specific path.
- Repeated local approvals and denials emit memory decision events that become Suggested Memories in the portal.
- Approved Suggested Memories become signed Cloud Policy bundle rules and auto allow or block matching local actions.
- The Policies route shows policy sync acknowledgement state after local bundle sync.
- All local and portal proof commands in "Expected Cross-Repo Verification Commands" pass.

## Portal Contract Summary

- `Blocked Now` now keeps projected local pending `blocked_action` rows from `reviewSource: live-local` when they arrive on `tab: needs-review`.
- Portal command display now builds clear human text for action envelopes that do not contain a shell `command`.
- Exact shell command fields still win over synthesized envelope text.
- Supported synthesized display cases include MCP server calls, MCP tool calls, Codex tool calls, skill requests, browser actions, file operations, package installs, network requests, unknown envelopes, and malformed envelopes.
- When local payloads set `redaction_enabled` or `redactionEnabled` to `false`, Cloud Review may display full raw command text and raw envelope JSON.
- When local payloads set `redaction_enabled` or `redactionEnabled` to `true`, Cloud Review prefers `envelope_redacted` or `envelopeRedacted`.
- Cloud Review hides live local rows only after approved or denied states. Portal denial persists as local status `blocked`, so local `hol-guard` must treat `blocked` as the denial terminal state.
- Cloud Review local row metadata now exposes `workspaceId`, `machineInstallationId`, `targetGrantId`, `targetRuntimeGrantId`, `requestId`, `approvalId`, `harness`, `localStatus`, `cloudStatus`, and `lastSeenAt`.
- Cloud Review dedupe keys by workspace, machine installation, and local request ID. Local `hol-guard` may reuse a local request ID on different machines, but must keep machine installation IDs stable.
- Cloud approval and denial queue `guard.approval.resolve` jobs with exact `targetGrantId`, `targetMachineInstallationId`, `targetRuntimeGrantId`, `workspaceId`, and remote approval runtime grant data.
- Cloud Review live item models now expose `deliveryState.status` values: `queued`, `sent`, `acknowledged`, `resumed`, `failed`, `expired`, and `none`.
- Local and Cloud Review decisions converge in the portal durable memory candidate pipeline.
- Suggested Memory candidate identity is normalized by workspace, decision action, decision scope, harness, project, action identity, and raw pattern fingerprint.
- The portal suppresses broad Suggested Memory promotion for generic fragments such as plain `bash`, `rg`, `cat`, or `tool` unless local `hol-guard` sends concrete behavior text.
- Cloud Review approvals and denials emit `decision_source: cloud_review` memory decision events into the same candidate repository as local `approval.memory_decision` sync events.
- Cloud Review memory decision ingestion now runs asynchronously after the approval transaction so local `guard.approval.resolve` command queue creation is not blocked by memory candidate recompute.

## Required Local `hol-guard` Implementation Tasks

### HG-001: Emit Clear Review Payloads For Every Action Type

Goal: every blocked local request must be understandable in Cloud Review without the reviewer knowing local internals.

Implement:

- For shell commands, send the exact full command in `raw_command_text` and `command_text`.
- Also send `rawCommandText` and `commandText` if the local code already emits camelCase payloads; do not drop existing aliases until all downstream code is migrated.
- For non-shell actions, send `action_envelope_json` with a typed envelope as described in "Action Envelope Contract".
- Set `redaction_enabled` explicitly on every review payload.
- If redaction is disabled, include all arguments/details required for a human to approve or deny safely.
- If redaction is enabled, include `envelope_redacted` with safe display details.
- Never emit generic command labels such as only `tool`, `mcp`, `skill`, `bash`, `rg`, or `cat` when concrete action details are available.

Acceptance criteria:

- MCP, tool, skill, browser, file, package, network, unknown, and malformed action envelopes render as clear Cloud Review rows.
- Redaction-disabled shell commands render the complete command in Cloud Review.
- Redaction-enabled payloads do not leak raw secrets, but still show the operation, target, and reason clearly.

Suggested local tests:

- Add or update local serialization tests for shell, MCP tool, skill request, file read, file write, browser action, package install, and network request payloads.
- Verify the emitted payload contains stable `workspace_id`, `machine_installation_id`, `runtime_grant_id`, `grant_id`, `local_request_id`, `harness_id`, and `request_last_seen_at`.

Portal proof already passing:

- `__tests__/guard-action-envelope-display.test.ts`
- `__tests__/guard-raw-command-text-e2e.test.ts`
- `__tests__/guard-command-display-resolver.test.ts`

### HG-002: Keep Cloud Approval Delivery Under 200 ms P95

Goal: once Cloud Review accepts an approval or denial, the matching local device receives the `guard.approval.resolve` job within 200 ms p95 while connected.

Implement:

- The local command queue worker must keep a bounded long-poll lease open whenever the device is connected.
- Use the portal `/api/guard/commands/lease` endpoint with `waitMs` enabled.
- After an empty long-poll response, immediately issue the next lease request.
- Keep exponential backoff only for authorization failures, server failures, network failures, and missing configuration.
- Do not sleep for `GUARD_CLOUD_COMMAND_QUEUE_POLL_INTERVAL_SECONDS` after an empty long-poll response.
- Preserve idempotency so duplicate lease responses or duplicate result submissions do not double-resume an agent.

Acceptance criteria:

- A connected local daemon renews the receive loop immediately after empty long polls.
- Cloud approval and denial decisions are received, acked, and completed through `/api/guard/commands/[jobId]/result`.
- The portal timing chain can observe `cloudAcceptedAt`, command job creation, local receive, local ack, lease event, and completion event.

Suggested local tests:

- `tests/test_guard_command_queue.py` should prove immediate renew after empty long poll.
- Existing OAuth revocation and server-error tests must still prove backoff on actual failures.
- Add a regression for duplicate `guard.approval.resolve` jobs or duplicate local result posts.

Portal proof already passing:

- `GUARD_TEST_REVIEW_CLOUD_API_ONLY=1 GUARD_TEST_REVIEW_CLOUD_LOAD=1 bun run guard:test:review-cloud-browser-decisions`
- Latest load evidence: `requestCount=25`, `machineCount=3`, `harnessCount=3`, `p50Ms=90`, `p95Ms=96`, `worstMs=97`.

### HG-003: Apply Cloud `guard.approval.resolve` Jobs Locally

Goal: Cloud Review approval or denial must update the exact local blocked request and resume or block the underlying harness process.

Implement:

- Accept `guard.approval.resolve` jobs only when the job target matches the local grant, runtime grant, machine installation, workspace, and local request ID.
- Verify signed decision material before applying it.
- Reject stale local request claims.
- Treat Cloud action `allow`, `allow-once`, or equivalent approval as local approval.
- Treat Cloud action `block` and local status `blocked` as denial.
- Mark the local request resolved exactly once.
- Post the local daemon result to `/api/guard/commands/[jobId]/result`.
- Wrap result payloads as `{ data: ... }` if using the current daemon result schema.
- Include non-sensitive result metadata: local request ID, remote decision, daemon ack status, resume status, and resume completion timestamp when available.

Acceptance criteria:

- Approving in Cloud Review resolves the same local request on the device.
- Denying in Cloud Review blocks the same local request on the device.
- Stale, mismatched, already-approved, and already-denied requests do not create duplicate local effects.
- Portal delivery states can move through `queued`, `acknowledged`, `resumed`, `failed`, or `expired`.

Suggested local tests:

- `executor_resolves_local_approval_request`
- `executor_blocks_local_approval_request`
- Add stale claim, replay, duplicate result, and mismatched machine/workspace tests if missing.

Portal proof already passing:

- `__tests__/guard-review-decision-command-sync-targets.test.ts`
- `bun run guard:test:review-cloud-browser-decisions`

### HG-004: Resume Codex And Non-Codex Harnesses

Goal: after Cloud approval, the paused process resumes in the harness that created the request.

Implement:

- Codex requests should call the existing live-hook resume path first.
- If no live Codex hook can consume the decision, fall back to retry-based resume.
- Codex denial should return a denied-result resume state instead of silently resolving only the row.
- Pi and `oh-my-pi` requests should use a non-Codex harness resume path.
- Pi approval should mark the waiting operation `resumed`.
- Pi denial should mark the waiting operation `blocked`.
- Do not expose local resume tokens or secrets in Cloud result metadata.

Acceptance criteria:

- Cloud approval resumes Codex work when a live hook is present.
- Cloud approval falls back correctly when no Codex live hook is present.
- Cloud denial records an explicit denied resume state.
- `oh-my-pi` resolves through the Pi contract and is marked resume-capable.

Suggested local tests:

- `tests/test_guard_command_queue.py`
- `tests/test_guard_headless_daemon_api.py`
- `tests/test_guard_harness_contracts.py`
- `tests/test_guard_non_codex_resume.py`

### HG-005: Enforce Cloud Policies Created From Suggested Memories

Goal: when a user approves a Suggested Memory in Cloud Review, the created Cloud Policy syncs to local `hol-guard` and auto allows or blocks future matching actions.

Implement:

- Accept signed `guard-policy-bundle.v1` payloads from portal sync.
- Validate bundle version, hash, signature, expiry, workspace, and required `rules`.
- Preserve last-known-good bundle when a new bundle is invalid.
- Reject bundles for the wrong workspace.
- Convert exact `matcher.artifactId` rules into local exact artifact decisions.
- Convert `scope.locations` into workspace-scoped or project-scoped local decisions.
- Avoid converting workspace-scoped exact rules into broad harness-wide rules.
- Support allow and block actions from memory-created rules.
- Preserve source metadata enough to diagnose which Suggested Memory created the policy.
- Upload policy bundle acknowledgement receipts back to the portal.

Acceptance criteria:

- Matching exact artifacts auto allow or auto block locally.
- Non-matching artifacts still enter review.
- Matching artifacts in a different workspace do not match.
- Invalid bundles do not replace last-known-good policy state.
- Portal Policies can show synced daemon acknowledgement state.

Suggested local tests:

- `policy_bundle_exact_artifact_rules_apply_with_workspace_scope`
- `policy_bundle_validation_rejects_tampered_hash`
- `policy_bundle_validation_rejects_missing_rules_field`
- `sync_receipts_preserves_last_known_good_policy_bundle_on_invalid_update`
- `sync_receipts_rejects_policy_bundle_for_the_wrong_workspace`
- `receipt_sync_context_uploads_policy_bundle_acknowledgement`
- `sync_receipts_uploads_policy_bundle_acknowledgement`

Portal proof already passing:

- `__tests__/guard-policy-plane-service.test.ts`
- `__tests__/guard-policy-batch05-backend.test.ts`
- `__tests__/guard-policy-sync-ack-service.test.ts`

### HG-006: Emit Local Memory Decision Events

Goal: local approval/denial patterns should create Suggested Memories in the portal, and approved memories should become Cloud Policies.

Implement:

- Continue emitting local approval and denial decisions as `approval.memory_decision` events.
- Include stable `action_identity`.
- Include exact `decision_scope`.
- Include `harness_id`, `project_id`, `workspace_id`, and `decision_action`.
- Include concrete `command_display` and `command_raw` values when available.
- Avoid sending broad memory candidates from bare fragments such as `bash`, `rg`, `cat`, or `tool`.
- Use concrete behavior text, for example `rg TODO src/lib/file.ts`, not only `rg`.

Acceptance criteria:

- Repeated same-direction local approvals create an allow memory candidate.
- Repeated same-direction local denials create a block memory candidate.
- Conflicting approve/block decisions do not merge into one candidate.
- Inventory-only and pending decisions do not create candidates.
- Different commands remain separate candidates.

Portal proof already passing:

- `bun run guard:test:suggested-memory-patterns`
- `__tests__/guard-memory-candidate-rules.test.ts`
- `__tests__/guard-memory-candidate-repository.test.ts`
- `__tests__/guard-memory-candidate-identity.test.ts`
- `__tests__/guard-memory-candidate-generic-fragment.test.ts`

## Action Envelope Contract

- Local HOL Guard should continue sending exact shell commands in `raw_command_text`, `rawCommandText`, `command`, `command_text`, or `commandText`.
- Local HOL Guard should send action details in `action_envelope_json` or `actionEnvelope` when the stopped action is not a shell command.
- MCP action envelopes should include:
  - `action_type` or `actionType`: value containing `mcp`
  - `mcp_server` or `mcpServer`: MCP server display id
  - `tool_name` or `toolName`: MCP tool name
  - `resource`, `resource_uri`, `resourceUri`, `target`, `target_resource`, or `targetResource`: target resource when available
  - `args`, `arguments`, `input`, or `parameters`: full arguments when redaction is disabled
- Skill action envelopes should include:
  - `action_type` or `actionType`: value containing `skill`
  - `operation`: requested operation such as `install`, `load`, or `run`
  - `skill_name` or `skillName`: skill name
  - `source_path` or `sourcePath`: local or package source when available
  - `permission`, `requested_permission`, or `requestedPermission`: requested permission when available
- File envelopes should include `operation`, `path`, `access_mode` or `accessMode`, and `content_state` or `contentState` so Cloud Review can explain path access and whether content was included or redacted.
- Browser envelopes should include `operation` plus `url`, `origin`, `path`, or `selector`.
- Package envelopes should include `operation`, `package_manager` or `packageManager`, and `package_name` or `packageName`.
- Network envelopes should include `method` and `url`, `uri`, `endpoint`, `origin`, or `host`.
- Generic tool envelopes should include `tool_name` or `toolName` plus `args`, `arguments`, `input`, or `parameters`.
- Local HOL Guard should set `redaction_enabled` or `redactionEnabled` explicitly when it knows whether raw payload data is allowed in Cloud Review.
- If redaction is enabled, local HOL Guard should send redacted details in `envelope_redacted` or `envelopeRedacted`; Cloud Review will prefer those redacted envelope fields over `action_envelope_json`.

## Expected Cross-Repo Verification Commands

Run in `hol-guard` after local implementation:

```bash
pipx run uv run --extra dev python -m pytest tests/test_guard_command_queue.py tests/test_guard_queue_api_contract.py tests/test_guard_runtime.py -k "executor_resolves_local_approval_request or executor_blocks_local_approval_request or executor_syncs_policy_without_local_request_id or codex_resolution_sends_continue_prompt_to_original_thread or guard_run_headless_waits_for_local_approval_and_resumes"
pipx run uv run --extra dev python -m pytest tests/test_guard_runtime.py -k "policy_bundle_exact_artifact_rules_apply_with_workspace_scope or policy_bundle_validation_rejects_tampered_hash or policy_bundle_validation_rejects_missing_rules_field or sync_receipts_preserves_last_known_good_policy_bundle_on_invalid_update or sync_receipts_rejects_policy_bundle_for_the_wrong_workspace or receipt_sync_context_uploads_policy_bundle_acknowledgement or sync_receipts_uploads_policy_bundle_acknowledgement"
pipx run uv run --extra dev ruff check src/codex_plugin_scanner/guard/runtime/command_queue.py src/codex_plugin_scanner/guard/runtime/command_executors.py src/codex_plugin_scanner/guard/daemon/server.py src/codex_plugin_scanner/guard/runtime/runner.py
```

Run in `hol-points-portal` after local changes are available to guard-test:

```bash
GUARD_TEST_REVIEW_CLOUD_API_ONLY=1 bun run guard:test:review-cloud-browser-decisions
GUARD_TEST_REVIEW_CLOUD_API_ONLY=1 GUARD_TEST_REVIEW_CLOUD_LOAD=1 bun run guard:test:review-cloud-browser-decisions
GUARD_TEST_PORTAL_STDIO=inherit GUARD_TEST_REVIEW_CLOUD_SURFACE_ONLY=1 bun run guard:test:review-cloud-browser-decisions
bun run guard:test:multi-harness-live-sync
bun run guard:test:suggested-memory-patterns
bun run guard:test:teardown
```

## Local HOL Guard Changes Already Prototyped Or Expected

- `src/codex_plugin_scanner/guard/runtime/runner.py` now accepts policy bundle rules that contain workspace or project paths in `scope.locations` instead of dropping them before local policy conversion.
- `src/codex_plugin_scanner/guard/runtime/runner.py` now extracts exact `matcher.artifactId` values from Guard Cloud policy bundle rules.
- Exact artifact rules with `scope.locations` now create workspace-scoped local `PolicyDecision` rows so portal-created Suggested Memory policies can auto allow or block only in the intended workspace.
- Exact artifact rules without `scope.locations` now create artifact-scoped local `PolicyDecision` rows.
- Family matcher rules with `scope.locations` now create workspace-scoped `family:*` fallback decisions instead of broad harness-scoped decisions.
- Rule-level `expiresAt` now wins over bundle-level `expiresAt` when present.
- `tests/test_guard_runtime.py` now includes `test_policy_bundle_exact_artifact_rules_apply_with_workspace_scope`, proving portal-style exact allow and block policy rules are applied locally, non-matching commands do not match, and matching commands in a different workspace do not match.
- `src/codex_plugin_scanner/guard/runtime/command_executors.py` now calls `defer_request_resume_to_live_hook` after a signed `guard.approval.resolve` decision for Codex requests.
- If no live Codex hook can consume the cloud decision, `guard.approval.resolve` now falls back to `retry_request_resume`.
- Successful Codex cloud approval results now include `codexResume` in the command result so the portal can see whether resume is pending, sent, skipped, or already sent.
- Successful Codex cloud denial results now include the skipped denied-result resume state instead of silently resolving only the local request row.
- `src/codex_plugin_scanner/guard/daemon/server.py` now applies the same Codex resume handling to headless remote-once decisions.
- Headless remote-once Codex responses now include `codex_resume` and record `codex/thread_resume` events.
- `tests/test_guard_command_queue.py` now covers Codex live-hook resume, retry fallback, and denied-result resume for cloud `guard.approval.resolve`.
- `tests/test_guard_headless_daemon_api.py` now proves headless remote-once records Codex resume evidence.
- `src/codex_plugin_scanner/guard/harness_resume.py` now provides non-Codex harness operation resume handling for Pi/oh-my-pi.
- Pi/oh-my-pi allow decisions now mark the waiting guard operation `resumed`; deny decisions mark it `blocked`.
- Browser approval, headless remote-once, and cloud `guard.approval.resolve` paths now attach `harness_resume` or `harnessResume` for Pi without exposing resume tokens.
- `src/codex_plugin_scanner/guard/adapters/contracts.py` now marks the `pi` contract, including alias `oh-my-pi`, as `resume_support=True`.
- `tests/test_guard_non_codex_resume.py` now proves Pi gets `harness_resume` while still avoiding `codex_resume`.
- `tests/test_guard_harness_contracts.py` now proves `contract_for("oh-my-pi")` resolves to a resume-capable Pi contract.
- Portal `src/lib/guard/commands/command-repository.ts` now recognizes local daemon command results wrapped as `{ data: ... }`, matching `/api/guard/commands/[jobId]/result` schema.
- `scripts/guard-cloud/guard-test/modules/review-cloud-local-lease-assertions.mjs` now posts local daemon command results for leased `guard.approval.resolve` jobs.
- `scripts/guard-cloud/guard-test/modules/review-cloud-browser-decisions.mjs` now proves Cloud Review approve/block decisions lease to the local runtime, accept daemon results, and mark the same local request rows resolved.

## Portal Proof Added

- `__tests__/guard-review-live-query.test.ts` proves projected local `blocked_action` rows remain visible in `Blocked Now`.
- `__tests__/guard-review-live-query.test.ts` proves approved, denied, and `blocked` denial rows are hidden while unresolved terminal-like states such as `resolved`, `rejected`, and `cancelled` remain visible.
- `__tests__/guard-review-command-queue-loader.test.ts` proves multi-machine projected local requests survive the Review live filter.
- `__tests__/guard-review-command-queue-dedupe.test.ts` proves dedupe does not collapse same request IDs from different machines.
- `__tests__/guard-review-command-queue-visibility.test.ts` proves rows keep complete local targeting and status metadata.
- `__tests__/guard-review-live-empty-state.test.ts` proves distinct `Blocked Now` empty-state copy.
- `__tests__/guard-review-decision-command-sync-targets.test.ts` proves allow and deny command jobs carry exact target grant, machine, runtime, and workspace routing data.
- `__tests__/guard-review-decision-command-sync-targets.test.ts` proves already approved or denied requests do not create duplicate jobs, high-risk requests call the step-up gate, exact live request claims are used before legacy fallback, stale requests are rejected, and live request status marking waits until after the command job is queued.
- `__tests__/guard-review-live-delivery-state.test.ts` proves portal live item delivery state can represent queued, sent, acknowledged, resumed, failed, expired, and none.
- `__tests__/guard-action-envelope-display.test.ts` proves MCP server, MCP tool, Codex tool, skill, browser, file, package, network, unknown, malformed, and redaction-aware envelope payloads produce clear Cloud Review display text.
- `__tests__/guard-command-display-resolver.test.ts` proves typed command display states return kind label, summary, primary text, raw text, redaction state, source, and confidence.
- `__tests__/guard-raw-command-text-e2e.test.ts` proves redaction-disabled raw shell commands stay complete through projection and display resolution.
- `__tests__/guard-review-command-center.test.tsx` proves the live detail card uses the same command display state as Review rows and renders commands in a wrapping monospace block.
- `__tests__/guard-memory-candidate-rules.test.ts` proves repeated local approvals and denials become Suggested Memory candidates at the explicit threshold.
- `__tests__/guard-memory-candidate-repository.test.ts` proves Cloud and local approvals/denials contribute to the same workspace candidate while workspace and normalized identity boundaries stay isolated.
- `__tests__/guard-memory-candidate-identity.test.ts` proves candidate identity separates decision, scope, harness, project, workspace, and action matcher.
- `__tests__/guard-memory-candidate-generic-fragment.test.ts` proves plain generic fragments do not promote to broad Suggested Memory without concrete behavior text.
- `__tests__/guard-review-decision-service.test.ts` proves Cloud Review approval and denial decisions emit durable memory decision events.
- `__tests__/guard-review-decision-service.test.ts` proves approved Suggested Memories persist Cloud policy rules with `sourceDecisionId`, `sourceSuggestionId`, source receipt lineage, workspace, scope, expiry, and audit trail events.
- `bun run guard:test:cloud-decision-roundtrip` passed pending sync, approve, block, ack, reject, and superseded-status paths.
- `bun run guard:test:multi-harness-live-sync` passed 3 runtime actor and multi-harness concurrent sync coverage.
- `bun run guard:test:suggested-memory-patterns` passed repeated-decision candidate grouping and exclusion coverage.
- `bun run guard:test:review-cloud-browser-decisions` passed browser-rendered exact command proof, approve/block browser decisions, exact handoff preservation, local ack queueing, and local runtime lease proof.
- Latest `bun run guard:test:multi-harness-live-sync` passed with 3 runtime actors (`machine-cursor-0`, `machine-vscode-1`, `machine-codex-2`), 3 harnesses (`cursor`, `vscode`, `codex`), 30/30 concurrent sync events accepted, idempotency, event ordering, harness attribution, state consistency, and protocol v1 storage.
- Latest `bun run guard:test:suggested-memory-patterns` passed repeated same-direction approvals, single-decision exclusion, approve/block conflict exclusion, inventory-only exclusion, pending-decision exclusion, and separate command grouping.
- `bunx vitest run __tests__/guard-review-decision-service.test.ts __tests__/guard-policy-plane-service.test.ts __tests__/guard-policy-batch05-backend.test.ts __tests__/guard-policy-sync-ack-service.test.ts` passed 48 tests proving memory approval creates Cloud policies, Policies loader returns memory-created rules, signed bundles include the rules, and local daemon policy sync acknowledgements are recorded.
- `GUARD_TEST_PORTAL_STDIO=inherit GUARD_TEST_REVIEW_CLOUD_SURFACE_ONLY=1 bun run guard:test:review-cloud-browser-decisions` passed 11 browser-backed steps and captured screenshots for Blocked Now, Suggested Memory, and Policies under `.guard-test-artifacts/review-cloud-browser-decisions/1783551156695/`.
- The latest B091 screenshot proof recorded HTTP 200 for `/guard/review?tab=live-blocked-now`, `/guard/review?tab=suggested-memory`, and `/guard/policy`, with matched page text `pnpm deploy --workspace api --prod`, `Suggested memory`, and `Policy Studio`.
- `__tests__/guard-policy-plane-service.test.ts` proves the Policies loader returns memory-created `reviewDecisionRules` immediately.
- `__tests__/guard-review-outcome-flows.test.tsx` proves the Suggested Memory success state links to the created Cloud policy and exposes undo/revoke for persistent deny memory.
- `__tests__/guard-policy-batch05-backend.test.ts` proves signed `guard-policy-bundle.v1` payloads include memory-created rule metadata, matcher, normalized allow/block action, scope, bundle version/hash, expiry, and source receipts.
- `__tests__/guard-policy-sync-ack-service.test.ts` proves Cloud records synced daemon acknowledgements in policy audit history and shows per-device active bundle status.

## Local HOL Guard Proof Added

- `pipx run uv run --extra dev python -m ruff check src/codex_plugin_scanner/guard/runtime/runner.py tests/test_guard_runtime.py` passed on the touched local HOL Guard files.
- `pipx run uv run --extra dev python -m pytest tests/test_guard_runtime.py tests/test_guard_command_queue.py tests/test_guard_queue_api_contract.py -k "policy_bundle_exact_artifact_rules_apply_with_workspace_scope or policy_bundle_validation_rejects_tampered_hash or policy_bundle_validation_rejects_missing_rules_field or sync_receipts_preserves_last_known_good_policy_bundle_on_invalid_update or sync_receipts_rejects_policy_bundle_for_the_wrong_workspace or receipt_sync_context_uploads_policy_bundle_acknowledgement or sync_receipts_uploads_policy_bundle_acknowledgement or executor_resolves_local_approval_request or executor_blocks_local_approval_request or executor_syncs_policy_without_local_request_id or codex_resolution_sends_continue_prompt_to_original_thread or guard_run_headless_waits_for_local_approval_and_resumes"` passed 13 focused local HOL Guard tests.
- `pipx run uv run --extra dev python -m pytest tests/test_guard_runtime.py -k "policy_bundle_exact_artifact_rules_apply_with_workspace_scope"` passed 1 focused policy application test.
- `pipx run uv run --extra dev python -m pytest tests/test_guard_runtime.py -k "policy_bundle_validation_rejects_tampered_hash or policy_bundle_validation_rejects_missing_rules_field or sync_receipts_preserves_last_known_good_policy_bundle_on_invalid_update or sync_receipts_rejects_policy_bundle_for_the_wrong_workspace or receipt_sync_context_uploads_policy_bundle_acknowledgement or sync_receipts_uploads_policy_bundle_acknowledgement"` passed 7 focused bundle rejection and ack tests.
- `pipx run uv run --extra dev python -m pytest tests/test_guard_command_queue.py tests/test_guard_queue_api_contract.py tests/test_guard_runtime.py -k "executor_resolves_local_approval_request or executor_blocks_local_approval_request or executor_syncs_policy_without_local_request_id or codex_resolution_sends_continue_prompt_to_original_thread or guard_run_headless_waits_for_local_approval_and_resumes"` passed 5 focused approval, daemon resume, policy sync, and harness resume tests.
- `pipx run uv run --extra dev pytest tests/test_guard_command_queue.py tests/test_guard_headless_daemon_api.py` passed 139 local HOL Guard tests covering command queue and headless daemon API behavior.
- `pipx run uv run --extra dev ruff check src/codex_plugin_scanner/guard/runtime/command_executors.py src/codex_plugin_scanner/guard/daemon/server.py tests/test_guard_command_queue.py tests/test_guard_headless_daemon_api.py` passed.
- `pipx run uv run --extra dev pytest tests/test_guard_command_queue.py tests/test_guard_harness_contracts.py tests/test_guard_non_codex_resume.py tests/test_guard_headless_daemon_api.py` passed 167 local HOL Guard tests covering command queue, harness contracts, Pi non-Codex resume, and headless daemon API behavior.
- `pipx run uv run --extra dev ruff check src/codex_plugin_scanner/guard/harness_resume.py src/codex_plugin_scanner/guard/runtime/command_executors.py src/codex_plugin_scanner/guard/daemon/server.py src/codex_plugin_scanner/guard/adapters/contracts.py tests/test_guard_command_queue.py tests/test_guard_harness_contracts.py tests/test_guard_non_codex_resume.py` passed.
- `bunx vitest run __tests__/guard-command-complete-local-request-resolve.test.ts` passed 15 tests, including daemon `{ data }` result wrapper resolution.
- `GUARD_TEST_REVIEW_CLOUD_API_ONLY=1 bun run guard:test:review-cloud-browser-decisions` passed, including local runtime result acceptance and same-request local ack assertions for approved and blocked decisions.
- `bun run guard:test:teardown` was run after the guard-test validation and completed successfully.
- `scripts/guard-cloud/guard-test/modules/review-cloud-local-ack-fixtures.mjs` now reads local decision timing rows from `hol.guard_command_jobs` and `hol.guard_command_job_events`.
- `scripts/guard-cloud/guard-test/modules/review-cloud-local-lease-assertions.mjs` now asserts ordered timing chains for Cloud accepted time, command job availability, local daemon receive, local ack, lease event, and completion event.
- `scripts/guard-cloud/guard-test/modules/review-cloud-browser-decisions.mjs` now threads decision `receipt.capturedAt` into local timing evidence for both API-only and browser-backed paths.
- `GUARD_TEST_REVIEW_CLOUD_API_ONLY=1 bun run guard:test:review-cloud-browser-decisions` passed with ordered timing evidence for approve and block paths.
- `bun run guard:test:teardown` was run after the B033 guard-test validation and completed successfully.
- The latest B033 timing proof still shows the B034/B037 gap: local receive was `1103ms` for approve and `1277ms` for block in API-only local docker conditions because the fixture does not keep a persistent receive loop active while the decision is posted.
- `scripts/guard-cloud/guard-test/modules/review-cloud-browser-decisions.mjs` now opens bounded long-poll local receive leases before Cloud approve/block decisions are posted.
- `scripts/guard-cloud/guard-test/modules/review-cloud-local-lease-assertions.mjs` now fails the scenario when p95 Cloud accepted to local daemon receive latency is above `200ms`.
- `scripts/guard-cloud/guard-test/modules/review-cloud-browser-decision-assertions.mjs` now accepts `queued` or `leased` for pre-ack local daemon acknowledgement jobs because the long-poll receiver can lease them before the assertion reads the DB.
- `GUARD_TEST_REVIEW_CLOUD_API_ONLY=1 bun run guard:test:review-cloud-browser-decisions` passed with `receiveLatenciesMs=[98,172]` and `receiveP95Ms=172`.
- `bun run guard:test:teardown` was run after the B034 guard-test validation and completed successfully.
- `../hol-guard/src/codex_plugin_scanner/guard/runtime/command_queue.py` now renews the command queue receive loop immediately after empty long-poll responses when `GUARD_CLOUD_COMMAND_QUEUE_LEASE_WAIT_MS` is enabled.
- Local `hol-guard` still preserves exponential retry backoff for network, server, authorization, and not-configured failures.
- `../hol-guard/tests/test_guard_command_queue.py` now proves empty long-poll responses produce immediate receive renewal while existing error and OAuth backoff behavior remains unchanged.
- `pipx run uv run --extra dev pytest tests/test_guard_command_queue.py -k "immediately_renews_after_empty_long_poll or command_queue_loop_backs_off_after_errors or retries_revoked_oauth_auth"` passed 3 focused local tests.
- `pipx run uv run --extra dev ruff check src/codex_plugin_scanner/guard/runtime/command_queue.py tests/test_guard_command_queue.py` passed.
- Portal `src/lib/guard/commands/command-repository.ts` now adds non-sensitive command completion event metadata for daemon ack status, local request ID, remote approval decision, Codex resume status, harness resume status/harness, and resume completion timestamp when local `hol-guard` returns those fields.
- Portal command lifecycle telemetry now covers decision accepted (`receipt.capturedAt`), job created (`command.created`), job delivered (`command.leased`), daemon acked (`command.completed`), and harness resumed (`command.completed` metadata) without storing command text in telemetry metadata.
- `__tests__/guard-command-complete-local-request-resolve.test.ts` now proves the ack/resume telemetry metadata is written for wrapped daemon result payloads.
- `bunx vitest run __tests__/guard-command-complete-local-request-resolve.test.ts` passed 16 tests.
- `GUARD_TEST_REVIEW_CLOUD_API_ONLY=1 bun run guard:test:review-cloud-browser-decisions` passed after the telemetry change with `receiveLatenciesMs=[101,158]` and `receiveP95Ms=158`.
- `bun run guard:test:teardown` was run after the B040 guard-test validation and completed successfully.
- Portal `src/lib/guard/commands/command-repository.ts` now leases queued command jobs inside a transaction with `for update skip locked`, preventing concurrent local receive polls from colliding on the same oldest queued job.
- Portal decision receipt persistence now returns inserted receipt rows and defers latest-artifact refresh for non-persistent immediate local-daemon decisions, keeping local approval propagation out of the slower receipt-derived index refresh path.
- `scripts/guard-cloud/guard-test/modules/review-cloud-browser-decisions.mjs` now supports `GUARD_TEST_REVIEW_CLOUD_LOAD=1`, seeds 25 pending Review requests across 3 local machine actors and 3 harness IDs (`codex`, `cursor`, `oh-my-pi`), verifies all 25 are visible before decisions, and drives approval delivery through a daemon-loop lease/result model.
- `GUARD_TEST_REVIEW_CLOUD_API_ONLY=1 GUARD_TEST_REVIEW_CLOUD_LOAD=1 bun run guard:test:review-cloud-browser-decisions` passed with all 25 decisions leased, acked, and resolved locally; load latency evidence recorded `p50Ms=90`, `p95Ms=96`, `worstMs=97`, `machineCount=3`, `harnessCount=3`, and `requestCount=25`.
- `bun run guard:test:teardown` was run after the B042 guard-test validation and completed successfully.

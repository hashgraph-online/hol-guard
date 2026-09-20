# Native runtime technical contract review (RSP-024)

Status: source-bound reconciliation prepared against `124472b8949805e0dd36052df6894b335d8b519d`.
This document records current behavior and unresolved evidence. It does not enable a new route,
change runtime policy, qualify an installed distribution, or replace the final CODEOWNER review.

## Original requirement and precedence

The preserved [original PRD](https://github.com/hashgraph-online/hol-guard/blob/aba7420f54eaa658d0422f09b08767a030317de8/review-evidence/2026-09-19/pr2974-completion/originals/PRD.md)
already identifies Python Watch and availability handling in its current-state discussion.
Section 14 requires four separate results: the native evaluated decision, mode/posture
transformation, transport availability result, and delivered harness response. It explicitly
preserves existing product behavior unless a separate behavior change is accepted.
Section 15 requires obsolete fallback and authority claims to be marked superseded while
retaining their historical context. E12 defines rollback as restoring the prior tested native
route, without automatically restoring a Python hook evaluator.

The [original TODO](https://github.com/hashgraph-online/hol-guard/blob/aba7420f54eaa658d0422f09b08767a030317de8/review-evidence/2026-09-19/pr2974-completion/originals/TODO.md)
makes RSP-024 depend on RSP-016 (outcome attribution), RSP-021 (commit/retry boundaries),
RSP-022 (actual I/O ownership), and RSP-023 (independent expectations). An old manifest or a
passing string/schema check cannot establish these behavioral claims. The preserved documents
are recovered originals; they are not the inaccessible chat transcript.

There is no requirement conflict requiring a runtime change here. The older blanket failure
declarations conflict with current delivery code and with the original PRD's explicit account
of that code. This reconciliation limits those declarations; it does not weaken an existing
integrity denial, native floor, authentication check, or approval fence.

## Four separate results

| Layer | Meaning | What it does not prove |
|---|---|---|
| Native evaluated result | A validated Rust edge result bound to its request and current policy | What Watch or approval continuation ultimately delivers |
| Mode/posture result | Enforce/observe handling of that result; Watch can render a nonblocking warning | A new native evaluated allow |
| Availability result | The event-specific response when native review cannot complete | A successful evaluation, receipt, or Python semantic fallback |
| Delivered harness response | The concrete harness schema after the preceding steps | That a top-level `continue: true` allows a tool or its output |

A `native_resident` / `native_fail_safe` context marker is route attribution, not a typed decision
receipt. The receipt validator and request/policy binding remain separate requirements.
For a completed edge result, `HookWorker` records the validated native receipt before Watch
rewrites the presentation. Evidence must retain both outcomes; it must not rewrite the original
native receipt to match the delivered warning. Queue admission and persistence success remain
separate from native receipt production.

## Current event-specific availability contract

This table describes `availability_harness_response` and the named Cursor fallbacks at the
reviewed source, not every possible failure of every launcher. The renderer does not infer an
emergency-safe action from the payload. Its ordinary PreToolUse branch also covers high-impact
actions and nonlisted reason codes. `hook_reason_continues_session` is a separate helper;
its reason-code set is not an allowlist for this renderer.

| Event / boundary | Failure class | Current delivery | Native evaluation / receipt |
|---|---|---|---|
| PreToolUse, PreTool, before* | Ordinary native absence, not-ready policy, incompatible/invalid edge, overload, deadline, command-control-fence unavailability | Continue/allow with `policy_action=warn`, preserving the reason code | No evaluated allow or new receipt is manufactured |
| Same PreToolUse aliases | `invalid_hook_payload_reference` or `daemon_hook_queue_bytes` | Deny/block, including when `recording_only=True` | Integrity rejection remains separate from ordinary availability |
| PostToolUse / after* and observation lifecycle events | Native review unavailable | Observation/continue; harness-specific schema below | No successful scan or evaluated allow may be inferred |
| PermissionRequest / PermissionRequestV2 / CopilotPermissionRequest | Review unavailable | Permission-specific response; Copilot denies automatic approval without interrupting the turn | No approval consumption is proved |
| Cursor daemon/native fallback | Known before* event | `permission=allow`, exit 0 | Availability only; no native receipt |
| Cursor daemon/native fallback | afterShellExecution / afterMCPExecution | Empty JSON, exit 0 | Observation only |
| Cursor unparseable stdin | Before shell/MCP, other named before event in enforcement | `permission=deny`, exit 2 | Distinct parsing boundary, not the ordinary unavailable path |
| Cursor unparseable stdin | Recording-only, empty event, or beforeReadFile | `permission=allow`, exit 0 | Current special handling; not evaluated safety |
| Cursor unparseable stdin | afterShellExecution / afterMCPExecution | Empty JSON, exit 0 | Observation only |

For ordinary PreToolUse availability, Grok/Hermes/OpenClaw/Pi/OMP receive a top-level
`decision=allow`; the other renderer branches receive
`hookSpecificOutput.permissionDecision=allow` with `continue=true`.
Integrity failures use top-level deny for Grok/OpenClaw/Pi/OMP, block for Hermes, and nested deny
for the other renderer branches.

For observation availability, Grok receives empty JSON, Hermes/OpenClaw/Pi/OMP receive
`decision=allow`, and other branches receive `continue=true` and the event name.
For permission availability, Copilot receives `behavior=deny, interrupt=false`;
Pi/OMP receive allow/warn; Grok/Hermes/OpenClaw receive allow; other branches continue with the
permission event name without inventing a permission decision.

These are rendering branches, not claims that every named harness installs every event.
The existing ownership inventory retains partial/detection-only/unsupported routes.

## Modes, completed decisions, and authority

Unset or invalid `HOL_GUARD_NATIVE` selects `auto`. Auto accepts only the verified bundled
runtime; it ignores arbitrary binary overrides and never searches PATH or downloads a runtime.
Supported auto/force events use the native edge. Explicit `off` disables native execution;
ordinary disabled review follows availability handling and is not a Python semantic rollback.
Shadow/oracle surfaces require their existing explicit diagnostic/test admission and do not
become a production fallback.

A completed enforcement-mode native denial remains a denial. A completed PostToolUse block can
contain `continue=true` while also carrying `decision=block` and `model_output_action=block`;
continuing the conversation is distinct from releasing the output.
Watch can instead deliver allow/warn after a completed native block/review while preserving the
native result and its receipt. The availability renderer's `recording_only` argument does not
override the two designated PreToolUse integrity failures.

The native enrollment contract describes the external-authority challenge/signature/claim/consume
route. That route is not the implementation of every current hook approval continuation.
The current daemon also calls `pause_native_pre_tool_for_approval`, persists pending approval
records in `GuardStore`, and can accept a bounded, request/policy-bound local compatibility
reuse. Its command allowlist excludes Ollama; resolving a legacy approval does not authorize
an unknown Ollama executable. Noncommand native review has its own exact review-scope/ACK
binding. These facts do not prove general native approval consumption or authorize an expanded
compatibility allowlist. RSP-080 remains a separate unresolved native-consume obligation.

## Commit and retry boundaries

| Boundary | Current source behavior | Limit |
|---|---|---|
| Managed native connection | Pre-request unavailable failures may follow the explicit retry allowlist | Later owner/process death does not convert a fatal exchange into replay permission |
| Authentication and request | Original authentication budget and absolute caller deadline remain; authentication failures are fatal | A timeout is not evidence that the peer did not commit |
| Written request / response | Ambiguous writes and committed-response failures remain nonretryable | Do not transparently resend a request after a lost response |
| Snapshot publication | An in-call new-generation retry requires the specific validated ACK rejection; accepted ACK checks generation/digest/resident generation before opening readiness | A missing/malformed/mismatched ACK does not grant readiness |
| Native approval consume | Resident-memory claim/consume occurs before a successful response is delivered | An ambiguous delivered response does not permit replay |
| MCP forwarding | Final current-authority check precedes one write; transport failure aborts | This review does not claim every remote MCP continuation was exercised |

The current four-platform native packet
`b9bc69b80dfccb5c060a33909041c678361d32ed` binds source 124472 and reports full default Rust
workspace, Clippy, release and self-test success plus the focused managed/Unix deadline controls.
Those focused controls overlap full-suite counts. They do not prove installed-wheel transitions,
end-to-end latency distributions, native approval enrollment or rollback.

## I/O, independent vectors, and distributions

The I/O inventory includes the recording/configuration path. Background policy capture and
synchronous posture/configuration reads are different categories; a background publisher does
not prove that every caller avoids synchronous Python I/O. The ordinary raw native route uses
its acknowledged snapshot mode, while compatibility/delivery paths must retain their actual
caller inventory. An AST graph is bounded source evidence, not a whole-program or installed proof.

The independent qualification corpus separates native expectations, delivered expectations,
Watch and unavailable cases. Its validator tests verify evidence admission and refuse a wrong
route; they are not themselves native workload executions. The older native-hook-parity
`native-unavailable` block row and the old fail-safe matrix remain historical declarations,
not current delivery oracles. Existing native floors and independently specified malicious and
benign outcomes remain required.

The original performance acceptance remains unchanged: preserve timing boundaries and per-platform
distributions; do not pool dissimilar platforms/workloads, omit failures, redefine cold/recovery,
or use a source test count as latency evidence. The required campaign sizes, repeated runs,
confidence method, resource measurements, and before/after comparisons remain in the original PRD.

## Distribution and rollback evidence still required

The supported wheel builder starts from the verified `hol-guard` wheel, injects the runtime and
manifest, recomputes RECORD and applies the platform tag. Desktop staging binds version/target,
refreshes runtime identity after signing, and verifies the frozen sidecar. These are source
capabilities. A universal Python wheel's installability does not grant a production Python hook
semantic fallback on an unsupported native platform.

Rollback for this program means reinstalling/restoring the prior tested native artifact for the
affected scope, with current authority and policy state revalidated. `HOL_GUARD_NATIVE=off`,
reverting a source import, or restoring an excluded file is not an installed native rollback test.
The retained Python oracle is a test/reference surface.

At this review, no current-124472 installed wheel/desktop upgrade-and-rollback cohort is admitted.
Older 8f paired evidence retains its failed cleanup/retirement and receipt-gap results; separate
launcher/corpus successes do not cure those failures or transfer qualification to 124472.
Required review evidence remains: exact artifact and installed-member identities, admitted
platform/harness routes, actual distributions and resources, loss accounting, prior/candidate
transition behavior, containment, policy/key/approval continuity and actual rollback outcomes.
Use the existing original acceptance for each scope; no additional release gate is introduced here.

## Verification scope and review state

`tests/test_native_runtime_delivery_contract.py` exercises the real current renderers with
independent expectations for availability, integrity, permission, completed block and Watch-copy
behavior. It does not invoke a native producer or assert installed qualification. Existing route,
receipt, native corpus, ownership and native deadline controls retain their separate responsibilities.

RSP-024 has a source-bound technical review and concrete reconciliations. It remains open for the
identified distribution, rollout/rollback and complete authority evidence. Final review of the
actual last push by the required CODEOWNER is a separate human approval; this document grants none.

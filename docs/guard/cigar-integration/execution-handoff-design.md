# Execution handoff implementation notes

Status: native SDK preconditions and the [optional native captured-Bash adapter](native-execution-context.md) are implemented locally. Four actual SDK/owning-executor tests now pass; broader regressions and matching installed qualification remain in progress. The latest installed product qualification remains `8fccb141`. Owner tests do not establish installed or external app delivery.

## Existing execution authority

Guard's captured-Bash route already provides the relevant owning executor on macOS. `native_exact_action_op/bash_route.rs` prepares a captured subject and artifact hash, then handles an authenticated execution request. `bash_grant.rs` repeats capture, checks the actual context, obtains a current policy fence, binds the exact subject and uses the operation journal. `bash_launch.rs` releases the held source/image through the native launch barrier. These authorities and [both approval choices](../approval-invariant.md) must retain their existing behavior.

The prepare protocol supplies review evidence and has no execution operation ID. Execute carries a logical operation ID and optional tool-call ID; the journal can allocate a distinct physical invocation. A CIGAR effect ID therefore needs an explicit native association with the actual journal invocation. Passing a caller-provided label through the SDK is insufficient to prove this association.

`edge::execution_intent_digest` commits to the validated tool intent and relevant host environment. It deliberately excludes policy generation for retry binding. It does not prove the eventual executable's bytes. The captured subject/artifact binding supplies that separate proof. Neither existing hash should change merely because assistance is enabled.

## SDK boundary

The approved CIGAR 0.14.1 broker advertises `execution_handoff.v1`. Its public operations are:

1. A scoped client submits the exact draft under its live context ticket.
2. The host retrieves the submission and independently reviews the complete claim set.
3. `check_answer` reports the content draft digest and assessment.
4. `bind_execution` commits to that submission, current source authority, host review/policy, effect ID and semantic intent digest.
5. `take_execution_handoff` rechecks and consumes once. It does not send the effect, approve a Guard command or hold a lock across the later send.

The submission ID is a fresh nonce; the assessment's draft ID is a content digest. Retain and compare both. An identical resubmission can invalidate the earlier binding even when its text is unchanged. Keep SDK version strings lossless.

Native library wrappers retain tickets and complete binding bytes privately. The bound handle has no public serialization, deserialization, cloning or debug output. Taking consumes that Rust handle even on error. Public metadata reports a context observation with `approval_grant:false` and `dispatch_confirmed:false`; it omits tickets, submissions, secrets and intent digests. A discarded successful SDK take cannot be safely repeated. Real effect uncertainty must be reconciled against Guard's actual operation journal.

Native code validates bounds, source/citation membership, host review shape, identities, current generations and replies. Python forwards public SDK calls and content-free error codes only. Host reviews must come from current trusted native/human authority. Agent-generated text cannot review itself. Fixed native observations can be supported by exact native evidence; free-form model claims need independent review.

## Product integration requirements and implementation

The local adapter now implements the separate disabled preference, private memory broker, prewarmed client, bounded optional stage, actual captured intent/artifact commitment, journal invocation association, atomic revocation/liveness checks and private observation panel described below. Treat the remaining items as acceptance requirements; source implementation alone does not qualify every route or boundary.

- Add an independently disabled execution-context preference with truthful platform/route availability. Propagate it through native configuration/restrictions, Python projections and TypeScript together. Keep a separate actual SDK doctor result and real executor qualification; a broker capability string cannot qualify a delivery route.
- Support a private memory broker when this feature needs the broker API. Do not force saved storage or agent sharing. Current memory broker opening requires explicit sharing, while private SQLite is already separate; extend that native boundary deliberately.
- Mint a native prepared-execution reference from actual capture. Bind its host/workspace/harness, existing tool intent, exact captured artifact and finite lifetime. Derive the SDK intent commitment from the real native intent and preconditions. Keep raw commands, environment values and private capture descriptors out of SDK context and ordinary diagnostics.
- Associate a native-minted context effect ID with the real journal invocation. Account for logical operation aliases, new tool-call IDs, already completed operations and uncertain retries. A context binding cannot substitute for the journal or saved approval.
- Prepare context on the optional control lane before execution. Perform SDK take on the explicit executor control plane with a short bound. Keep SDK calls/imports, source scanning and waits out of the synchronous hook path and outside native state/policy locks. An already approved action must continue through its native route when optional context is unavailable, stale, revoked or uncertain.
- Pass a native freshness witness to the actual launch boundary. It must check the current service/scope generation, permission, expiry, current cited source basis and exact native artifact/intent. It performs no SDK RPC there. Failure drops the optional association while preserving native authorization. Record when checks happened and the remaining send-boundary uncertainty.
- Keep per-execution facts private to their own views. Replacing the shared `guard:action` source for each parallel action would invalidate other clients' contexts. Prefer bounded per-execution native sources/views and explicit cleanup. Extend native/UI citation validation consistently if a new source identity is required.
- Bound execution contexts and private clients within the existing global SDK-client/queue/resource limits. Account for operator and ordinary agent clients. Resource exhaustion produces an honest optional-context outcome and leaves ordinary Guard execution available.
- Store only allowlisted association/observation metadata in a separate native sidecar or independently versioned projection. Preserve mandatory executor reply validation and existing approval payloads. Show prepared, checked, dispatched and completed states according to their actual native sources.

The integration point must be chosen after inspecting the complete launch-fence and journal contracts. The optional stage may not keep a policy/state lock while waiting for CIGAR. Any returned freshness witness must be native-owned and revocable without an actor round trip at launch.

## Mutable source currentness investigation

An actual macOS test disproved a proposed kqueue/metadata witness. Ordinary writes, atomic leaf replacement, ancestor rename, symlink replacement, hard links and expiry were detected, but an already mapped file changed through shared `mmap` before flush or close without a vnode event or a metadata change. The test failed as required. The proposed production witness and its dependency feature were removed; no `is_current` API based on those observations is shipped. [The disposable probe](../../../scripts/ci/cigar_source_currentness_probe.py) reproduces the boundary without reading user documents. Its output reports observations rather than asserting a universal filesystem guarantee.

Consequently, launch-time handoff must not claim that mutable workspace documents or notes remain byte-current merely because notifications are quiet. Full protected reads before SDK bind/take still establish their recorded check times, and remain useful for review/context retrieval. They cannot prove the later send boundary without further source ownership or a content read there; potentially blocking file reads under the native policy mutex are unacceptable.

The initial real executor association should therefore use a separate private view containing only fixed native facts from its actual captured subject, tool intent and admitted policy. It must not include mutable workspace documents, shared notes or receipts in that execution precondition. The actual executor compares the existing captured artifact and policy again under its normal launch fence, while native atomic service/scope fences reject revocation and expiry without an SDK or actor wait. Documents can continue informing independently timestamped review briefs. This is an explicit source qualification limit, not qualification of arbitrary document currentness or a reason to block a native-approved command.

Native process-local epoch fences now invalidate on service reconfiguration, Stop, shutdown, scope context reset and owner drop. They cannot be serialized or restored and permanently refuse saturation. They are foundation for the adapter; their presence alone does not establish real executor delivery.

## Acceptance still required

Use an actual installed Guard executor and the exact approved worker. Demonstrate both Allow once and Always allow, identical saved-approval reuse, changed captured code/intent, source changes, changed reviewer/policy, revocation, opt-out, missing/wrong Python, unavailable worker, full restart, repeated invocation and lost consume/send/acknowledgement outcomes. Show that a supported native command still runs under its existing approval during every optional-context fault.

Retain exact source/artifact identities and distinguish SDK-only, native executor, installed HTTP/CLI and actual external harness evidence. The previously reproduced hardened-helper failures remain unqualified; selecting a verified captured-Bash subset must be explicit. Complete feature-on/off hook contention, all-worker RSS, useful reuse, accessibility/setup and final release checks from the [full goal](EXECUTION_GOAL.md).

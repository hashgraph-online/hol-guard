# Native last-good rollback and completion recovery

The live controller now supports explicit rollback through the same background preparation and cutover engine as switching. It also preserves a published target when final journal acknowledgement fails. These are local P6 milestones. [Automatic source restoration](CIGAR_SOURCE_RESTORATION.md) now has separate saved/memory SDK acceptance for known unpublished failures; full P6/P9 qualification remains required.

## Explicit rollback

`Service.prepare_rollback` chooses the runtime from the authenticated last-good selection. It requires the expected current Service generation and an idle lifecycle journal. A nonterminal prior transaction must be reconciled before another preparation begins. After verification, the target's complete measured installation/approval/producer/origin identity must equal last-good. A matching opaque ID alone is insufficient.

Rollback takes its data from the current serving actor. It captures the current reviewed vector, current source/policy/app intent and readonly history. Saved mode builds a fresh producer-bound generation; memory mode uses the proven in-memory handoff. It never selects the last-good data pointer as a substitute for current reviewed data. This preserves edits and removals made after upgrading.

The existing explicit reconnect acknowledgement, semantic/source/settings/policy checks, native epoch revocation, old-actor cleanup acknowledgement and journal/config publication remain shared. Fresh SDK state is built alongside the currently serving actor. Feature/data differences still require a separately supported explicit choice; current implementation only preserves the effective preferences while changing runtime ID and refuses unsupported differences before cutover.

The native request has an optional rollback flag. False is omitted when serializing and defaults for older records, preserving exact legacy switch request bytes and fingerprints. The rollback flag creates a distinct idempotency intent. Retrying a completed rollback returns that original job even though last-good now points back to the other runtime.

## Completion acknowledgement

The journal records target health before attachment, and records Completed/last-good after the native Service attaches the actor. A native publication flag distinguishes a serving target from an unpublished failed candidate. Errors after attachment require metadata reconciliation; they never authorize cancelling the serving SDK or deleting its data.

`Service.reconcile_switch` cannot start an SDK or reconstruct scopes. An authenticated Completed transaction can finish matching historical job metadata. A Healthy transaction requires an actual current target actor, matching settings/generation, fresh artifact and health checks, and an exact measured SDK/data pointer. Reconciliation preserves actor, epoch and preference bytes and performs no SDK mutation replay. Cancelled/failed progress cannot be rewritten into success through the ordinary progress writer.

## Evidence

Both actual scenarios use finalSDK0.14.1, a v1-enrolled source, a test-only qualified exact-wheel target and external CPython3.14.7/3.14.10. They upgrade, change reviewed data, then explicitly return to the earlier interpreter/SDK installation using current data. Complete reviewed-note digests and original expiry survive; the deliberately removed original note does not return. Existing scope IDs remain while old SDK contexts/agents/epochs remain revoked. The memory case also preserves the second app's complete vector and original times, with no saved-evidence store.

The saved-mode test makes the lifecycle journal read-only after attachment. Context queries still succeed while the journal is Healthy; last-good is not yet promoted. After restoring write access, reconciliation completes the journal and job with the same actor, epoch and config bytes. Wrong-generation recovery refuses. An inactive-Service unit case proves that stored recovery metadata never starts a process or creates grants.

Executing native image c7b054f122dd5a7169303334de865a3e46c4cdb7f5fce9137b74a1bfd139a8be covers both actual round trips. Native selection/policy/privacy/progress/rollback29 and Service11 tests pass; the two SDK cases are separately executed. Production Rust1.88, context Clippy with existing scanner/freshness warnings, CI formatting and authority/I/O/privacy gates pass. Full native Clippy retains36 hash-verified unchanged baseline errors and zero new errors.48 production unused-entry warnings remain visible while public switch/rollback/reconcile routes are not yet exposed.

These are same-SDK data/controller round trips, not original-b47380 or genuine newer-SDK, managed-interpreter end-to-end, installed/frozen or all-platform acceptance. Finish every process-loss/cleanup/Stop boundary, retained-generation source restoration, durable erasure and retained-copy privacy, inactive-data/lineage/capacity and feature/data transitions. Complete P7/P8 controls/catalog/policy/UI and P9/P10 qualification before claiming the full objective. The unbudgeted P0–P10 goal remains active.

[Evidence](evidence/receipts.json) binds source hashes, exact images and raw logs. Original acceptance/log, live profile/hooks/preview, upstream SDK sources, system Python, Guard approvals and Git staging/history remain untouched.

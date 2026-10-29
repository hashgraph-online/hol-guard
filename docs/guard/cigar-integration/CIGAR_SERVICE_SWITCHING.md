# Native live Service switch coordinator

This local P6 milestone prepares an inactive replacement beside the serving CIGAR actor and commits it through the native selection owner. The full upgrade objective remains active. Public prepare/commit controls are deliberately not exposed while rollback and privacy work remain unfinished.

## Native flow

`Service.prepare_switch` requires an enabled, verified actor, its current generation and a distinct installed runtime. It acquires the same profile lease as SDK/interpreter preparation. Native requested/effective policy snapshots cover both the current runtime and a hypothetical runtime-ID-only target; preparation changes no preference bytes. Strict durable job IDs, request fingerprints, a shared 32-record quota, a 120-second deadline and request-bound cancellation markers provide progress and idempotency. Stored progress cannot recreate a worker or authorize a commit.

The background worker measures both installed identities, verifies the actual target SDK/features, captures currently granted app/workspace intent, prepares reviewed data and constructs fresh target SDK state. The source keeps serving. Only a live Ready worker accepts a commit for its original generation, with explicit acknowledgement that SDK contexts and agent sessions must reconnect.

Cutover rechecks current settings/policy, config write permission and target artifacts. It pauses source admission at the bounded native boundary, compares current scope/source/reviewed-data semantics, and transfers the latest bounded readonly history and receipt facts to the private target. The native epoch, observations and execution readiness are revoked before stopping the source. The old actor must acknowledge cleanup before the journal/config commit. The verified target becomes the serving actor only after the coupled SDK/data selection and health publication succeed. History preserves original timestamps/producers; SDK clients, contexts, credentials and agent sessions are fresh.

Cancellation and final publication compete for a single atomic transition. Cancellation that wins prevents publication. Once publication wins, a late job Cancel cannot set the target SDK's cancellation flag. Stop and ordinary incompatible settings changes still revoke runtime authority. A cutover fence defers the coordinator's own source/target setting observations without deferring Stop or unrelated CIGAR setting changes.

Unknown config or journal acknowledgements require authenticated reread and exact config inspection. The coordinator never blindly repeats a publication after an uncertain result. An external edit after an uncertain commit is preserved. Known readonly/ACL failures are checked while the old actor still serves, and publication repeats the actual checks.

## Cleanup and privacy boundary

Ready-copy cleanup requires the native lifecycle lease, owning request and authenticated selection. It protects current/last-good/in-flight data and transitive unmapped parent generations. Actual cache and SQLite ownership checks run again before deletion. SDK/Python/switch jobs share ID and quota checks; read-only inspection no longer creates an installation registry after explicit data removal.

Authenticated privacy/access-reducing operations first cancel and drain an in-flight preparation, with a bounded cleanup wait. This is only the coordination prerequisite: per-scope erasure across every retained copy, durable interrupted-erasure reconciliation, complete cleanup-pending recovery and all Stop/cutover races still need implementation/qualification.

## Evidence and limits

The actual SDK test uses final0.14.1 bytes, an explicitly v1-enrolled source, a test-only qualified exact-wheel target and external CPython3.14.7/3.14.10. It cancels one Ready copy, verifies its data was removed while the source remains active, then switches another copy through the live Service and real native config/journal. The source served257 requests during target preparation. Reviewed notes and the final readonly history survive; the old actor acknowledges cleanup, its native epoch becomes stale, old contexts/agents are absent, last-good is recorded and late cancellation leaves the target ready. This is not original-b47380 or newer-SDK qualification, nor a broad latency/availability guarantee.

Context tests79, native switching/policy/privacy/job tests24, Service tests11, preparation29, registry12, settings19 and off-state repair6 pass. Context has13 separately gated SDK cases and preparation has4; the new live Service case was explicitly run. Production Rust1.88 check, CI formatting and authority/I/O/privacy gates pass. Full native Clippy still reports36 errors in byte-verified unchanged baseline sources and zero new errors. Its production entry points remain unexposed, with42 unused-entry warnings visible rather than suppressed.

[Memory-only reviewed-note transfer](CIGAR_MEMORY_NOTES.md) now has separate actual SDK acceptance. [Explicit last-good rollback and published-target completion recovery](CIGAR_ROLLBACK_RECOVERY.md) now use the live controller and have actual saved/memory acceptance. [Automatic source reconstruction](CIGAR_SOURCE_RESTORATION.md) now covers known unpublished failures with exact settings/policy/ownership checks, fresh authority and independent bounded restoration cancellation. Retained-generation restoration, all failure/cleanup/process-loss boundaries, accepted feature/data changes and lineage/capacity handling remain required. Complete P7/P8 operator/CLI/HTTP/UI/update-policy/catalog work and P9/P10 real/installed/frozen/platform/approval/transport/performance acceptance before claiming the full objective.

[Evidence](evidence/upgrades-live-service-switch-20261027.json) binds exact source hashes, the actual SDK image, later fault-injection image, passing and development-failure logs. No production catalog qualification, live profile/hook/preview, system Python, upstream SDK source, Guard approval or Git history was changed.

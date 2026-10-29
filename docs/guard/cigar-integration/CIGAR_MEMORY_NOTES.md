# Memory-only reviewed notes during a CIGAR switch

The native live Service can now carry reviewed memory-only notes to a replacement without enabling saved evidence. This extends the [live switch coordinator](CIGAR_SERVICE_SWITCHING.md); it does not complete rollback, privacy recovery or the public operator workflow.

## Handoff contract

Only the native actor's currently granted scopes can request capture. The transfer value has private fields, no Serde/request deserializer and no durable recovery format. Its constructor requires an actual verified SDK domain and checks that the domain uses memory, is a sharing domain, is not a private execution domain and is not restored from saved storage. Native cached documents, version and basis must match the actual SDK digest and reviewed-proposal provenance. Producer identity still binds the exact SDK/profile/dependencies and complete interpreter identity. Matching version labels cannot substitute for those checks.

Target import requires the current native app/workspace namespace, a fresh memory broker with an empty notes revision, the qualified target producer and freshly admitted source content matching every dependency digest. It uses the existing SDK source API; no SDK client, context, credential, session or execution handoff is copied. The native vector remains bounded by32 notes and16 KiB per scope. Ordinary SDK/domain retention and source limits continue to apply.

The SDK's original observation time and valid-until time survive. Target retention can narrow that deadline using the original observation time; it never starts a new retention period at installation or switching. History separately retains original SDK/producer labels and timestamps. A transfer describes the exact current data producer, not a new human review or command approval.

The engine uses the same native semantic boundary check for saved and memory data. A newly reviewed edit after Ready invalidates the earlier candidate; the old actor remains available. A fresh preparation includes the latest reviewed vector. Prepared memory values and target brokers stay private, and cancelling the job closes the candidate without creating saved-evidence generations.

Saved transfers retain their existing exact native slot/storage checks. The common SDK content/provenance and fresh-source checks are shared with the memory path, while each path retains its own storage requirements. Memory mode never uses a fabricated disk manifest.

## Actual SDK acceptance

The final0.14.1 SDK case uses a v1-enrolled source and a test-only qualified exact-wheel target across external CPython3.14.7/3.14.10. It exercises two separately granted apps. A Ready candidate is cancelled, a later Ready candidate is refused after a newly reviewed edit, and a fresh candidate switches through the live native Service/config/journal. The source keeps its epoch and actor after cancellation/refusal, and serves148 requests during the final preparation.

After switching, SDK-verified canonical full note digests, counts, app/workspace namespaces, observation times and expiry match the latest source values for both apps. Query-specific retrieval and negative cross-app marker checks pass. No saved-evidence or evidence-generation directory is created. The old native epoch is revoked, a context proven usable immediately before cutover is refused on the target, the original authorized agent session is absent, current/last-good selection is correct and late Cancel leaves the target ready. Executing native image58a3f7f8e081e1dbbccb033ef561536187d9ac715b5e9fc4756164dc7c7c7792.

The SQLite scenario also passed after the shared provenance refactor, serving267 requests during preparation and preserving reviewed notes/history while removing a cancelled Ready generation. Its imageb69ad3291196c592fd7c677f423b95d53caf7aa6e3b7f8ee93f0d838ee3e8af9 predates only the memory fixture doctor correction, complete-content metadata getter and stronger memory assertions; SQLite behavior is unchanged.

Context79 pass on stable and Rust1.88 (13 SDK-gated cases), and native Service11 pass (both new actual cases were separately executed). Production Rust1.88 check, context Clippy with the existing scanner/freshness warnings, CI formatting and authority/I/O/privacy gates pass. Full native Clippy retains36 errors in hash-verified unchanged baseline sources and zero new errors in its recorded audit. The final getter is pure metadata and separately passes context Clippy. There are43 visible production unused-entry warnings because public prepare/commit routes remain unexposed.

Retained development failures include internal validator visibility, a fixture that requested a SQLite doctor in memory mode, and a rendering assertion that incorrectly required every query to return every note. The final test replaces that last assumption with complete SDK-proven vector digests for both apps, plus relevant retrieval and isolation checks. No original acceptance assertion, SDK deadline or mutation-retry policy was weakened.

[Explicit memory rollback](CIGAR_ROLLBACK_RECOVERY.md) now preserves latest reviewed data, removals, both app vectors and original expiry through the live Service; it creates no saved-evidence store.

## Remaining work

Known pre-publication failure after source shutdown can still require recovery. Finish safe automatic restoration, comprehensive cleanup-pending/process-loss recovery, durable erasure and per-scope deletion across retained copies. Complete inactive-data/lineage/capacity and feature/data transitions, P7/P8 native/CLI/HTTP/UI/catalog/policy controls and P9/P10 installed/frozen/platform/approval/transport/performance qualification. No original-b47380 or genuine newer-SDK, private-interpreter end-to-end or all-platform qualification is claimed here. The full unbudgeted P0–P10 goal remains active.

[Evidence](evidence/upgrades-memory-service-switch-20261027.json) records exact sources, images, passing and development-failure logs. No production catalog qualification, live profile/hooks/preview, upstream SDK source, system Python, Guard approvals or Git staging/history was changed.

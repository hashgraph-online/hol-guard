# CIGAR committed disabled-selection recovery

Status: locally implemented and checked 2026-10-28; partial P6/P7/P9. [Evidence](evidence/upgrades-disabled-recovery-20261028.json) binds the current sources and native test image. The complete P0–P10 objective remains unfinished.

The exact-settings limitation for Committed/Healthy targets below is superseded by [Stop-aware recovery](CIGAR_STOP_RECOVERY.md), which also supports previously live targets after Stop. CommitIntent and initial-selection requirements remain strict. The earlier receipt retains its original source/image scope.

## Supported recovery

An explicit recovery request can now finish a previously committed selection or rollback while CIGAR remains disabled, including a journal left at CommitIntent after the target configuration was written. The original transaction, job, SDK/data identities, raw settings, update rules and current authority generation must match. A disabled selected target capsule contains no SDK eligibility or source/app authority. Live-selected committed transactions and other process-loss phases remain outside this checkpoint.

The shared initial/disabled verifier runs a bounded temporary SDK worker with a fresh 120-second attempt. It measures the target installation against the captured identity, closes the temporary process, then rechecks cancellation, settings, prepared data and ownership before completing health and last-good metadata. Recovery does not write preferences, data generations or grants and does not publish a serving actor. A repeated request while the same attempt is live returns that attempt. A later explicit attempt renews its cancellation nonce; an old cancellation cannot veto it.

Startup retention briefly holds the evidence metadata lock. Only the initial read-only snapshot retries the exact context-busy result, for a fixed monotonic 200ms budget before writer acquisition, job admission or SDK work. Other errors return immediately. This is not automatic retry of an SDK action or an unknown write outcome.

The target still requires the exact recorded post-commit configuration hash. A later Stop or unrelated configuration edit can therefore refuse recovery while preserving the newer settings and off state. Narrowing-aware recovery, live-selected/rollback recovery, unavailable-source choices and the full operating-system process-loss matrix remain required.

## Consistent job completion

SDK preparation, Python preparation, catalog refresh and switch status now reload persisted job metadata after observing that a local worker has finished. The earlier cached Publishing snapshot paired with worker-running false was a real inconsistent view; a deterministic paused-fetch regression now covers it. This is metadata consistency, not evidence of SDK eligibility or permission to activate.

## Verification

The current native test image is `6c98cbd610e6b1b76bc04a1e8559d8b23874297e078e7db9c51b71602b9e82ff`. Registry/lifecycle tests pass143 with5 actual-SDK tests gated; service tests pass21 with20 SDK tests gated; configuration tests pass57 with1 helper ignored; off-data tests pass10. Rust1.88 checks, formatting, authority ownership, I/O ownership and privacy gates pass. Clippy retains36 baseline errors in23 hash-verified unchanged files, with zero new errors; it is not globally green.

Five actual final-0.14.1 SDK workflows pass on this same native image: committed disabled recovery/cancel/retry; initial recovery; initial selection; disabled selection and rollback; live selection and latest-data rollback. They use task-owned profiles, external CPython3.14.7/3.14.10 and the same approved final SDK on local macOS ARM64. The new case recreates Service within the same process, not an operating-system crash. It proves reviewed note digests/expiry and off-state preferences survive recovery and that separate enablement and fresh grants are required. It does not prove the older candidate, a real newer SDK, other platforms or installed/frozen HTTP operation.

Two earlier failures remain bound to their original images and logs. The registry run failed140/1 because of the stale completion snapshot, corrected with the deterministic regression. The first new SDK recovery run failed on startup metadata contention; the bounded read-only snapshot change and later passing run do not constitute load/performance qualification. Earlier integration broker/transport load and initial workspace timeout observations remain open.

Frontend comparison also normalizes the known optional execution_context default: absent and false are equal; true remains distinct. The merge and routing assertion modules pass. Strict checking retains the same13 prior shared diagnostics and no new ones. Fourteen intercepted-API browser checks pass, including pending-edit preservation, actual utility styles and390px layout. These browser fixtures are separate from native SDK acceptance.

All seven approved SDK/interpreter inputs are rehashed unchanged. The original84 dirty paths retain75 byte-identical files, seven exact inverse-patch-preserved workspace/tutorial files and the two previously recorded intentional differences. Lockfiles, original acceptance and Git HEAD/branch/staging/history remain preserved. No live Guard, hooks, preview, system Python, upstream SDK or publication changed.

## Remaining work

Complete narrowing-aware Stop/settings recovery, live-selected/rollback and remaining durable phases, true process-loss qualification, unavailable/withdrawn-source and native initial/clear/reset/data-choice routing, inactive legacy scopes, removal/retention, notification delivery, accessibility and the remaining P9/P10 real release, installed/frozen, platform, approval, cleanup, load/performance and maintainer-bump evidence. Production catalog trust/feed/qualification is still an external prerequisite.

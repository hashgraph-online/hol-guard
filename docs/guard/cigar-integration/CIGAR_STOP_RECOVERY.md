# CIGAR recovery preserves a later Stop and current settings

Status: locally implemented and verified 2026-10-28; partial P6/P7/P8/P9. [Evidence](evidence/receipts.json) binds current sources and checks. The full P0–P10 goal remains unfinished.

## Current disabled intent wins

Explicit recovery can finish an authenticated Committed or Healthy target after a later Stop or other valid settings save. This includes a previously live switch whose recorded activation intent is now superseded by Stop. It preserves the original immutable job/request hash and sealed source/target SDK/data pair. Recovery snapshots current requested/effective disabled preferences, update rules, home identity, prepared data and authority generation; it does not reconstruct the earlier preferences or source/app authority.

The same bounded native verifier serves initial, disabled and stopped-live targets. It privately re-verifies the exact installation and required features, checks cancellation and current settings/data again, measures and closes the SDK, then completes health/job/last-good metadata. It attaches no serving actor, writes no preferences/data generation/grants, and offers no switch/commit handle. A new explicit attempt has a fresh120-second nonce/budget. Current settings, generation, policy or selection changes after admission invalidate it. A repeated live request converges on the same attempt.

| Durable phase and current state | Supported behavior |
| --- | --- |
| Initial committed target | Existing bounded initial verifier; its exact-settings and empty-data proof requirements remain. |
| Selected CommitIntent | Still requires exact written target settings; an uncertain write is not assumed complete merely because later settings exist. |
| Selected Committed, currently disabled | Verify the sealed selected target against current disabled settings; preserve all newer settings. |
| Selected Healthy, disabled with newer settings or formerly live | Re-verify under current disabled settings, then finish metadata. |
| Selected Healthy, originally disabled and exact unchanged settings | Existing metadata-only completion; no new SDK starts. |
| Selected Completed | Reconcile missing job metadata without replaying a switch. |
| Still-enabled committed live target, earlier/restore/recovery phases, or incompatible/missing data | Existing explicit refusal; complete recovery/data-choice work remains required. |

Admission refuses an opted-in profile, a different selected runtime, changed storage kind, missing/tampered generation, mismatched original job mode or current verification/policy restriction. All settings/data checks remain exact for the lifetime of the admitted attempt. Stop or another settings edit during verification cannot be overwritten. Previously recorded post-commit settings hashes remain unchanged as original transaction evidence.

## Stable configuration snapshots

A cached-catalog/live-switch companion failed on the prior9d6d77d1 image while polling job metadata, with configuration_unavailable before reconciliation. Its log did not retain the specific underlying read error, so the exact cause remains unconfirmed and the failure stays recorded. Review identified a separate reproducible gap: the CIGAR control path treated a recognized concurrent Changed read as persistent unavailability and revoked the runtime.

The CIGAR-only home reader now takes at most three fresh descriptor-verified snapshots within a50ms monotonic retry budget, retrying only SecureReadError::Changed with a2ms delay. It never returns cached settings or retries a mutation/unknown write. Permission, symlink/hardlink, malformed/invalid UTF-8, size, path and other errors still fail immediately; exhausted Changed reads retain failure/revocation. The general Guard config reader and approval logic are unchanged. Two reader tests and three native control tests cover fresh values, fixed exhaustion, invalid files, generation preservation and later Stop. A later actual SDK pass does not by itself establish the old failure's exact cause or load/performance remediation.

## UI clarity and catalog maintenance

Recovery details now distinguish the renewed recovery deadline from the original preparation deadline and explicitly say that recovery keeps CIGAR off. Installed cards show reported core identity and distinguish selected/running state. SDK/Python cards have accessible version/build names, with unavailable-action explanations linked to their buttons. Keyboard preference edits preserve focus and perform no native action until the explicit save.

[The release maintenance runbook](CIGAR_RELEASE_MAINTENANCE.md) describes compatible catalog/lock/qualification changes, same-version rebuilds, private Python patches, adapter-change boundaries and the authorized qualification/signing/publishing process. The new read-only catalog CI workflow runs native contracts and maintainer tests. A deterministic fixture drafts three synthetic builds, including a same-version rebuild, through the unchanged generator/profile with distinct source/manifest/wheel/tree identities. They remain upstream-only and unqualified. Hosted CI and a real three-release installed/switch exercise are not claimed.

## Evidence and practical limits

Native image `b6486445abe6e50955556388accf6c6de51752106cde9b698bbc5563f0f12322` passes148 registry/lifecycle tests with5 SDK tests gated,22 service tests with21 SDK tests gated,59 configuration tests with1 helper ignored, and10 off-data tests plus three native snapshot-control regressions. Rust1.88, formatting, authority/I/O ownership and privacy gates pass. Clippy retains the same36 baseline errors in23 unchanged files and no new errors. The wired TypeScript graph retains the same13 prior shared errors, with no new errors; neither broad check is globally green.

Six actual final-0.14.1 SDK workflows pass on this same current snapshot-reader image: stopped-live recovery; disabled recovery; initial recovery; initial selection; disabled selection/rollback; live selection/latest-data rollback. They use task-private profiles and approved external CPython3.14.7/3.14.10 on local macOS ARM64. The two new recovery cases prove a later Stop/narrower settings, cancel/retry, data digests/expiry, metadata completion and separate enablement/fresh grants. A fresh Service is still same-process, not operating-system process-loss acceptance. These are two Python builds of the same final SDK, not prior-candidate/final or genuinely newer SDK qualification.

Four focused dashboard assertion modules and16 intercepted-API browser checks pass, including renewed deadlines, accessible card names/descriptions, keyboard focus, pending edits, generated utilities and390px layout. These fixtures do not run native/SDK/installed workflows or establish complete assistive-technology acceptance. Maintainer tests pass41 Python and85 native release/installer cases. Workflow parsing/read-only/pinned-action checks pass locally; hosted CI has not run.

All seven approved SDK/interpreter inputs are rehashed unchanged. Original84 dirty paths retain75 byte-identical files, seven exact inverse-patch-preserved workspace/tutorial files and the two earlier intentional differences. Original acceptance, locks, Git HEAD/branch/staging/history, live Guard/hooks/preview, system Python and upstream SDK remain preserved. Earlier registry/startup-contention failures retain their original images/logs in the previous receipt. Earlier SDK workspace timeout and broker/transport load observations remain open; these passing workflows are not their load/performance remediation proof.

Remaining work includes still-enabled live and other durable-phase/process-loss recovery, initial/clear/reset/unavailable-source data choices, inactive legacy scopes, managed removal/retention, notifications and complete accessibility, real approved older-candidate/final/newer transitions, managed/installed/frozen/current CLI/HTTP/platform/approval/cleanup/load/performance qualification and full next-bump acceptance. Production catalog trust/feed remains an external prerequisite. See the full plan rather than inferring completion from this checkpoint.

# CIGAR dynamic infrastructure readiness

The user clarified on 2026-10-28 that 0.14.1 is the newest available CIGAR build and that 80–90% reusable infrastructure, without hardcoded SDK releases in application logic, meets the current target. The engineering estimate is approximately 85% for this infrastructure scope. This is a qualitative implementation estimate, not a measured production-readiness or platform-certification score. The full P0–P10 release roadmap remains available for later hardening and qualification.

## How a compatible build is added

Add its exact SDK/core/source/manifest identity, platform wheels/dependencies, worker/package-tree hashes and reviewed qualification data to the authenticated catalog. Reuse the shipped adapter when its SDK API, worker/broker protocol, storage/evidence and Python contract remain compatible. Publish/import that metadata through the authorized release process. Guard can prepare the replacement beside the selected runtime and expose a separate explicit switch; refreshing metadata does not select, enable or start CIGAR.

A new version string or same-version rebuild does not require a version-specific runtime/client/CLI code edit. New bytes receive a distinct immutable build/installation identity. A breaking SDK/protocol/storage/Python contract requires a reviewed adapter/Guard update. Exact version/hash locks remain necessary catalog data so Guard verifies the build the user chose.

## Version-pin audit

The current source audit found 21 release-literal/constant matches, all in explicit test-only constants/imports, inline test modules, gated actual-SDK fixtures or the isolated browser fixture. `CIGAR_VERSION = "0.14.1"` is guarded by `cfg(test)` and absent from production compilation. Production runtime SDK/core identities come from `RuntimeRelease::catalog` and its resolved release; historical legacy enrollment comes from the catalog's separate legacy entry. Artifact and handshake checks compare against that resolved identity. UI history/status/catalog parsing accepts independent future SDK/core/build identities.

The audit covers Rust crates, Python source/tooling, dashboard source/scripts and CIGAR adapter integration source, with 21 matches individually classified and source hashes recorded. It is a current source/control-flow audit, not a claim that an unrestricted textual scan understands all future code changes. Future-release native/installer/client contracts and the new catalog CI workflow provide regression coverage. Historical fixtures remain labeled with the artifacts they actually test.

## Implemented core and evidence

| Infrastructure | Current state |
| --- | --- |
| Single release/profile catalog, exact locks and authenticated refresh/offline import | Implemented; live metadata refresh/import preserves the current runtime. Production feed/root provisioning remains separate. |
| Release-driven SDK/core identities and shipped adapter boundary | Implemented; compatible future identities route through the existing profile. Unsupported contracts refuse clearly. |
| Immutable SDK/private-Python preparation and bounded native jobs | Implemented; exact files, cancellation, deadlines and inactive preparation are preserved. |
| Existing installation/history compatibility | Implemented with authenticated archived identity; catalog/Guard refresh does not require replacing installed bytes. Preserve historical legacy metadata when adding new releases. |
| Coupled SDK/data switching and last-good rollback | Supported normal live/off/initial paths are implemented and exercised with real final 0.14.1 bytes. |
| Cancellation and recovery preserving off/current settings | Supported initial/committed/healthy and stopped-live paths are implemented; the full crash/cleanup matrix remains backlog. |
| Native administration, thin CLI/HTTP and Versions UI/walkthroughs | Implemented; CLI/HTTP framing is checked, 16 browser fixture cases pass. Current installed/frozen transport acceptance remains backlog. |
| Repeatable maintainer entry generation and catalog CI | Implemented locally; 41 Python/85 native contracts pass. Three unqualified synthetic drafts cover a same-version rebuild and another compatible SDK version. Hosted CI has not run. |

Six real final 0.14.1 SDK workflows pass on native image `b6486445abe6e50955556388accf6c6de51752106cde9b698bbc5563f0f12322`, using task-private profiles and approved CPython 3.14.7/3.14.10 on local macOS ARM64. Two synthetic future-version client modules pass. Native checks pass 148 lifecycle, 22 service, 59 configuration, 3 snapshot-control and 10 off-data tests, with their explicitly gated SDK/helper cases retained. Rust 1.88, formatting and authority/I/O/privacy gates pass. Broad Clippy and wired TypeScript remain at their 36/13 pre-existing errors in unchanged files, with zero new errors; neither broad check is represented as globally green.

[Stop/recovery evidence](evidence/receipts.json) and [the version/scope audit](evidence/receipts.json) bind exact sources, inputs and results. All seven approved SDK inputs are rehashed. Original dirty workspace/tutorial content and original acceptance are preserved. Changes are local; no live Guard/hooks/preview, system Python, upstream SDK, Git staging/history or publication changed.

## Remaining release work

The remaining work includes production trust/feed provisioning, installed/frozen and other-platform acceptance, full process-loss/cleanup recovery, initial/clear/reset/unavailable-source data choices, inactive legacy scopes, managed removal/retention, notification delivery, complete assistive-technology acceptance, Guard approval/load/performance qualification and an actual next-version upgrade when approved newer bytes exist. The successful same-SDK/two-Python tests and synthetic drafts do not qualify a real newer CIGAR release.

The earlier masked configuration-read SDK failure remains recorded and its exact cause is unconfirmed. The new typed Changed-read retry has deterministic regression coverage and the subsequent six-workflow run passes; this is not proof that all earlier workspace/broker/transport load observations are resolved. These limitations remain part of release hardening rather than a reason to invent a newer build or reintroduce version-specific application pins.

Use [the release-maintenance runbook](CIGAR_RELEASE_MAINTENANCE.md) for the next compatible build. The current core target is met; the extended roadmap is not claimed complete.

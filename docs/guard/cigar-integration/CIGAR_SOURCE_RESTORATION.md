# Automatic source restoration after an unpublished failed cutover

The live native coordinator can restore the previous CIGAR runtime after a known pre-publication failure following source shutdown. It reconstructs fresh SDK state from native scope intent; no old SDK context, agent session, execution handoff or epoch returns. This is a local P6 milestone, with full crash/privacy and public-workflow qualification still pending.

## Eligibility and settings

The cutover retains a nonserializable native boundary snapshot before stopping the old actor. It contains app/workspace/source intent, notes access, readonly history, receipts and SDK-proven in-memory reviewed data. Only that living native coordinator can use it. Neither job history nor a lifecycle record can reconstruct this snapshot or authorize an app.

Restoration requires acknowledged cleanup of both the original actor and the unpublished candidate. [Cleanup-pending ownership](CIGAR_CLEANUP_OWNERSHIP.md) now retains the same lease and private handles until those acknowledgements, including a failed reconstructed-source actor. The native Service must still have the same cutover owner, expected incremented generation and source settings, without another runtime. The same profile lifecycle lease excludes installer/interpreter/selection owners throughout the attempt.

The owner reloads and authenticates the transaction/key before effects. Only the exact captured original or target config bytes, unchanged source/target native policy snapshots and an originally enabled source qualify. An unrelated edit, disabled preference, changed policy, missing/corrupt authentication or unexpected transaction leaves recovery required. A published target is handled by completion reconciliation or explicit rollback instead.

Under the short settings writer lock, RestoreIntent precedes any config effect. Exact original config bytes need no rewrite, even when the file became readonly. Exact target bytes may be compared and exchanged for the entire original text, preserving comments and every other preference. Unknown write acknowledgements require inspection of exact current bytes; there is no blind mutation replay. Native Stop/config revocation is serialized with that small config effect.

## Fresh runtime and data

The source installation is loaded and verified again, including requested SDK feature proofs. [Prepared recovery](CIGAR_PREPARED_RECOVERY.md) now performs that fresh SDK startup/verification beside the serving source before Ready; physical/transport/data checks repeat after failure before user-data admission. Its complete measured installation/approval/interpreter/producer identity and recorded data selection must match the authenticated source pointer. Ready generation bindings are checked under the existing owner rather than acquiring another lifecycle lease. Legacy saved slots retain their original key namespace.

The shared engine builder rereads the captured selected source files and rechecks current root policies. Saved mode resumes the original selected cache with the same exact SDK producer. Memory mode imports only the retained SDK-proven reviewed vector, with original observation/expiry, into fresh brokers and creates no saved-evidence generation. Logical scope IDs, readonly history and receipts survive; all SDK contexts, app views and agent sessions are fresh.

After artifact/transport/settings checks, RolledBack records the original SDK/data pair and preserves the existing last-good pointer. Publication advances the native generation and invalidates its epoch again, registers fresh notifications/watchers and attaches the reconstructed actor. Unselected prepared data is discarded through protected native retention checks. A cleanup failure is reported separately while an already-restored source keeps serving.

## Cancellation and interruption

Cancelling an upgrade requests a return to the original selection. Native Stop, shutdown and policy/settings revocation instead cancel both candidate work and restoration, preventing publication. Reconstruction uses its own cancellation token; the already-cancelled target token cannot accidentally kill a rebuilt source. The restoration watchdog is finished before attachment and cannot subsequently cancel the serving runtime.

The preparation deadline remains 120 seconds. A separate restoration cancellation budget is at most 30 seconds and never extends beyond the original preparation deadline plus 30 seconds. Job metadata exposes that additional deadline and bounded original/restoration failure codes. SDK request/actor deadlines remain unchanged. Pending cleanup and uncertain outcomes remain visible rather than promising immediate availability.

Ready history is published after live commit readiness; can_commit requires both observations. This closes a race found by the actual SDK test, where history previously became Ready just before the live coordinator accepted commit.

## Qualification and remaining work

The saved and memory actual SDK scenarios each force an unwritable config after acknowledged source shutdown, then cancel after native target config commit, then issue Stop after source config restoration but before reconstruction. Both successful recovery cases preserve exact original config, complete SDK-proven reviewed digests/expiry and readonly history. A real old agent/session and context are checked before cutover and absent afterward; old actor cleanup and epoch revocation are verified. Stop remains disabled without a runtime.

These tests use finalSDK0.14.1, v1-enrolled source, test-only qualified exact-wheel target and external CPython3.14.7/3.14.10 on local macOS arm64. Later prepared-recovery evidence also covers one current edited selected generation. These cases do not exhaust retained/inactive-generation states or qualify original b47380, genuinely newer SDK bytes, installed/frozen packaging or other platforms. Commit-to-finished-recovery timings conservatively include native validation, metadata and cleanup, not just SDK outage; exact local values are in the receipt.

Cleanup-pending ownership for all three actor roles now has separate actual SDK acceptance. Finish the complete process-loss/unknown-write/cleanup/Stop matrix, the remaining retained/inactive-generation and source-mutation cases, durable interrupted erasure, per-scope retained/prepared-copy deletion, inactive-data readmission, lineage/capacity and accepted feature/data differences. Final source capture still performs bounded policy/file work on the old actor and needs workload qualification. P7/P8 controls/catalog/update-policy/UI and P9/P10 real/installed/frozen/platform/approval/transport/performance qualification remain required. No public update route is exposed by this milestone. The full unbudgeted P0–P10 goal remains active.

[Evidence](evidence/receipts.json) binds source hashes, exact images, passing checks, the development compile/readiness failures and raw logs. Original acceptance/log, live profile/hooks/preview, upstream SDK source, system Python, Guard approvals and Git staging/history remain unchanged.

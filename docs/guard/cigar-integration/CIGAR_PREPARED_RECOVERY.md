# Prepare recovery before interrupting the serving SDK

An upgrade now prepares two inactive resources beside the serving runtime: the target engine with current reviewed data, and a freshly verified original SDK process with no user scope, source file or saved cache opened. Ready requires both. This keeps costly original-SDK startup and feature verification outside the cutover interruption.

The original process uses the same installation, interpreter, artifact, shared/persistence and requested execution checks as before. The profile owner verifies its complete measured source SDK/data identity against the authenticated Prepared transaction. Only synthetic doctor data is used. It is not the old source process and carries no old SDK context, agent, execution handoff or app grant.

During this background step the original source keeps serving. A preparation-only cancellation bridge propagates the target job's cancellation into the recovery process while commit is unavailable. The bridge is finished before Ready; its finished watcher cannot later cancel a serving reconstruction. Native Stop/config/shutdown always cancel both tokens. The new preparing_recovery phase is appended, preserving earlier phase numbers and legacy request fingerprints.

The target actor is registered with the live owner before any later fallible progress or recovery verification. An early failure therefore cannot drop an untracked candidate and release the lease while private state remains. The existing three-role cleanup ownership remains authoritative. Unused synthetic-only recovery processes are closed before the owner releases its profile lease.

After an unpublished cutover failure and acknowledged old/candidate cleanup, the retained fresh SDK repeats physical artifact and transport checks. Exact config/policy/owner/generation and source-data verification still precede user-data admission. It then rereads the captured sources and constructs fresh SDK views against the selected current saved cache or proven memory vector. Its independent cancellation token and fresh native epoch remain separate from the cancelled target. Publication and last-good semantics are unchanged.

Preparation remains bounded by120 seconds; restoration retains the existing at-most30-second cancellation budget and original absolute cap. SDK request and actor deadlines are unchanged. Extra verification uses background CPU/process resources and can lengthen preparation; it does not open a second user cache. Full workload/installed/platform qualification remains pending.

## Evidence and scope

The selected-generation actual SDK test first upgrades, removes the original review, admits a replacement in the selected ready generation and deliberately makes a reverse switch fail after source shutdown. Recovery must return to that exact edited generation and current producer, preserve complete note digest/original expiry/history and the original last-good pointer, remove the failed prepared generation, reject old context/epoch authority and make retries return the prior job. The removed legacy note must not return.

The initial test hit the30-second restoration deadline. A diagnostic-only rerun passed in29.6 seconds, including25.6 seconds of fresh SDK verification; that pass was not treated as a fix. Moving those checks into preparation reduced the later local recovery path to5.4 seconds while the original SDK served237 context requests during background verification. These are local observations with stage probes, not a controlled performance guarantee.

The updated memory test preserves the complete reviewed vector/original times without saved evidence, and Stop still prevents reconstruction. The destructor-gated saved-mode tests recheck candidate/source/failed-reconstruction ownership with the added prepared process. All cases use finalSDK0.14.1, v1-enrolled source, test-only qualified target and external CPython3.14.7/3.14.10. They do not qualify b47380, a genuinely newer SDK, managed-interpreter end-to-end, installed/frozen packaging or other platforms.

Finish every process-loss/unknown-write/Stop/cleanup boundary, durable interrupted erasure and per-scope retained/prepared-copy deletion, inactive data/lineage/capacity, accepted feature/data differences and loaded-workspace timing. Complete P7/P8 native/CLI/HTTP/catalog/policy/UI and P9/P10 final qualification. The full unbudgeted P0–P10 goal remains active and incomplete.

[Evidence](evidence/upgrades-prepared-recovery-20261027.json) binds passing/failing logs, exact images, current source identities and qualification limits. Original acceptance/log, live profile/hooks/preview, upstream SDK source, system Python, Guard approvals and Git staging/history remain unchanged.

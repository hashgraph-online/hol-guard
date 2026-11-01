# Local CIGAR integration acceptance

The authorized local P0–P5 integration is accepted on **2026-10-25**. The product build is **`ed5011acbba43cb19c093064b34ffe47bf3f2616`**, based on HOL Guard v3.55.1, on local branch `feature/integrate-cigar-0.14.1`. Later delivery commits contain qualification records and documentation. [Machine-readable acceptance](evidence/receipts.json) records the source, artifact and evidence audit; [the execution log](EXECUTION_LOG.md) preserves every checkpoint and failed attempt.

Qualification covers local **macOS arm64**, Guard **Python 3.12.13**, and the independently verified final **CPython 3.14.7 / CIGAR 0.14.1** candidate. CIGAR source remains unchanged at `b47380e5a5cbeaaad5a61cab3372e9e67368732f`. This is a local integration delivery, with the external and baseline limits below.

## Product behavior

Context assistance is optional and **off by default**. Rust verifies the actual selected CIGAR interpreter as qualified, final CPython with version tuple exactly `(3, 14)`, together with package, worker, platform, protocol and feature identities. Unsupported, altered or unqualified runtimes cannot activate assistance through settings, CLI, HTTP, MCP or cached tools. Guard retains its existing Python >=3.10 support; a separate verified 3.14 environment is valid. No system Python, live Guard installation or SDK source was changed.

| Phase | Delivered behavior | Evidence and guide |
| --- | --- | --- |
| P0 | Native settings/defaults/managed restrictions, requested/effective availability, verified runtime registry, recheck/start/stop and optional packaging | [Runtime controls](runtime-controls.md), [runtime verification](evidence/receipts.json), [matching frozen package](evidence/receipts.json) |
| P1 | Persistent public-SDK bridge, Rust supervision, bounded graphs/views/jobs, protected selected sources, current citations, withdrawal/revocation, independent evidence notifications and native-only degradation | [Native runtime](native-runtime-implementation.md), [source lifecycle](evidence/receipts.json), [fault/eviction checks](evidence/receipts.json) |
| P2 | Home status, Protection setup/settings, app/workspace/source controls, independent review brief/source comparison, Evidence context history and Data & repair | [Screen design](experience.md), [three matching browser flows](evidence/receipts.json) |
| P3 | Authenticated scoped MCP status/context/explanation, consistent discovery/calls, explicit refusal after disablement and actual installed MCP/Pi/OMP tool delivery | [Agent access](agent-access.md), [matching backend acceptance](evidence/receipts.json) |
| P4 | Separately enabled broker sharing, protected grants, finite leases/quotas, quarantined proposals and host admission; optional private SQLite evidence with retention/removal and fresh authority after restart | [Sharing](broker-sharing.md), [private persistence](private-persistence.md), [matching restart/concurrency/browser checks](evidence/receipts.json) |
| P5 | Separately enabled exact native action/context association and supported captured-Bash executor handoff, preserving Allow once/Always allow, replay and uncertain-effect reconciliation | [Native execution context](native-execution-context.md), [matching executor/SDK/owner-loss cases](evidence/receipts.json) |

Local enablement grants no implicit workspace, app or document access. Agent context, independent sharing, persistence and execution context have separate controls. Memory-only storage is the default. Turning off revokes optional access and stops optional work while preserving Guard's existing approval rules. The remote Honey effect service remains a separate optional deployment.

Use the [runtime guide](runtime-controls.md) for setup and verified candidate enrollment. A running Guard app or daemon is required for persistent activation; a short-lived standalone CLI does not host the native service. Public installation requires qualified version-bound artifacts rather than silently substituting another CIGAR release.

## Verification

| Layer | Qualified result |
| --- | --- |
| Final source regressions | 144 pass, including 16 frozen preferred-status cases; 8 of those fail before the correction |
| Native context lane | 81 distinct executed cases at the recorded source; all four changed Rust files match that receipt |
| Ownership | All five semantic, capability, Rust authority, I/O and privacy gates pass |
| Installed backend | 13 pass, zero failures/errors/skips, 3,880 stable inputs per job |
| Installed React/HTTP browser | 3 pass, zero skipped/unexpected/flaky results, 1,830 stable inputs |
| Actual onefile daemon/CLI/MCP | 4 pass, including off-state SIGINT and 3 fresh context profiles; 4,095 stable inputs |
| Package/compiler binding | 139 generated projections, 10 explicit runtime-file hashes, 33 UI assets, 80 operator files and strict local signatures verify |
| Complete installed SLO | All 22 gates pass in each off/on mode |
| Original fixed contention cohort | All 10 runs pass all 13 individual gates; both original relative comparisons pass |

Every matching installed functional/frozen job requires complete sampling and zero remaining new descendants. Each frozen daemon exits zero without fallback. Actual context flows verify all ten fixed facts across three questions, current citations, reuse of one graph revision, retained base tools, cached-call refusal and persisted opt-out. These are controlled local facts and repetitions, not independent model tasks or human studies.

[Source evidence](evidence/receipts.json), [frozen/component evidence](evidence/receipts.json), [installed functional evidence](evidence/receipts.json) and [performance evidence](evidence/receipts.json) retain exact commands, hashes, inputs and scope.

The final source audit verifies that all production Rust outside the qualified context-worker lane is unchanged from the native-owner qualification at `4c4db2d9`. All seven changed Python runtime files since that reference are covered by the ten-file installed/frozen binding. Dashboard product source and all 33 shipped asset hashes match the qualified pairing build at `95657b30`. Earlier fault/churn/retention receipts retain their original artifact identities; this audit does not relabel them as current reruns.

## Performance and usefulness

The same installed artifact runs the original complete SLO off/on and then five alternating contention pairs, without an overlapping owned build, diagnostic or acceptance job. Workloads, deadlines, resource bounds, scheduling priority and the median-of-per-run-p95 estimator are unchanged.

| Warm p95 comparison | Off | On | Difference | Original allowance | Result |
| --- | --- | --- | --- | --- | --- |
| Direct native | 1.806 ms | 1.754 ms | −0.052 ms | 1 ms | Pass |
| Installed HTTP | 8.809 ms | 9.394 ms | +0.585 ms | 1 ms | Pass |

The allowance is `max(1 ms, 5% of off p95)`. All individual rows and paired deltas remain retained; the fifth HTTP pair is +1.444 ms. The prescribed cohort estimator passes, which does not imply that every pair lies within the relative allowance or establish general reliability. Earlier +1.312/+1.438 ms artifact failures remain failed in their own receipts.

The focused synthetic cohort explicitly selects force-mode native bytes. Automatic installed discovery and actual frozen application behavior have separate functional qualification; an automatic-mode production latency cohort is not established. Resource sampling includes the bridge/SDK/native tree, with possible shared-page double counting. No memory reduction or long-term plateau is claimed.

Verified useful mechanisms include scoped evidence reuse, current attributed answers, source-change rejection, explicit refresh, shared agent context, exact execution associations and native fallback during optional faults. Avoided fallback discovery is verified at the installed publisher-handoff entry. These results establish no causal speedup, provider/model-token saving, internal tokenizer saving, human-time improvement, arbitrary-task accuracy or exponential efficiency gain.

## Reviewable artifacts

| Artifact | Path | SHA-256 |
| --- | --- | --- |
| Guard wheel | `/private/tmp/hol-guard-cigar-shared-status-20261025/package/native-wheels/hol_guard-3.55.1-py3-none-macosx_11_0_arm64.whl` | `bb5dfd23afc3cb4cd22f246b185092ab776d7a9623bfa1d0b317781108ee92f5` |
| Onefile application | `/private/tmp/hol-guard-cigar-shared-status-20261025/onefile/dist/hol-guard` | `a7e82b664d47b33c481f8ec8241385fca4e7d59671063702cc4249201cc1ea66` |

The local checkout and task-owned detached build/evidence trees remain available for review. No push, merge, publication, deployment, release credential access or live installation change was performed.

## Release checklist and limits

- [x] Local P0–P5 implementation, default-off/runtime gates and approval invariants.
- [x] Matching source/installed/browser/frozen checks, package binding, complete SLO and original fixed relative cohort.
- [x] Source-equivalence audit, unchanged SDK baseline, preserved failures, documentation and local delivery commits.
- [ ] Public CIGAR artifact/platform attestation and authorized publication/release.
- [ ] Developer ID/notarization and full outer Desktop application qualification; only its local onefile core shape is covered here.
- [ ] Other OS/architecture matrix, including qualified Windows Job Object/persistence support. Unsupported targets remain unavailable.
- [ ] Interactive external CLI/account/model-led sessions beyond the actual installed MCP and Pi/OMP SDK tool checks.
- [ ] Provider/model/human efficiency studies, automatic-mode production performance, longer-term resource/reliability studies and additional executor timing/atomicity claims.
- [ ] Existing repository baseline checks: 18 previously recorded non-context production TypeScript diagnostics and hardened-helper launch failures remain unqualified. This is not a claim that the entire repository test/typecheck suite is green.

Private POSIX persistence provides neither encryption nor physical secure erasure or hostile-same-user isolation. Mutable workspace excerpts are advisory evidence at their checked read boundary; they are not proof of launch-time currentness. Saved evidence restores no execution authority. These limits remain part of the delivered product contract.

# `main` to `release/3.1` compatibility matrix

## Pinned inputs

| Ref | Commit |
| --- | --- |
| `origin/main` | `b92d3054be4d8a71ac47847edbcb0a29fd9c4754` |
| `origin/release/3.1` | `15b9add58d0c1cba20ba5f7bf1cbdb9b60ed0f01` |
| merge base | `4ab0cef80266dce2a1eeeeeaaa075069aed69fba` |

The pinned branches diverge by 29 main-only and 213 release-only commits. A raw recursive merge reports 139 conflicts: 72 content and 67 add/add across 23 dashboard, 68 runtime, 42 test, two workflow, two script, one package metadata, and one lockfile path. A blind merge or global conflict preference would overwrite 3.1 alpha contracts.

## Strategy

The stable `2.1` release snapshot is not copied into `release/3.1`. Compatible post-snapshot fixes are forward-ported individually, conflicts are resolved against the 3.1 contracts, and incompatible stable-dashboard repair paths remain excluded. After focused verification, an `ours` ancestry merge records that the pinned `main` ref was reviewed without replacing release-only content.

## Main-only commits

| Commit | Subject | Disposition |
| --- | --- | --- |
| `eef187ae788c` | feat(release): ship HOL Guard 2.1 | excluded: stable 2.1 squash/release baseline |
| `fcdc38378dde` | fix(hooks): self-heal Codex review failures (#1850) | ported: conflict-resolved for 3.1 context |
| `7679be4ddda5` | fix(macos): bound passive keychain reads (#1851) | ported cleanly |
| `2b43ddccb884` | fix(dashboard): repair protection inline (#1849) | excluded: stable dashboard architecture conflicts with 3.1 UI |
| `6711959c52f2` | fix(guard): make protection repair converge (#1853) | partially ported: managed-install proof and compatible checks; retained 3.1 truthful unknown semantics |
| `e09b048da020` | fix(guard): ignore inactive hook history (#1855) | ported with 3.1 attestation semantics: inactive history ignored, active remains unknown without proof |
| `12b2f1696447` | fix(hooks): self-heal daemon-dependent harnesses (#1854) | ported: bounded daemon fast path and local fallback; revived upstream latency regression test for validation |
| `db07731bc067` | fix(guard): canonicalize hook health identities (#1856) | ported: canonical managed-install identity; retained 3.1 proof-gated health assertions |
| `5154fd221ad8` | fix(cursor): preserve global hook state from home (#1857) | ported cleanly: preserve Cursor global hook state |
| `4701ba000480` | fix(guard): recover command evidence health (#1858) | excluded: depends on stable protection-repair endpoint absent from 3.1; avoids dead synthetic probe path |
| `c0801455ebe8` | fix(macos): keep keychain trust daemon-owned (#1859) | ported: daemon-owned macOS keychain trust; release corpus retained until the final source-bound report regeneration |
| `c7f42db57932` | fix(macos): bind cached trust to live daemon (#1860) | ported cleanly: cached trust bound to live daemon |
| `a7b5b91565c6` | fix(macos): serve passive trust from daemon state (#1861) | ported: passive trust served from authenticated daemon state; retained release fixture and only relevant commit/rollback test |
| `50f2bdcfacde` | fix(daemon): prevent duplicate keychain access (#1862) | ported: daemon owner lock and duplicate keychain prevention; revived focused regression tests |
| `ab0d37a24aa2` | fix(github): allow static pull request creation (#1863) | ported cleanly: static GitHub pull-request creation capability |
| `2d60196e8181` | fix(security): bound hook output and static PR proposals (#1864) | ported: bounded hook output and static PR proposals; release corpus retained until targeted regeneration |
| `ea3f94a4c0a7` | fix(guard): isolate background keychain access (#1865) | ported: isolated background keychain access; release corpus retained until targeted regeneration |
| `8202f3609f8f` | fix(guard): recover stale cloud request sync (#1866) | ported: stale Cloud request-sync recovery with binding and runtime-identity regressions |
| `a6fa67438f05` | feat(guard): repair quarantined request sync | ported: quarantined request-sync repair with typed runtime and tests |
| `63e2d889ca6e` | fix(pi): bound hook fallback deadline (#1869) | ported cleanly: bounded Pi fallback deadline |
| `c3df5eb10443` | fix(guard): allow safe PR body files (#1872) | ported: safe static PR body files with existing capability confirmation preserved |
| `65d0de4fa924` | fix(github): allow verified canonical PR body files (#1874) | ported: verified canonical PR body files |
| `74cbae579938` | fix(guard): tolerate removed install workspace (#1876) | ported cleanly: removed install workspace tolerance |
| `0a8442037006` | fix(guard): harden PR body file validation (#1877) | ported: hardened PR body file validation |
| `9f67abb61c1b` | fix(guard): harden daemon hook resilience (#1878) | ported: daemon/hook resilience architecture, bounded CLI fallback, per-harness capacity, process isolation, heartbeat, adversarial tests |
| `c321fb8b76d6` | fix(guard): close daemon resilience gaps (#1879) | ported: closed daemon resilience gaps, typed socket admission, startup rollback, deadline contracts |
| `4f1d6b66be6c` | fix(guard): harden daemon worker ownership (#1881) | ported cleanly: daemon worker ownership containment |
| `93fd5c9d1d72` | fix(guard): bound local evidence storage (#1880) | ported: bounded local evidence storage; preserved 3.1 daemon/tray command routes |
| `b92d3054be4d` | fix(guard): restore resident hook output review (#1883) | ported cleanly: resident hook output review regression |

## Release-only contract preservation

- Keep `release/3.1` package/version/publish metadata and alpha validation; do not import the stable `2.1` release snapshot.
- Keep 3.1 extension-control, protection-health, attestation, daemon/tray routing, Cloud sync, and dashboard contracts when a stable fix conflicts.
- Preserve the 3.1 command corpus during conflict resolution, then regenerate its source-bound decision-diff report from the integrated runtime.
- Do not broaden containment eligibility or reinterpret isolation as approval.
- Treat Pi and other fail-open harnesses as degraded; the bounded fallback work improves liveness but does not make them authoritative mandatory-assurance coverage.
- Keep the resident hook fast path default-off for the 3.1 alpha; explicit opt-in remains the rollback boundary.

## Open compatibility blockers

- No evidence currently proves 2.1/2.2 policy, receipt, runtime-session, protection, or approval payload compatibility with 3.1. The stable snapshot exclusion is not a compatibility adapter.
- The surface schema method list and runtime method list require an explicit negotiated contract before the compatibility gate can pass.
- Archived receipt-rollup reconstruction requires migration evidence before old receipt compatibility can pass.
- Harnesses that cannot enforce authenticated local decisions remain degraded or unsupported for mandatory assurance.
- This branch is not mergeable until these blockers have focused evidence and independent approval.

## Verification gates

Before review: run focused tests for every ported subsystem, followed sequentially by lint, typecheck, package build, and clean-wheel smoke. GitHub CI owns exhaustive suite validation through the PR review loop. The dedicated PR targets only `release/3.1`; no release, publication, deployment, or policy activation is authorized.

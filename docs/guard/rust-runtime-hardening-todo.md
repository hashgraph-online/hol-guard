# HOL Guard native runtime hardening TODO

Status: canonical follow-up backlog for `release/3.0`.

## Execution rules

- Work from the latest `release/3.0`; never merge it into `main` here.
- Eligible PostToolUse uses verified bundled Rust in source-default `auto`; explicit `off` and pure-Python fallback remain rollback paths, while PreToolUse stays Python-authoritative.
- Every task needs code, tests, installed-artifact evidence, and matching documentation.
- Any security-lowering Python/Rust mismatch blocks authority.
- Never persist raw commands, prompts, output, paths, endpoints, database strings, environment values, secrets, tokens, or proofs.
- Delete replaced dead Python code; retain only named supported Python control/reference paths exercised in CI.

## PR 1: Source of truth and executable contracts

- [x] NRH-T001 reconcile merged Rust PRs, crates, workflows, packaging, transport, authority, and defaults;
- [x] NRH-T002 update migration PRD/TODO to current architecture;
- [x] NRH-T003 add protocol/admission ADR;
- [x] NRH-T004 add native/daemon failure ADR;
- [x] NRH-T005 add same-user/DoS/crash/fallback threat-model delta;
- [x] NRH-T006 add executable fail-safe matrix;
- [x] NRH-T007 ratify exact emergency-safe profile;
- [x] NRH-T008 add stable public native/daemon reason codes;
- [x] NRH-T009 add capability ownership and Python-removal manifest;
- [x] NRH-T010 add contract validation tests without changing authority.

## PR 2: Protocol v2, authentication, and bounded admission

- [ ] NRH-T020 define request envelope with protocol, request ID/digest, operation, size, deadline, runtime/rule/policy identities;
- [ ] NRH-T021 define request-bound response envelope and fixed overload response;
- [ ] NRH-T022 reject duplicate/trailing/invalid UTF-8/deep/wide/overlong/unsupported structures before evaluation;
- [ ] NRH-T023 enforce operation-specific frame caps before allocation;
- [ ] NRH-T024 enforce authentication/header/payload/evaluation/write deadlines;
- [ ] NRH-T025 add cross-language golden vectors and strict Python response binding;
- [ ] NRH-T026 add POSIX mutual authentication while preserving `0700` directory and `0600` socket defenses;
- [ ] NRH-T027 replace handwritten first-party HMAC with an audited minimal crate;
- [ ] NRH-T028 rotate/clear per-process auth material and prove it never reaches argv/env/files/logs/payloads;
- [ ] NRH-T029 separate small handshake and authentication-failure budgets;
- [ ] NRH-T030 remove blocking permit wait from accept loop;
- [ ] NRH-T031 use fixed workers and bounded queue/executor;
- [ ] NRH-T032 reserve lifecycle capacity, use deadline-aware admission and RAII release;
- [ ] NRH-T033 handle transient accept errors with bounded backoff and fatal corruption with explicit exit;
- [ ] NRH-T034 reject poisoned socket paths and remove only verified stale sockets;
- [ ] NRH-T035 add malformed frame, slowloris, auth flood, low-descriptor, panic, capacity, and no-busy-spin tests.

## PR 3: Supervision, fallback budgeting, and daemon fail-safe

- [ ] NRH-T040 add explicit native health states and child-generation identity;
- [ ] NRH-T041 retain child handle and detect exit without waiting for another hook;
- [ ] NRH-T042 prewarm outside the first hook;
- [ ] NRH-T043 add authenticated health operation outside normal evaluation capacity;
- [ ] NRH-T044 restart asynchronously with single-flight, exponential backoff, jitter, bounded budget, and half-open probe;
- [ ] NRH-T045 add crash-loop circuit and zero-downtime rotation;
- [ ] NRH-T046 bind in-flight responses to their serving generation;
- [ ] NRH-T047 add global one-shot semaphore/rate-limit/cooldown and bounded Python fallback queue;
- [ ] NRH-T048 distinguish overload/unavailable/incompatible/auth/timeout/invalid/crash categories;
- [ ] NRH-T049 prove 64 failures cannot create 64 processes;
- [ ] NRH-T050 implement deterministic fail-safe behavior for every hook when daemon is unavailable;
- [ ] NRH-T051 allow only authenticated current emergency-safe profile during daemon failure;
- [ ] NRH-T052 add bounded daemon restart reservation and preserve approval/receipt/activity ordering;
- [ ] NRH-T053 add panic/kill/hang/stale endpoint/port/socket/binary/manifest/policy/disk/permission/crash-loop tests;
- [ ] NRH-T054 add privacy-safe aggregate lifecycle journal and critical health state.

## PR 4: Cross-platform installed-wheel and resource gates

- [ ] NRH-T060 run equivalent real-wheel suites on Ubuntu 22.04/24.04, macOS Intel/arm64, and Windows x64;
- [ ] NRH-T061 add CPython 3.10-3.14 smoke;
- [ ] NRH-T062 add pip/pipx/uv tool/offline/upgrade/downgrade/reinstall/rollback/Desktop/managed smoke;
- [ ] NRH-T063 run parity, mutation, overload, crash, daemon-failure, path, privacy, and performance on every Tier 1 target;
- [ ] NRH-T064 add Windows PowerShell/CMD, reparse/junction/UNC/device/long path/Job Object/lock/quarantine cases;
- [ ] NRH-T065 add macOS APFS case modes, aliases, links, mounts, socket paths, quarantine/signing/sleep cases;
- [ ] NRH-T066 add Linux static, path walk, bind/overlay, namespace/container, FD/cgroup/noexec/read-only/stale socket cases;
- [ ] NRH-T067 make explicit Linux arm64 and musl support decisions;
- [ ] NRH-T068 emit aggregate-only evidence and scan artifacts for prohibited data.

## PR 5: Catastrophic-risk effect and detector parity

- [ ] NRH-T080 define versioned privacy-safe effect DTO and corpus version;
- [ ] NRH-T081 model sensitive read, network sink, subprocess/package execution, writes/deletion, DB/infra mutation, Guard tampering, confidence/scope/reversibility/containment/approval floor;
- [ ] NRH-T082 bind effects to request/parser/rule/policy identities;
- [ ] NRH-T083 keep durable correlation in Python and add read-then-exfil plus Guard-disable-then-retry sequences;
- [ ] NRH-T084 use more restrictive effect/action on mismatch;
- [ ] NRH-T085 expand secret/exfiltration corpus across credentials, shells, encodings, archives, cloud/GitHub/webhook/database/language clients;
- [ ] NRH-T086 prove no secret sample reaches responses/logs/diagnostics/metrics/artifacts/crashes;
- [ ] NRH-T087 add bounded native prompt-injection DTO/rules with documentation/fixture/quotation context parity;
- [ ] NRH-T088 scan untrusted repository/web/issue/PR/log/MCP/file output and expose tightening-only signals until parity;
- [ ] NRH-T089 add POSIX/PowerShell/CMD/language/Git/package/cloud mass-deletion effects and bounded scope estimation;
- [ ] NRH-T090 add destructive production DB, migration, backup, cloud DB, cluster/namespace/bucket/IAM/secret/resource-group effects;
- [ ] NRH-T091 add Guard tampering and flood-then-retry effects;
- [ ] NRH-T092 require 100% pause/deny on approved catastrophic corpora, zero unsafe downgrade, and safe-corpus false-pause <0.5%;
- [ ] NRH-T093 keep uncertain dangerous commands paused and native PreToolUse allow authority disabled.

## PR 6: DX, observability, repair, and dead-code cleanup

- [ ] NRH-T100 add stable native status model for CLI/dashboard/Desktop/MDM;
- [ ] NRH-T101 add `hol-guard doctor --native` and `hol-guard runtime status --json`;
- [ ] NRH-T102 add idempotent native lifecycle repair and clear diagnosis for noexec/wrong wheel/unsupported/manifest/permission/stale endpoint/circuit/daemon;
- [ ] NRH-T103 add bounded aggregate metrics for latency/size/cost/queue/overload/auth/fallback/timeout/crash/restart/circuit/mismatch;
- [ ] NRH-T104 add support-bundle redaction and privacy tests;
- [ ] NRH-T105 add plain-language pause copy and exact approve-once/target/pattern/contained/narrow/dry-run/edit/cancel options;
- [ ] NRH-T106 keep healthy safe operations silent and approval scope consistent across surfaces;
- [ ] NRH-T107 add local and managed native kill switches plus rollback playbook;
- [x] NRH-T108 generate static import/call graph and runtime import coverage for migration candidates;
- [ ] NRH-T109 delete dead duplicate Python implementations, including the unused `choose_post_tool_response` selector, plus its tests, imports, dependencies, package entries, flags, and shims;
- [x] NRH-T110 move reusable cases to language-neutral fixtures and add package-content/import-removal tests;
- [x] NRH-T111 publish Python LOC/dependency delta and require every retained reference backend to run in named CI.
- [x] NRH-T112 delete `choose_post_tool_response` after repository-wide static and dynamic caller proof;
- [ ] NRH-T113 delete replaced PostToolUse traversal, scanning, secure-read, hashing, and path-validation Python implementations in the same authority-cutover wave;
- [ ] NRH-T114 delete replaced command parsing and catastrophic-risk Python implementations only after cross-shell native authority gates pass;
- [ ] NRH-T115 remove dependencies and build/package metadata used only by deleted implementations;
- [x] NRH-T116 add installed-wheel tests proving removed private modules are absent and intentionally non-importable;
- [ ] NRH-T117 audit dynamic imports, entry points, plugin references, and string-based module loading before every deletion;
- [ ] NRH-T118 treat every unreachable or untested fallback as dead code rather than dormant rollback;
- [x] NRH-T119 prove dead-code package exclusion preserves the named pure-Python unsupported-platform and rollback configurations.

## PR 7: Supply chain, fuzz, chaos, soak, and opt-in gate

- [ ] NRH-T120 add Cargo advisory, source, license, duplication, and banned-crate gates;
- [ ] NRH-T121 generate Rust SBOM/provenance bound to every native wheel and verify staged/published wheel bytes;
- [ ] NRH-T122 add persistent frame/envelope/output/scanner/prompt/command/path/response fuzz targets and deterministic PR seeds;
- [ ] NRH-T123 add 10,000 malformed frames, auth floods, 16 slow clients, 64 mixed clients, fallback saturation, daemon kills, disk/read-only/stale/low-FD chaos;
- [ ] NRH-T124 add 100,000-request soak, rotation, memory/handle/thread/process/socket leak gate;
- [ ] NRH-T125 measure installed adapter-to-decision p50/p95/p99/max, throughput, CPU, RSS, threads, handles, FDs, sockets, processes, queue, and fallback;
- [ ] NRH-T126 enforce PR no-regression and documented-hardware absolute SLOs without weakening security;
- [ ] NRH-T127 complete independent security review and resolve all unsafe/unexplained mismatches;
- [x] NRH-T128 enable eligible PostToolUse `auto` by default only for verified bundled wheels, retaining explicit `off` and Python fallback;
- [ ] NRH-T129 retain pure-Python/reference rollback and do not enable PreToolUse allow authority.

## Final release gate

NHD-091–095 completes the ownership/graph/package proof for the cleanup
surface. `native_runtime_resident.py` remains a recorded deletion candidate,
not a deleted file; T109, T113, T114, T115, T117, and T118 remain open until a
separate authorized deletion wave removes source and any newly proven-dead
implementation dependencies.

- [ ] all transport, overload, fallback, supervision, daemon-failure, privacy, cross-platform, catastrophic-risk, safe-autonomy, performance, fuzz, chaos, soak, artifact, review, and rollback gates pass;
- [ ] dead replaced Python code is removed and retained Python ownership is explicit;
- [x] a dedicated PR changes eligible PostToolUse source default to `auto` with installed-wheel and rollback evidence;
- [ ] `release/3.0` remains unmerged to `main` during this program.

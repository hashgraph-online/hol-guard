# Takeaway Prompt: HOL Guard Rust Runtime Hardening

Copy and give the prompt below to the implementation agent.

```text
You are taking over HOL Guard's Rust runtime hardening and cross-platform production-readiness work.

Repository:
- https://github.com/hashgraph-online/hol-guard
- Base every pull request on the latest `release/3.0`.
- Do not merge `release/3.0` into `main`.
- Do not retarget or merge the release train PR into `main`.
- Do not push directly to protected branches.
- Use clean branches and reviewable pull requests.
- Keep the canonical checkout read-only if a local checkout is available. Use clean worktrees for edits.
- Re-read the latest repository state before changing anything because other agents may have advanced `release/3.0`.

Primary specifications:
- `docs/guard/rust-runtime-migration-prd.md`
- `docs/guard/rust-runtime-migration-todo.md`
- `docs/guard/rust-runtime-hardening-prd.md`
- `docs/guard/rust-runtime-hardening-todo.md`
- `docs/guard/adr/0008-native-resident-protocol-and-admission.md`
- `docs/guard/adr/0009-native-and-daemon-critical-failure.md`
- `docs/guard/rust-runtime-threat-model-delta.md`
- `docs/guard/contracts/rust-native-capability-ownership.v1.json`
- `docs/guard/contracts/rust-native-fail-safe-matrix.v1.json`
- `docs/guard/contracts/rust-emergency-safe-profile.v1.json`
- `docs/guard/contracts/rust-native-reason-codes.v1.json`

Mission:
Make the Rust integration production-grade on Windows, macOS, and Linux without weakening HOL Guard's security model or developer experience.

HOL Guard's product contract:
- Safe, routine engineering work should proceed autonomously with minimal or no prompts.
- Catastrophic-capable actions must pause before the side effect occurs.
- Catastrophic risks include secret exfiltration, prompt injection, broad file deletion or corruption, destructive production database or infrastructure actions, supply-chain compromise, and attempts to disable or overload Guard.
- PostToolUse output must not reach the model until it has been safely reviewed.
- A timeout, crash, overload, stale policy, invalid artifact, transport failure, or parser uncertainty must never become an unsafe allow.
- If Python and Rust disagree, choose the more restrictive outcome and record only a privacy-safe mismatch category.
- A Rust crash must not crash the Python daemon.
- A Python daemon crash or authenticated daemon-unavailable state is a critical failure and must invoke the documented fail-safe hook behavior.
- Native performance must remain excellent at the actual hook boundary, including transport, parsing, scanning, policy, and response decoding.
- The native runtime must resist local denial-of-service by a compromised same-user agent or process.

Current architecture that must be preserved unless the specification explicitly changes it:
- The public product remains a Python package.
- Python remains authoritative for policy authoring, approvals, durable grants, receipts, cloud, MDM, dashboard, containment orchestration, and third-party scanners.
- Rust remains a standalone contained executable, not an in-process Python extension for the critical hook path.
- Native discovery does not use PATH and does not download binaries.
- Version-matched wheels bind package version, source SHA, rule digest, runtime hash, size, target, and platform tag.
- The pure-Python backend and wheel remain available.
- Native authority remains default-off until the dedicated release gate.
- `plugin-scanner` remains pure Python.
- First-party Rust crates continue to forbid unsafe code.
- Do not weaken existing payload, scan, path, timeout, approval, containment, or artifact checks.

Known high-priority gaps to verify and fix:
1. The resident accept loop must not block while waiting for evaluator capacity.
2. Slow clients must not hold a worker indefinitely.
3. POSIX needs message-level mutual authentication in addition to owner-only socket permissions.
4. Resident execution needs fixed workers or an equivalently bounded executor, a bounded queue, and deadline-aware admission.
5. Native one-shot and Python fallback must be globally bounded so overload cannot create a process storm.
6. Native child health must be proactively supervised and process-exit driven, not only discovered on the next request.
7. Crash loops need bounded restart, backoff, circuit breaking, and a healthy half-open probe.
8. Daemon-unavailable behavior must be explicit and fail-safe for every hook.
9. Differential, performance, DoS, and recovery tests must run against installed wheels on Linux, macOS Intel, macOS Apple Silicon, and Windows x64.
10. The native PostToolUse path needs security evidence for prompt injection as well as secret scanning.
11. Native PreToolUse allow authority must remain disabled until POSIX, PowerShell, CMD, wrapper, redirect, substitution, and policy parity is proven.
12. The existing migration TODO must be corrected to reflect work already completed by later pull requests.

Required implementation order:

PR 1: Source-of-truth correction
- Inventory current code, workflows, merged PRs, and branch state.
- Update the existing Rust PRD and TODO.
- Add or update ADRs for resident protocol v2, overload behavior, fallback amplification, supervision, daemon failure, and rollback.
- Add the executable fail-safe action matrix and stable public reason codes.
- Do not change native authority.

PR 2: Transport and DoS hardening
- Implement resident protocol v2 with request and response binding.
- Use audited HMAC primitives and cross-language vectors.
- Add mutual authentication on POSIX while retaining socket ownership and mode checks.
- Validate framing and structure before allocation or expensive work.
- Add authentication, header, payload, evaluation, and response deadlines.
- Make the accept loop non-blocking with respect to worker capacity.
- Use a fixed worker pool, bounded async executor, or equivalent bounded design.
- Add a fixed queue and immediate overload behavior.
- Use RAII capacity guards.
- Reject poisoned or unexpected socket paths safely.
- Add slowloris, malformed frame, oversized frame, auth flood, and same-user local DoS tests.
- Do not expand decision authority.

PR 3: Supervision, fallback, and daemon critical-failure behavior
- Add explicit native health states and process-generation identity.
- Prewarm outside the first interactive hook.
- Detect process exit from the child handle.
- Restart asynchronously with bounded backoff and jitter.
- Add crash-loop circuit breaking and one half-open probe.
- Add zero-downtime rotation after bounded uptime or request count.
- Bound native one-shot and Python fallback globally.
- Prevent resident failure from causing a process-spawn storm.
- Implement the fail-safe action matrix for native and daemon failures.
- Add process kill, panic, hang, stale endpoint, port or socket contention, stale binary, stale manifest, stale policy, disk, permission, and crash-loop tests.
- Do not expand decision authority.

PR 4: Cross-platform installed-wheel gates
- Refactor tests so the same real-wheel suites run on:
  - Linux x64 on Ubuntu 22.04 and 24.04
  - macOS Intel
  - macOS Apple Silicon
  - Windows x64
- Add CPython 3.10 through 3.14 smoke.
- Add pip, pipx, uv tool, offline wheelhouse, upgrade, downgrade, reinstall, rollback, Desktop, and managed-install smoke.
- Run real resident parity, mutation, overload, crash, daemon-failure, path, privacy, and performance tests on each Tier 1 target.
- Cover Windows reparse and Job Object behavior, macOS APFS and socket paths, and Linux static binary, permissions, noexec, and stale sockets.
- Upload aggregate evidence only and scan artifacts for prohibited data.

PR 5: Catastrophic-risk effect and detector parity
- Define a versioned, privacy-safe effect model shared by Python and Rust.
- Keep durable and cross-request correlation in Python.
- Add secret read and network sink effects and read-then-exfil correlation.
- Expand secret exfiltration fixtures across shells, encodings, archives, cloud CLIs, GitHub CLI, webhooks, and language runtimes.
- Add deterministic prompt-injection scanning for untrusted tool output, preserving documentation and fixture context.
- Start prompt-injection work in shadow or tightening-only mode.
- Add mass deletion effects for POSIX, PowerShell, CMD, language runtimes, Git, package managers, and cloud storage.
- Add production database and infrastructure destructive effects.
- Add Guard tampering and flood-then-retry sequences.
- Preserve parser uncertainty. An uncertain dangerous command pauses.
- Do not make incomplete native PreToolUse parsing authoritative for allows.
- Require 100 percent pause or deny on the approved catastrophic corpus and zero unsafe Rust-over-Python downgrades.

PR 6: DX, diagnostics, privacy-safe observability, and rollout controls
- Add `hol-guard doctor --native`.
- Add machine-readable native runtime status.
- Add idempotent repair.
- Add clear distinction between policy pause, native degradation, overload, circuit open, and daemon failure.
- Keep normal healthy backend selection invisible.
- Provide scoped approval and containment choices for dangerous actions.
- Never expose raw commands, prompts, output, paths, destinations, environment values, database strings, secrets, tokens, or proofs in diagnostics or telemetry.
- Add aggregate bounded metrics and privacy tests.
- Add local and managed kill switches.
- Document rollback.
- Do not change the default.

Later dedicated release-gate PR:
- Change the default only for eligible PostToolUse after every required gate passes.
- Do not enable PreToolUse native allow authority in the same PR.
- Retain Python and the pure fallback for at least two stable release cycles.

DoS requirements:
- Treat same-user local processes as untrusted.
- Bound active handshakes, active evaluations, queued evaluations, fallback processes, input bytes, output bytes, JSON depth, keys, collection items, strings, file reads, scanner work, CPU deadlines, logs, restarts, and lifecycle events.
- The accept loop must never wait indefinitely for capacity.
- Saturated requests must receive a constant-size overload result or clean close before payload parsing.
- Unauthenticated handshakes must have a separate small capacity and failure rate budget.
- No connection may hold capacity beyond its deadline.
- No panic or early return may leak capacity.
- No one-shot fallback storm is allowed.
- Overload must not prevent health, shutdown, or repair operations.
- Under 64 slow or mixed clients, the runtime must remain alive and legitimate traffic must either meet the SLO or receive an explicit bounded fail-safe response.

Crash requirements:
- Native crash detection p95 target: 250 ms or better.
- Native recovery p95 target: 1 second or better and outside the requesting hook.
- Python daemon recovery p95 target: 2 seconds or better while hooks remain fail-safe.
- Repeated crashes open a circuit and keep Python authoritative.
- A native crash during a request may use Python only if deadline and capacity remain.
- A daemon crash must never allow a dangerous, network, secret-capable, destructive, package-executing, process-control, policy-tampering, or uncertain action.
- PostToolUse output remains blocked while the daemon is unavailable.
- Only the ratified authenticated emergency-safe read-only profile may continue.

Performance requirements:
- Measure installed-wheel adapter-to-decision latency.
- Small warm hook: p50 <=5 ms, p95 <=20 ms, p99 <=35 ms.
- 250 KiB output: p95 <=50 ms, p99 <=80 ms.
- 1 MiB source read and scan: p95 <=120 ms, p99 <=180 ms.
- Cold native one-shot: p95 <=100 ms and at least 5x faster than cold Python topology.
- Resident readiness: p95 <=250 ms.
- Overload rejection: p95 <=5 ms.
- Sixteen concurrent legitimate small requests: no errors and p99 <=100 ms.
- Sixty-four concurrent mixed requests: bounded completion or explicit overload, never a hang or unbounded queue.
- 100,000-request soak: zero crash and no more than 10 percent RSS growth after warm stabilization.
- Resident RSS remains at least 60 percent lower than the equivalent Python worker baseline unless a separately reviewed absolute cap is approved.
- Never reduce security scope to pass a benchmark.

Cross-platform security requirements:
- Windows:
  - Authenticated loopback only.
  - No payload before server proof.
  - Port squatting, malicious listener, auth flood, executable lock, long paths, case folding, junctions, reparse points, non-ASCII profile, firewall, and Job Object cleanup.
- macOS:
  - Intel and Apple Silicon.
  - APFS case-sensitive and case-insensitive behavior.
  - Owner-only authenticated Unix socket.
  - Socket path limits, symlinks, hardlinks, rename races, permissions, quarantine, and non-ASCII paths.
- Linux:
  - Static runtime proof.
  - Ubuntu 22.04 and 24.04.
  - Owner-only authenticated Unix socket.
  - Poisoned or stale sockets, symlinks, hardlinks, mounts, rename races, low file descriptors, noexec, and process or memory pressure.
- Unsupported platforms:
  - Pure-Python fallback.
  - No wrong binary.
  - Actionable diagnosis.

Security parity rules:
- Compare decision, output action, reason code, notice, policy action, observed action, reviewed output hash, excerpt hash, effect model, parser confidence, uncertainty, and approval floor.
- Rust may not allow when Python pauses or denies.
- Rust may not expose more output.
- Rust may not omit a catastrophic effect.
- Rust may not treat uncertainty as exact.
- A stricter Rust result must be deterministic, documented, and false-positive tested.
- Any unsafe or unexplained mismatch blocks native authority.

Developer experience rules:
- No Rust toolchain is required for users.
- Safe existing developer workflows must remain silent and autonomous.
- False-pause rate on the approved safe corpus must remain below 0.5 percent.
- Pause messages state the risk category and bounded scope without exposing secrets.
- Approval is scoped and broad permanent approval is never the default.
- Repair is one command, idempotent, non-destructive, and does not remove approvals or configuration.
- Managed settings cannot be weakened locally.

Privacy rules:
Never persist or upload:
- raw commands
- raw prompts
- tool output
- file contents
- secret samples
- full paths
- environment values
- database strings
- network destinations
- auth tokens or proofs
- arbitrary exception text

Permitted aggregate evidence:
- backend
- health state
- public risk class
- disposition
- request-size bucket
- cost class
- latency histogram
- queue bucket
- overload count
- auth-failure count
- timeout category
- fallback category
- crash count
- restart count
- circuit state
- differential mismatch category

Required validation:
- `cargo fmt --all --check`
- `cargo clippy --locked --workspace --all-targets -- -D warnings`
- `cargo test --locked --workspace --all-targets`
- Cargo dependency advisory, source, and license gates
- Python Ruff lint and format
- BasedPyright
- Relevant Python test shards
- Native protocol, auth, overload, recovery, differential, mutation, rule-contract, identity, wheel, privacy, path, performance, fuzz, chaos, and soak gates
- Linux, macOS Intel, macOS Apple Silicon, and Windows x64 installed-wheel gates
- CPython 3.10 through 3.14 smoke
- CodeQL
- Security Gates
- Full repository CI
- Diff and test-suite ratchets
- No skipped required gate and no baseline inflation without reviewed evidence

PR and review requirements:
- Keep PRs focused and ordered by the sequence above.
- Include threat model, exact files, tests, and measured evidence in each PR description.
- Do not include raw user or machine data.
- Resolve every code-review thread with a real fix or a documented, evidence-backed rejection.
- Do not dismiss a failure as flaky without reproducing and proving the cause.
- Rerun failed jobs after fixing the root cause.
- Do not weaken or delete a test merely to make CI green.
- Do not merge until every required check and review is complete.
- Merge only into `release/3.0`.
- Do not merge `release/3.0` into `main`.

Completion standard:
Do not stop after creating docs, scaffolding, a partial implementation, or one passing platform. Continue end to end until the scoped PR is implemented, reviewed, green, and merged into `release/3.0`, or until a genuinely external permission or infrastructure dependency makes completion impossible. When blocked externally, leave the repository in a clean, reviewable, fail-safe state and report the exact external blocker.

Final report for each PR:
- PR URL and merge commit
- Scope completed
- Security invariants proven
- Cross-platform evidence
- Performance evidence
- DoS and crash evidence
- Privacy evidence
- Review and CI status
- Remaining work mapped to the next task IDs
```

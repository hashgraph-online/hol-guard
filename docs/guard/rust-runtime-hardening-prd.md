# HOL Guard native runtime hardening PRD

Status: accepted follow-up for `release/3.0`.

## Objective

Make the bundled Rust runtime a cross-platform, low-latency safety kernel for catastrophic AI-agent risks while preserving the Python control plane, exact approval semantics, and safe autonomous developer workflows.

The native kernel must reliably pause or block secret exfiltration, prompt injection, broad deletion, destructive production database or infrastructure actions, supply-chain compromise, and Guard tampering. Routine reads, tests, builds, linting, bounded workspace edits, and exact low-impact cleanup must remain quiet and autonomous.

Eligible PostToolUse and supported PreToolUse review use the verified bundled Rust runtime in `auto` mode by default. Python remains the control plane and explicit differential-test oracle; it is never a production semantic fallback. `HOL_GUARD_NATIVE=off` is an explicit fail-safe disablement, and shadow comparison is diagnostic-only.

## Security invariants

1. Rust never lowers the canonical action, approval floor, or output restriction.
2. When native PostToolUse review completes, blocked output never reaches the model. When that review cannot complete, the turn continues because the tool already ran.
3. Unknown parsing, stale policy, exhausted scan budget, overload, or daemon unavailability never becomes an unsafe high-impact PreToolUse allow.
4. Same-user local processes are untrusted until message-level authentication succeeds.
5. Every connection, frame, allocation, parser, scanner, worker, queue, subprocess, log, restart, and fallback is bounded.
6. The resident Rust child remains outside the Python process and runs through the existing containment and process-tree cleanup boundary.
7. Runtime selection remains package-bound: no `PATH` discovery, runtime download, writable or foreign-owned executable, symlink, version skew, rule skew, or manifest mismatch.
8. Raw commands, prompts, output, paths, endpoints, database strings, environment values, secrets, tokens, and proofs are forbidden from diagnostics, metrics, logs, and CI artifacts.

## Fail-safe decision model

Internally preserve three outcomes:

- `allow`: exact bounded low-risk work.
- `pause`: potentially legitimate but catastrophic-capable work requiring an exact approval, narrower action, dry run, or containment.
- `hard_block`: known exfiltration, Guard bypass/tampering, invalid integrity, or non-overridable policy violation.

During native failure:

`resident Rust -> bounded verified one-shot Rust -> fail-safe pause/block`

A resident crash must not retire a healthy Python daemon. Restart occurs outside the requesting hook under a single-flight supervisor. Repeated crashes open a circuit.

During Python daemon failure:

- PostToolUse output is withheld when native review blocks it. When the daemon cannot complete PostToolUse review, the turn continues because the tool already ran.
- Mutating, network, secret-capable, destructive, package-executing, process-control, policy-tampering, and uncertain PreToolUse operations pause.
- Only the authenticated exact emergency-safe profile may continue.
- Empty or malformed responses are never treated as successful execution.

## Target architecture

- **Harness adapters:** authenticate the daemon and enforce daemon-unavailable fail-safe behavior.
- **Python daemon:** policy, approvals, receipts, containment, durable correlation, health orchestration, and explicit differential-test oracle support.
- **Rust resident runtime:** bounded parsing, output traversal, secret and prompt-injection fast paths, secure source reads, hashing, effect extraction, and eligible decisions.
- **Native supervisor:** child identity, health, prewarm, restart, rotation, circuit breaking, and fallback budgeting.
- **Authenticated policy snapshot:** immutable, versioned native inputs bound to package/rule/policy identity.
- **Privacy-safe health surface:** enumerated status and aggregate latency, queue, overload, fallback, crash, restart, and mismatch evidence.

## Resident protocol v2

Protocol v2 must include:

- request ID and SHA-256 digest;
- operation and operation-specific size cap;
- deadline budget;
- protocol, runtime, rule, and policy identities;
- response binding to the request ID/digest and serving generation;
- strict duplicate-field, trailing-data, UTF-8, depth, width, item, key, and string validation;
- independent authentication, header, payload, evaluation, and write deadlines;
- a fixed-size overload response that does not parse or echo payload content.

Linux/macOS retain owner-private Unix sockets and add the same per-process mutual authentication used by Windows. Windows retains authenticated IPv4 loopback unless a separately reviewed named-pipe design proves stronger ACL and spoofing properties.

The accept loop may not wait for evaluator capacity. Use fixed workers and a bounded queue or equivalent. Reserve capacity for authenticated health and shutdown operations.

## Availability and overload

Native health states are:

`disabled`, `starting`, `healthy`, `degraded`, `recovering`, `overloaded`, `circuit_open`, `incompatible`.

Requirements:

- prewarm outside the first interactive hook;
- retain and monitor the actual child handle;
- asynchronous restart with exponential backoff, jitter, and bounded budget;
- one half-open probe after cooldown;
- bounded one-shot queue;
- no fallback process storm;
- zero-downtime generation rotation after bounded uptime or request count;
- stale sockets, ports, binaries, manifests, policy snapshots, and generation responses rejected;
- overload cannot prevent health, shutdown, doctor, repair, or rollback.

## Catastrophic-risk coverage

The versioned privacy-safe effect model represents:

- sensitive reads;
- network and upload sinks;
- subprocess and package execution;
- file writes and exact/bounded/recursive deletion;
- database mutation;
- infrastructure mutation;
- Guard tampering;
- confidence, uncertainty, scope, target class, reversibility, containment, and approval floor.

Python retains durable cross-request correlation. Required sequences include sensitive-read then external transmission, and Guard-disable attempt then retry of a blocked action.

Corpora must cover:

- secrets from `.env`, SSH, cloud, package registries, Git, Docker, Kubernetes, wallets, signing, databases, and CI;
- direct, piped, encoded, archived, compressed, chunked, shell-wrapped, cloud-CLI, GitHub-CLI, webhook, and language-runtime exfiltration;
- prompt injection from repository/web/issue/PR/log/MCP/tool output, concealment, Guard bypass, exact secret reads, and encoded or nested text;
- POSIX, PowerShell, CMD, Git, package-manager, language-runtime, and cloud mass deletion;
- destructive SQL, migrations, schema resets, backups, cloud databases, clusters, namespaces, buckets, IAM, secrets, and broad resource groups;
- binary, policy, approval, hook, socket, daemon, and evidence tampering.

An uncertain dangerous command pauses. Native PreToolUse may first contribute tightening-only signals. Native low-risk allow authority is a later gate requiring POSIX, PowerShell, CMD, wrapper, redirect, substitution, effect, and policy parity.

## Cross-platform release matrix

Tier 1 native targets:

- Linux x86-64 on Ubuntu 22.04 and 24.04;
- macOS Intel;
- macOS Apple Silicon;
- Windows x86-64.

Required installed-artifact coverage:

- CPython 3.10 through 3.14;
- `pip`, `pipx`, `uv tool`, offline wheelhouse, upgrade, downgrade, reinstall, rollback, Desktop, and supported managed install;
- real resident parity, mutation, overload, crash, daemon-failure, path, privacy, and performance tests.

Windows adds PowerShell 5.1/7, CMD, reparse points, junctions, UNC/device/extended paths, case folding, Job Objects, executable locks, antivirus quarantine, and malicious listener/port races.

macOS adds APFS case modes, aliases, symlinks, hardlinks, mounts, socket path limits, quarantine/signing/notarization, sleep/wake, and process-group cleanup.

Linux adds static-runtime proof, secure path walks, bind/overlay mounts, namespaces/containers, low descriptor limits, cgroups, noexec, read-only Guard homes, and stale socket attacks.

Unsupported platforms must provide actionable diagnosis and fail-safe for supported hook events. Python semantic evaluation remains available only through explicit differential-test fixtures.

## Performance and resource SLOs

Measure installed adapter-to-decision latency, not direct library calls.

- safe warm PreToolUse: p50 <= 1 ms, p95 <= 5 ms, p99 <= 10 ms;
- high-risk command analysis: p95 <= 10 ms, p99 <= 20 ms;
- small warm PostToolUse: p95 <= 20 ms, p99 <= 40 ms;
- 250 KiB PostToolUse: p95 <= 50 ms;
- 1 MiB secure source read/scan: p95 <= 120 ms;
- 5 MiB maximum request: p95 <= 350 ms;
- cold verified one-shot: p95 <= 100 ms and at least 5x faster than cold Python;
- resident readiness: p95 <= 250 ms;
- overload rejection: p95 <= 5 ms;
- native crash detection: p95 <= 250 ms;
- native recovery: p95 <= 1 second outside the requesting hook;
- Python daemon recovery: p95 <= 2 seconds while hooks remain fail-safe;
- 16 legitimate concurrent requests: no errors, p99 <= 100 ms;
- 64 mixed requests: bounded result or explicit overload, never a hang;
- 100,000-request soak: zero crash and <= 10% RSS growth after stabilization.

Resident RSS must remain at least 60% below the equivalent Python worker baseline unless a separately reviewed absolute cap is approved. No security limit may be weakened to pass a benchmark.

## Developer experience

Add:

- `hol-guard doctor --native`;
- `hol-guard runtime status [--json]`;
- idempotent native lifecycle repair;
- exact distinction between policy pause, native degradation, overload, circuit open, and daemon failure;
- plain-language scoped approval choices without secret disclosure;
- local and managed native kill switches;
- privacy-safe bounded support evidence.

Healthy backend selection remains invisible. The safe-corpus false-pause rate must remain below 0.5%.

## Dead Python cleanup

Maintain `docs/guard/contracts/hook-data-plane-ownership.v2.json`.

For every capability, classify Python code as:

1. required control plane;
2. active named differential-test oracle exercised in CI;
3. dead duplicate.

Delete category 3 only in a separately authorized deletion change. Replaced, unreachable, or untested Python runtime implementations are dead code, not
dormant rollback. NHD-091–095 makes the first package boundary explicit:
`docs/guard/contracts/python-capability-ownership.v1.json` classifies the full
hook/runtime scope, `scripts/ci/python_capability_cleanup_gate.py` proves
source/runtime reachability and package content, and the six-case parity
fixture is language-neutral. The superseded Python resident source is retained
but excluded from wheels/sdists and recorded as the sole deletion candidate;
source deletion, tests/imports/dependencies/flags/shims removal, and any other
category-3 cleanup remain separate until their rollback boundary is reviewed.
Record Python LOC/dependency deltas for each authorized removal.

Do not remove the active Python differential-test oracle while this PRD requires it. A production semantic fallback is forbidden; an untested oracle is dead code and must be removed.

## Rollout gates

1. Documentation, contracts, threat model, SLOs, ownership, and emergency profile.
2. Protocol v2, cross-platform authentication, bounded admission, workers, deadlines, and fallback circuit breakers.
3. Supervision, crash safety, daemon-unavailable behavior, and recovery.
4. Equivalent Tier 1 installed-wheel evidence.
5. Catastrophic-risk effect/detector parity and safe-corpus autonomy.
6. DX, diagnostics, privacy, repair, and rollout controls.
7. Dedicated eligible PostToolUse default-`auto` PR with installed-wheel and rollback evidence.
8. Separate future expansion of native authority only after the remaining independent security and catastrophic-risk gates pass.
9. Separate future PreToolUse authority PR.

`release/3.0` must not be merged into `main` as part of this work.

## Definition of done

- Slow or unauthenticated clients cannot starve the resident runtime.
- Every resource and recovery path is bounded.
- Native and daemon failures are isolated, detected, recovered, circuit-broken, and fail-safe.
- Equivalent installed wheels pass parity, performance, DoS, crash, path, privacy, DX, and rollback gates on all Tier 1 targets.
- Catastrophic corpora have zero unsafe downgrades and required 100% pause/deny coverage.
- Safe autonomy and false-pause gates pass.
- Native doctor/status/repair are accurate and privacy safe.
- Dead replaced Python code is deleted; active Python control/reference code is explicitly retained and tested.
- Cargo lock/fmt/Clippy/tests/audit/deny/SBOM/provenance, CodeQL, Security Gates, fuzz, differential, chaos, soak, CI, and review gates pass.
- Eligible supported-hook source default is `auto`; explicit `off` is a fail-safe disablement, shadow is diagnostic-only, and Python control/oracle ownership remains covered by differential tests.

# HOL Guard Rust runtime migration

Status: implementation in progress on the 3.0 prerelease train.

## Objective

Keep `hol-guard` primarily a Python package while moving latency-sensitive deterministic runtime work to Rust. The goal is materially lower end-to-end hook latency, process count, CPU, and RSS without changing the public CLI/API, action lattice, approval semantics, reason-code contracts, or containment guarantees.

## Architecture

Python remains authoritative for CLI/API presentation, config and policy authoring, approvals, SQLite migrations and durable receipts, dashboard, cloud sync, MDM, MCP, Cisco/LiteLLM integration, and containment orchestration. A standalone Rust executable owns eligible PostToolUse payload traversal, secret scanning, secure source reads, hashing, path validation, and decision composition. Later waves may add command parsing/evaluation, safe decode, and bounded package-tree work only after profiling and parity proof.

## Current performance premise

The existing 3.0 baseline shows `evaluate_command()` is already sub-millisecond. The primary opportunity is eliminating interpreter startup, nested Python worker/guardian/evaluator processes, repeated imports, JSON/pipe coordination, and Python-heavy file/output scanning from the interactive hook path. Performance claims must therefore be measured from actual adapter or installed-wheel boundaries, not only direct engine calls.

## Performance gates

After cross-platform baselines are ratified, require both relative and absolute improvement: warm small PostToolUse at least 3x and p95 <=20 ms; 250 KB at least 3x and <=50 ms; 1 MB source read at least 3x and <=120 ms; cold one-shot at least 5x and <=100 ms; runtime readiness at least 3x and <=250 ms; 16-way fixed-resource throughput at least 4x; resident hook RSS at least 60% lower. No security budget or scan scope may be weakened to hit these numbers.

## Migration waves

1. Evidence and benchmark correction.
2. Rust workspace, protocol contracts, rule metadata, CI and provenance.
3. Bounded output traversal and secret scanner parity.
4. Secure source-read parity using validated handles and bounded reads.
5. Native PostToolUse engine with differential fixtures.
6. Resident native runtime plus one-shot fallback.
7. Python facade and shadow mode.
8. Version-matched platform packaging and installed-wheel canaries.
9. Direct harness PostToolUse transport.
10. Profile-gated PreToolUse, safe decode, and supply-chain acceleration.
11. Dedicated default-enable PR after security, parity, rollback, and performance gates.

## Non-goals

Do not rewrite the dashboard, cloud plane, MDM, whole daemon, gVisor/OCI/Kubernetes integration, or third-party Python scanners merely to increase Rust percentage. Do not remove the Python reference backend during the first stable release carrying native support.

## Release blockers

Any Python/native mismatch that would lower a decision, expose more model-visible output, change a security-critical reason, weaken path handling, or create unbounded memory/process behavior blocks native authority. Any crash, version mismatch, stale endpoint, binary replacement, or unavailable native target falls back to the Python reference path unless an existing stronger fail-closed contract applies.

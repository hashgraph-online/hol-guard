# HOL Guard Rust runtime migration

Status: foundation implemented on the 3.0 prerelease train. The canonical follow-up is `docs/guard/rust-runtime-hardening-prd.md`.

## Objective

Keep `hol-guard` primarily a Python-facing package while moving latency-sensitive deterministic enforcement into the version-matched Rust safety kernel. Native work must reduce hook latency and process overhead without weakening action, approval, reason-code, path, containment, privacy, or artifact-integrity contracts.

## Current architecture

Python remains the control plane for CLI and API presentation, configuration and policy authoring, approvals, SQLite migrations and durable receipts, dashboard, cloud sync, MDM, MCP, Cisco/LiteLLM integration, and containment orchestration.

The bundled standalone Rust runtime now provides:

- Bounded PostToolUse payload traversal and secret scanning.
- Bounded generic PreToolUse action extraction and classification, including
  the command parser's conservative floors.
- Bounded secure source reads, hashing, sensitive-path handling, and decision composition.
- Versioned request/response contracts and exact rule-contract provenance.
- Resident Unix-domain-socket transport on POSIX.
- Mutually authenticated IPv4-loopback resident transport on Windows.
- Bounded native one-shot fallback.
- A shadow-only command model for a conservative POSIX subset.
- Version-matched Linux x64, macOS Intel, macOS Apple Silicon, and Windows x64 wheel artifacts plus a pure-Python compatibility wheel.
- Manifest binding for package version, source SHA, rule digest, platform tag, runtime digest, and runtime size.

Native execution remains source-default `off`. Python is authoritative in `off`
and `shadow`; `auto` and `force` use the native generic PreToolUse and
PostToolUse results under the current compatibility contract. Supported
PreToolUse action classification and command floors remain Rust-owned in
those native modes; Python retains only explicit compatibility and approval
presentation boundaries.

## Current performance premise

The dominant opportunity is avoiding interpreter startup, nested Python worker processes, repeated imports, and Python-heavy output and file scanning. Performance is measured from installed adapter and hook boundaries. The current minimum gates remain warm resident p95 <=20 ms, cold one-shot p95 <=100 ms with at least 5x cold speedup, and readiness <=250 ms. The hardening PRD adds overload, recovery, concurrency, memory, and cross-platform installed-wheel gates.

## Completed migration waves

1. Evidence and benchmark correction.
2. Pinned Rust workspace, protocol contracts, rule provenance, CI, and artifact identity.
3. Bounded output traversal and secret scanner parity.
4. Secure source-read parity for the supported source-ref contract.
5. Native PostToolUse engine and differential fixtures.
6. Resident runtime plus one-shot fallback.
7. Python facade, shadow mode, and native-first opt-in modes.
8. Version-matched platform wheel assembly and trusted publication integration.
9. Shadow command model and privacy-safe live observation.
10. Authenticated Windows residency.

## Remaining release gates

The canonical remaining work is tracked in `docs/guard/rust-runtime-hardening-todo.md` and includes protocol v2, authentication-first bounded admission, fixed workers, overload and fallback circuit breaking, crash supervision, daemon fail-safe behavior, cross-platform installed-wheel parity and performance, catastrophic-risk effect expansion, DX, privacy-safe diagnostics, and capability-by-capability deletion of dead Python duplicates.

## Non-goals

Do not rewrite the dashboard, cloud plane, MDM, approvals, durable receipts, containment providers, or third-party scanners merely to increase Rust percentage. Do delete Python runtime implementations once they are replaced, unreachable, and no longer part of a named supported compatibility path.

## Release blockers

Any native mismatch that lowers severity, exposes more model-visible output, broadens approval, weakens path handling, creates unbounded resource use, or converts runtime failure into an unsafe allow blocks native authority. After a capability cuts over, the valid recovery chain is verified resident Rust, bounded verified one-shot Rust, then fail-safe pause.

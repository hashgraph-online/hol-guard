# HOL Guard Rust runtime migration TODO

Status: foundation complete. The canonical hardening and rollout backlog is `docs/guard/rust-runtime-hardening-todo.md`.

## Foundation

- [x] Add migration PRD and architecture ADR.
- [x] Select a standalone Rust runtime as the native boundary.
- [x] Add packaging ADR and keep `plugin-scanner` pure Python.
- [x] Add a pinned, unsafe-forbidden Rust workspace with separated contracts, rules, scanner, secure-fs, hook-core, policy-snapshot, rule-contract, command, and runtime crates.
- [x] Add versioned native hook DTOs, bounded protocol caps, capabilities, and exact rule digest.
- [x] Port bounded model-visible output traversal.
- [x] Port initial secret families, sample suppression, rolling context, match limits, deadlines, and early exit.
- [x] Add bounded source reads with no-follow final open, symlink-component rejection, identity validation, SHA-256, and strict UTF-8.
- [x] Add native PostToolUse inline and source-ref decision paths.
- [x] Add native one-shot hook, capabilities, self-test, Unix framed serve, and authenticated Windows resident serve.
- [x] Add a Python native facade with `off`, `shadow`, `auto`, and `force` modes and no PATH discovery.
- [x] Commit Cargo.lock from the pinned dependency graph.
- [x] Add bundled-runtime discovery, manifest identity, rule-contract v2, and package/source/runtime binding.
- [x] Produce native Linux x64, macOS Intel, macOS Apple Silicon, and Windows x64 wheels while retaining the pure-Python compatibility wheel.
- [x] Integrate native wheel assembly into trusted 3.0 alpha publication.
- [x] Add shadow command-model parsing and resident command evidence.
- [x] Add mutation differential, recovery, performance, Windows resident, and installed-wheel workflows.

## Canonical remaining work

Reconciled 2026-10-30 against `main` at `755022afa0`, shipping as 3.58.0.

- [x] Prove protocol v2, authentication-first admission, fixed worker and queue bounds, overload behavior, fallback circuit breaking, and crash supervision. Shipped: strict envelopes and caps (`resident_protocol.rs`, `strict_json.rs`), kernel peer identity (`resident_peer_identity.rs`), separated auth and evaluation lanes with bounded queues (`lib.rs`, `resident_worker_pool.rs`), a fixed `native_overloaded` answer instead of blocking (`resident_transport.rs`), bounded accept backoff (`hardening.rs`), the restart budget and crash circuit (`resident_restart_budget.rs`, `native_runtime_resilience.rs`), and recorded Python fallbacks (`hook_bridge_fallback.rs`). Cross-language golden vectors now bind each answer to the request that asked for it (NRH-T025, `edge-request-binding-v1`). Slowloris, authentication-flood and malformed-frame tests closed NRH-T035.
- [x] Move the hot path to native authority. PreToolUse is native-authoritative: `runtime_transition_admission.py` admits a runtime only after the native edge answers a known-allow and a known-deny probe and its receipts reconcile against runtime identity, policy generation, and policy digest. Python checks receipts; it never recomputes a verdict.
- [ ] Prove equivalent installed-wheel parity, performance, DoS, and recovery on all Tier 1 platforms and supported Python/install surfaces. Partial today through `nightly-native.yml`, `release-native-wheel.yml`, `release-native-determinism.yml`, and `rust-runtime-performance.yml`; the equivalent-suite matrix of NRH-T060 to NRH-T068 does not exist yet.
- [ ] Expand catastrophic-risk, prompt-injection, exfiltration, destructive filesystem, production database, infrastructure, supply-chain, and Guard-tampering evidence. Detection lives in `guard-command`; the versioned effect DTO, corpus, and measured parity gate (NRH-T080 to NRH-T092) are open.
- [x] Delete replaced or unreachable Python runtime implementations. The ownership and package proof landed (NHD-091 to NHD-095, NRH-T108, NRH-T110 to NRH-T112, NRH-T116, NRH-T119) and `native_runtime_resident.py` has been deleted. The deletion wave itself is finished: NRH-T109 and NRH-T113 to NRH-T117 are closed, `python-capability-ownership.v1.json` records 125 retired modules, 34 retired test paths and 38 retired bodies with `deletion_candidates` empty, and the command parsing NRH-T114 named reads through `guard-command` rather than Python. NRH-T118 is closed too: the sweep found no unreachable Python evaluator left. Every `except PolicyBundleNativeUnavailableError` and `except NativeRuntimeUnavailableError` in `src/` either re-raises or answers with the closed verdict — `review_verification_keyring.py` is the only one that returns, and it returns "not ready" — and `HOL_GUARD_PYTHON_ORACLE` is retired, with `python_capability_cleanup_gate.py` and `hook_data_plane_ownership_contract.py` failing any pull request that reintroduces it. The remaining matches for `fallback` name reachable backends, not a second evaluator.
- [x] Close the supply-chain and fuzz gaps. `rust/deny.toml` pins the allowed licences, sources and duplicate exceptions and the `Cargo supply chain` job in `security-gates.yml` runs `cargo deny check`, advisories included, on every pull request (NRH-T120); `fuzz.yml` carries a `rust` job that builds the nightly `cargo-fuzz` matrix over the eight targets in `rust/fuzz/fuzz_targets` and uploads their artifacts (NRH-T122).
- [ ] Keep every retained compatibility backend named and exercised in CI.
- [x] Ship from `main`. The earlier rule that `release/3.0` must stay unmerged is retired: the work landed on `main` through ordinary PRs, and `release/3.0` is now 3,629 commits behind with 8 commits that were never merged. Treat it as history, not a base.

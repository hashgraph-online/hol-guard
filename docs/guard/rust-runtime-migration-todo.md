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

- [ ] Complete every P0 and P1 item in `docs/guard/rust-runtime-hardening-todo.md`.
- [ ] Prove protocol v2, authentication-first admission, fixed worker and queue bounds, overload behavior, fallback circuit breaking, and crash supervision.
- [ ] Prove equivalent installed-wheel parity, performance, DoS, and recovery on all Tier 1 platforms and supported Python/install surfaces.
- [ ] Expand catastrophic-risk, prompt-injection, exfiltration, destructive filesystem, production database, infrastructure, supply-chain, and Guard-tampering evidence.
- [ ] Enable native authority only through dedicated release-gate pull requests.
- [ ] Delete replaced or unreachable Python runtime implementations in the same release wave as authority cutover.
- [ ] Keep every retained compatibility backend named and exercised in CI.
- [ ] Do not merge `release/3.0` into `main` as part of this work.

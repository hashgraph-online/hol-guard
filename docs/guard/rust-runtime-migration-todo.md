# HOL Guard Rust runtime migration TODO

The canonical execution backlog is grouped by release gate. Completed items must have code/tests or reproducible evidence, not only prose.

## Foundation

- [x] Add migration PRD and architecture ADR.
- [x] Select standalone Rust runtime as primary native boundary.
- [x] Add packaging ADR and keep `plugin-scanner` pure Python by design.
- [x] Add pinned Rust workspace and separated contracts/rules/scanner/secure-fs/hook-core/policy/runtime crates.
- [x] Add versioned native hook DTOs, protocol caps, capabilities and rule digest.
- [x] Port bounded model-visible output traversal.
- [x] Port initial secret families, sample suppression, rolling context, match limits, deadlines and early exit.
- [x] Add bounded source reads with no-follow final open, symlink-component rejection, identity validation, SHA-256 and strict UTF-8.
- [x] Add native PostToolUse inline and source-ref decision paths.
- [x] Add native one-shot hook, capabilities, self-test and Unix framed serve commands.
- [x] Add Python-only native facade with off/shadow/auto/force modes and no PATH discovery.
- [x] Commit Cargo.lock from the pinned CI-resolved dependency graph.
- [x] Add bundled-runtime discovery under the installed `hol-guard` package.
- [ ] Complete Windows named-pipe serve transport and reparse/final-path validation.
- [ ] Complete source-path parity for every external sibling-checkout and hidden-path case.
- [ ] Generate canonical security-rule manifests consumed by both Python and Rust.

## Differential and performance gates

- [ ] Add golden request/response fixtures for every supported harness.
- [ ] Run all eligible hook fixtures in Python, shadow and native-force modes and compare decision, output action, reason code, notice, proof, match metadata and excerpt hash.
- [ ] Add persistent fuzz targets for protocol frames, output traversal, scanner and source-read request/path handling.
- [ ] Add file replacement, rename, symlink swap, truncation and permission-race tests.
- [ ] Extend installed-wheel benchmarks for warm/cold/off daemon, Python fallback, native one-shot, resident native, overload/crash/recovery, 1/4/8/16 concurrency, cache hit/miss and 5 MB limits.
- [ ] Record p50/p95/p99/max, throughput, CPU, process count and RSS on Tier 1 platforms.
- [ ] Ratify absolute release thresholds without weakening relative speedup requirements.

## Packaging and direct hooks

- [ ] Produce version-identical platform-specific `hol-guard` wheels with the native executable injected only into supported Guard wheels.
- [ ] Preserve the existing pure-Python `hol-guard` wheel as unsupported-platform fallback and keep `plugin-scanner` pure Python.
- [ ] Add pip, pipx, uv tool, offline wheelhouse, CPython 3.10-3.14, MDM/PyInstaller and Desktop install proofs.
- [ ] Add SBOM, provenance, binary digest, target, protocol and rule-digest metadata to every bundled runtime artifact.
- [ ] Route eligible PostToolUse adapters directly to the resident runtime and use native one-shot as the cold fallback.
- [ ] Keep unsupported request types and platforms on Python.

## Later profiling waves

- [ ] Port canonical command parsing/evaluation only after PostToolUse is parity-proven and default-ready.
- [ ] Keep approval creation/durable grants Python-owned until an atomic bridge is proven fail-closed.
- [ ] Port safe decode only with deterministic parsers for constructs unsupported by Rust's linear-time regex engine.
- [ ] Profile package walking/hashing/manifest parsing and port only measured hotspots.
- [ ] Keep containment providers, cloud, MDM and third-party scanners out of the rewrite unless separately justified.

## Default enablement

- [ ] Complete threat-model delta and independent security review.
- [ ] Resolve every decision/output differential mismatch.
- [ ] Pass Tier 1 latency, throughput, RSS, process-count and installed-artifact gates.
- [ ] Pass crash, downgrade, stale-runtime, unsupported-platform and rollback drills.
- [ ] Enable `HOL_GUARD_NATIVE=auto` by default only in a dedicated release-gate PR.
- [ ] Retain `HOL_GUARD_NATIVE=off` and the Python reference backend through at least one stable release.

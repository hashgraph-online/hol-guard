## Summary
- Moves digest-bound offline archive inspection into `hol-guard-runtime`: new `archive-inspect --stdin` command backed by a `guard-archive` crate (immutable-blob admission via `guard-secure-fs`, tar/gzip member policy, `package.json` and Python build-metadata checks) under rlimits, a Linux seccomp deny list, and a network-capability probe that fails closed when containment is absent. macOS runs under the existing `sandbox-exec` profile.
- Adds the `archive-inspection-v1` runtime capability and `guard-archive-inspection.v1` / `guard-archive-inspection-result.v1` wire schemas.
- `supply_chain_package_eval` now calls a mechanical transport adapter (`native_archive_inspection.py`) that takes a per-Guard-home advisory lease, invokes the bounded child, and verifies the request id, request hash, result schema, and clean-result digest. There is no Python semantic fallback; transport or containment failures surface as `incomplete`.
- Removes the five `offline_archive_*` modules and their implementation tests; retirements are recorded in the capability ownership contract and runtime retirement ledger.
- Regenerates the command-program/catalog artifacts and raises the native capabilities probe timeout to 5s to stop cold-start false negatives from being cached for the process lifetime.

## Testing
- `cargo test --manifest-path rust/Cargo.toml -p guard-archive -p guard-secure-fs -p hol-guard-runtime -p guard-contracts`
- `cargo clippy --manifest-path rust/Cargo.toml --workspace --all-targets`
- `python -m pytest tests/test_native_archive_inspection.py` (62 passed, 1 skipped)
- `python -m pytest tests/test_guard_supply_chain_evaluator.py tests/test_guard_external_archive_approval_boundary.py tests/test_guard_external_archive_approval_evidence.py tests/test_guard_external_archive_launch_binding.py tests/test_guard_external_archive_private_binding.py` (128 passed)
- `python scripts/ci/rust_authority_ownership_gate.py` / `rust_io_privacy_gate.py` / `python_capability_cleanup_gate.py` / `python_hook_semantic_callgraph_gate.py` / `rust_pretool_no_python_gate.py` / `rust_io_ownership_gate.py` — all pass
- Built `hol_guard-3.13.1` native wheel locally and verified the bundled runtime through the installed adapter: clean archive passes with verified digest, forged digest returns `blocked/external_archive_digest_mismatch`, lifecycle script returns `blocked/tarball_install_script`

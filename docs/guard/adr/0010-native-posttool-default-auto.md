# ADR 0010: Default hook review to bundled Rust data plane

Status: accepted for `main`.

## Decision

HOL Guard 3.x selects native `auto` behavior when `HOL_GUARD_NATIVE` is not set, and the daemon hook fast path is enabled when `HOL_GUARD_HOOK_FAST_PATH` is not set. Published native wheels and Desktop Core sidecars use the verified, version-matched bundled Rust runtime as the semantic authority for supported `PreToolUse` and `PostToolUse` review on that default production path.

The native boundary begins at the raw hook envelope. Rust extracts the hook event and supported action, performs command classification, PostTool output extraction, source-reference validation, secure source reads, hashing/equivalence checks, and secret scanning. Structurally valid `PreToolUse` actions that are not yet modeled for automatic allow remain inside the Rust authority boundary and return conservative native review instead of automatically escaping to a Python evaluator.

Resident client authentication, request/response framing, digest validation, and local socket/loopback I/O are implemented by the bundled Rust runtime. Python remains a bounded control plane for daemon route authentication, resident lifecycle supervision, policy-snapshot transport, harness response rendering, approval presentation/continuation surfaces, and asynchronous non-authoritative evidence persistence.

## Security boundary

Automatic runtime selection is limited to the runtime bundled inside the installed `hol-guard` wheel or signed Desktop Core artifact. The runtime must pass executable ownership and permission checks plus manifest bindings for package version, protocol, source/build SHA, rule digest, byte digest, and size. Default `auto` does not search `PATH`, honor an arbitrary runtime override, download decision-time code, or call a network service.

Secret-bearing output remains blocked by the Rust path. Native unavailability, incompatibility, overload, timeout, malformed output, containment failure, client-authentication failure, framing failure, or digest mismatch fails closed. None of those failures can automatically enter the Python reference evaluator or become an allow.

## Explicit compatibility settings

`HOL_GUARD_NATIVE=off` and `shadow` are retained as explicit compatibility/reference modes. They are never selected automatically and are not entered because the Rust runtime failed.

- `off` preserves the Python reference/rollback surface for compatibility and emergency diagnosis.
- `shadow` preserves Python reference behavior while exercising native evaluation as non-authoritative evidence where supported.
- `auto`, including the no-environment default, is Rust-authoritative and fails closed on native failure.
- `force` is Rust-authoritative and remains available for developer validation and explicit runtime overrides.
- Invalid or empty mode values resolve to the product default instead of silently disabling Rust.

The permanent ownership gate distinguishes this explicit compatibility surface from automatic fallback. Python reference evaluators may remain reachable only after an operator explicitly selects `off` or `shadow`; they may not be reached from `auto`/`force` native failure.

## Evidence

The permanent ownership contract in `ci/rust-authority-ownership.v1.json` requires:

- no-environment native `auto` selection and enabled hook fast path;
- Rust semantic authority for supported PreToolUse and PostToolUse on `auto`/`force`;
- Rust raw hook-edge extraction on the default production path;
- Rust PostTool decision-critical content/file I/O;
- Rust resident-client authentication, framing, digest validation, and socket I/O;
- no automatic Python source-reference or semantic fallback;
- explicit Python compatibility limited to `off`/`shadow`;
- fail-closed native failure behavior.

`python scripts/ci/rust_authority_ownership_gate.py --root .` is the executable source-of-truth check for these ownership invariants.

CI builds and lints the complete Rust workspace, runs real-binary PreToolUse/PostToolUse adversarial integration, resident differential and mutation integration, performance gates, and installed native-wheel execution proof. Stable native-wheel and Desktop packaging tests must continue to validate the bundled runtime without requiring native or fast-path environment-variable configuration.
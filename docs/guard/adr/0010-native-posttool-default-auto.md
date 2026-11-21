# ADR 0010: Default eligible PostToolUse review to bundled Rust

Status: accepted for `main`.

## Decision

HOL Guard 3.x selects `HOL_GUARD_NATIVE=auto` when the variable is not set. The verified, version-matched Rust runtime is the exclusive semantic authority for supported command `PreToolUse` and `PostToolUse` review on published native wheels.

Python remains the control plane: authentication, transport, harness rendering, approval continuation, and bounded evidence. It is not a semantic fallback for those supported events. Unsupported inputs use the native conservative floor or fail closed; no automatic Python evaluator fallback is permitted.

## Security boundary

Automatic selection is limited to the runtime bundled inside the installed `hol-guard` wheel. The runtime must pass executable ownership and permission checks plus manifest bindings for package version, protocol, source/build SHA, rule digest, byte digest, and size. `auto` does not search `PATH`, honor an arbitrary runtime override, download code, or call a network service.

Secret-bearing output remains blocked by the Rust path. Native unavailability, incompatibility, overload, timeout, malformed output, or containment failure fail closed instead of becoming an allow or a Python rescan.

## Rollback

There is no local rollback, and there is no local disablement either. The
`off` and `shadow` values this ADR first described are retired: both stay
accepted so an existing install keeps starting, both resolve to the product
default, and each logs `native_mode_legacy_value_ignored` once. Honoring `off`
would mean running supported review with no semantic authority at all, and
honoring `shadow` would mean keeping a Python evaluator alive to compare
against. `force` requires native even for developer overrides. Invalid or empty
values resolve to the product default instead of silently disabling Rust.
`HOL_GUARD_NATIVE_DIAGNOSTIC=1` on a declared non-production surface adds
bounded transport and timeout diagnostics to that path; it evaluates nothing
and compares nothing.

## Evidence

Source contracts prove default, invalid and retired values all select `auto`, that a retired value warns exactly once, and that supported auto/force paths fail closed without Python semantic evaluation (`tests/test_native_legacy_modes.py`). Stable main publication uploads the four Tier 1 native wheels plus the pure wheel to PyPI; the sdist is attached to the GitHub release only. Native-wheel jobs install the real wheel on Linux x64, macOS Intel, macOS Apple Silicon, and Windows x64 with no native environment variable, then prove runtime attestation, clean-output allow, secret-output deny, and resident execution.

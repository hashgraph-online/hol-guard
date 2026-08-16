# ADR 0010: Default eligible PostToolUse review to bundled Rust

Status: accepted for `release/3.0`.

## Decision

HOL Guard 3.x selects `HOL_GUARD_NATIVE=auto` when the variable is not set. The verified, version-matched Rust runtime is therefore the first execution path for eligible PostToolUse review on Tier 1 native wheels.

Python remains the control plane and reference fallback. PreToolUse policy, approvals, receipts, and action authority remain Python-owned. Unsupported pure-Python wheels and any unavailable, incompatible, overloaded, timed-out, or invalid native response continue through the existing Python review path.

## Security boundary

Automatic selection is limited to the runtime bundled inside the installed `hol-guard` wheel. The runtime must pass executable ownership and permission checks plus manifest bindings for package version, protocol, source/build SHA, rule digest, byte digest, and size. `auto` does not search `PATH`, honor an arbitrary runtime override, download code, or call a network service.

Secret-bearing output remains blocked by the Rust path, while any failure to obtain a valid native result falls back to the Python safety engine rather than becoming an allow.

## Rollback

`HOL_GUARD_NATIVE=off` is the immediate local and managed rollback. `shadow` and `force` remain explicit diagnostic/developer modes. Invalid or empty values resolve to the product default instead of silently disabling Rust.

## Evidence

Source contracts prove default and invalid values select `auto`, explicit `off` disables native execution, and Python fallback remains available. Tier 1 native-wheel jobs install the real wheel on Linux x64, macOS Intel, macOS Apple Silicon, and Windows x64 with no native environment variable, then prove runtime attestation, clean-output allow, secret-output deny, resident execution, and explicit rollback.

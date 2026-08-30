# ADR 0010: Default eligible PostToolUse review to bundled Rust

Status: accepted for `main`.

## Decision

HOL Guard 3.x selects `HOL_GUARD_NATIVE=auto` when the variable is not set. The verified, version-matched Rust runtime is the exclusive semantic authority for supported command `PreToolUse` and `PostToolUse` review on published native wheels.

Python remains the control plane: authentication, transport, harness rendering, approval continuation, and bounded evidence. It is not a semantic fallback for those supported events. Unsupported `PreToolUse` tools still raise `HookWorkerUnsupported` so the existing CLI path can coordinate policy and approval UX.

## Security boundary

Automatic selection is limited to the runtime bundled inside the installed `hol-guard` wheel. The runtime must pass executable ownership and permission checks plus manifest bindings for package version, protocol, source/build SHA, rule digest, byte digest, and size. `auto` does not search `PATH`, honor an arbitrary runtime override, download code, or call a network service.

Secret-bearing output remains blocked by the Rust path. Native unavailability, incompatibility, overload, timeout, malformed output, or containment failure fail closed instead of becoming an allow or a Python rescan.

## Rollback

`HOL_GUARD_NATIVE=off` is the immediate local and managed rollback. `shadow` keeps Python authoritative while collecting native evidence. `force` requires native even for developer overrides. Invalid or empty values resolve to the product default instead of silently disabling Rust.

## Evidence

Source contracts prove default and invalid values select `auto`, explicit `off` disables native execution, and supported auto/force paths fail closed without Python semantic evaluation. Stable main publication uploads the four Tier 1 native wheels plus the pure wheel and sdist. Native-wheel jobs install the real wheel on Linux x64, macOS Intel, macOS Apple Silicon, and Windows x64 with no native environment variable, then prove runtime attestation, clean-output allow, secret-output deny, resident execution, and explicit rollback.

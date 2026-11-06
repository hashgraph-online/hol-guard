# ADR 0006: Python control plane with Rust runtime data plane

Status: accepted for the 3.0 prerelease train. Eligible PostToolUse default-`auto` is authorized by ADR 0010; broader native authority remains out of scope.

## Decision

HOL Guard remains a Python package and Python control plane. Latency-sensitive deterministic local hook work moves behind a versioned native runtime boundary implemented in Rust.

The standalone `hol-guard-runtime` executable is the primary native boundary. PyO3 is not the default architecture because direct harness-to-native execution removes Python interpreter startup from cold and fallback paths and avoids multiplying wheels by Python minor version.

The first authoritative migration surface is PostToolUse. PreToolUse, approvals, durable storage, cloud sync, MDM, dashboard, containment orchestration, and third-party Python scanners remain Python-owned until separate parity and threat-model gates authorize them.

## Security invariants

- Native failure, timeout, panic, version skew, malformed input, and missing runtime never weaken the Python decision.
- No runtime binary is downloaded on install or first run.
- Runtime discovery uses authenticated package metadata or an explicit developer/test override, never PATH lookup.
- Raw hook output and secret samples are forbidden from native logs and scanner result objects.
- Secure source reads are bounded, reject symlinked targets, validate file identity, and never mmap mutable user-controlled content.
- Existing containment claims remain owned by Seatbelt, Bubblewrap, gVisor, OCI, Kubernetes RuntimeClass, Windows Job objects, and other already-reviewed providers. The Rust hook runtime does not create a new containment guarantee.

## Rollout

`HOL_GUARD_NATIVE=auto|force` controls the backend. Eligible hooks default to
`auto`, which accepts only the verified bundled runtime with protocol and exact
package-version compatibility. Native unavailability fails closed. `force`
remains a developer/test mode.

The `off` and `shadow` values this ADR first described are retired. They stay
accepted so an existing install keeps starting, but they select nothing: each
resolves to the product default and logs `native_mode_legacy_value_ignored`
once. Neither a Python rollback nor a local disablement exists, because both
would reinstate the Python authority this boundary removed.
`HOL_GUARD_NATIVE_DIAGNOSTIC=1` on a declared non-production surface turns on
bounded transport and timeout diagnostics; it starts no Python evaluator and
compares no decisions. See ADR 0010 for the release-gate decision.

# ADR 0006: Python control plane with Rust runtime data plane

Status: accepted for the 3.0 prerelease train. This ADR does not authorize stable default enablement.

## Decision

HOL Guard remains a Python package and Python control plane. Latency-sensitive deterministic local hook work moves behind a versioned native runtime boundary implemented in Rust.

The standalone `hol-guard-runtime` executable is the primary native boundary. PyO3 is not the default architecture because direct harness-to-native execution removes Python interpreter startup from cold and fallback paths and avoids multiplying wheels by Python minor version.

The first authoritative migration surface is PostToolUse. PreToolUse, approvals, durable storage, cloud sync, MDM, dashboard, containment orchestration, and third-party Python scanners remain Python-owned until separate parity and threat-model gates authorize them.

## Security invariants

- Native failure, timeout, panic, version skew, malformed input, and missing runtime never weaken the Python decision.
- No runtime binary is downloaded on install or first run.
- Runtime discovery uses authenticated package metadata or an explicit test/shadow override, never PATH lookup.
- Raw hook output and secret samples are forbidden from native logs and scanner result objects.
- Secure source reads are bounded, reject symlinked targets, validate file identity, and never mmap mutable user-controlled content.
- Existing containment claims remain owned by Seatbelt, Bubblewrap, gVisor, OCI, Kubernetes RuntimeClass, Windows Job objects, and other already-reviewed providers. The Rust hook runtime does not create a new containment guarantee.

## Rollout

`HOL_GUARD_NATIVE=off|shadow|auto|force` controls the backend. The source default is `off`. `shadow` keeps Python authoritative. `auto` requires protocol and exact package version compatibility. Default `auto` requires a dedicated release-gate PR with differential and performance evidence.

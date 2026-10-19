# Experimental private-loopback profile v1

This is the proposed `private-loopback-v1` cell-network variant, not a supported
workflow executor. Its declaration and proof must accompany every new frozen
tuple. Existing `unix-only-v1` behavior, captured OCI policy bytes and installed
prefixes remain unchanged. Native/harness conformance and independent review are
still required before protected workflow or qualification claims.

The original Podman network-none floor provides private loopback without egress.
The experimental cell's additional Unix-only socket filter prevented the normal
Guard HTTP daemon and development-app loopback servers from functioning. This
variant permits AF_INET/AF_INET6 inside a fresh network namespace while retaining
the entire captured OCI filter and its supplementary native-ABI socket filter.
Vsock, packet sockets and non-route netlink remain refused. Unix socketpair remains
Unix-only. No network interface, bridge, veth, host forward, route, credential or
external destination is introduced. No syscall or LSM layer is disabled.

The Root constructor may raise only the pre-existing `lo` interface, before any
product import or privilege drop. Before mutation, it verifies private Root PID1,
that the passed parent network namespace matches the inherited host proc view,
that its own network namespace differs, and that only loopback interfaces,
addresses and routes exist. It repeats topology validation after raising `lo`.
Only explicit IPv6 unreachable reject stubs and loopback destinations are accepted.
It writes the profile declaration into the new read-only root. Neither product
state nor task contents selects this profile.

Outside the cell, the collector verifies every namespace differs from its own,
then observes the actual gated PID's network topology before releasing any product
code. After dropping all capabilities/IDs/groups and enabling no-new-privileges,
the actor validates topology again before loading both syscall filters. The
unprivileged product cannot add devices/routes or join a host/peer namespace.
Private network identity isolates abstract Unix sockets as well as IP loopback.

Memory, task-count, CPU, virtual-address, file and stream ceilings are unchanged.
The cell remains under the same enforcing AppArmor profile, normal private proc
with sensitive-interface denials, read-only installed runtime and exact task
idmapping. Cgroup termination remains responsible for detached descendants.

Required actual controls before use: local IPv4 and IPv6 request/reply; denial of
host and peer loopback/abstract Unix canaries; denied external routing, vsock and
packet channels; zero capabilities/NNP/two filters/enforcing LSM; unchanged host
network topology; actual native proc/overlay admission, contained effects,
authorization binding/replay and required Post; timeout/cancellation/descendants;
then the real SDK path. Capability controls alone cannot enable acceptance.

Guard's detached launcher currently discards the bounded allocator environment.
Use its normal foreground `guard daemon --serve` CLI as a gated owned product
process for compatibility controls. This preserves normal daemon code, private
state and native policy; it does not manufacture readiness or authorize sinks.
Readiness must be observed rather than inferred from `ensure` exit0. Compatibility
of the detached route remains explicit until separately repaired and validated.

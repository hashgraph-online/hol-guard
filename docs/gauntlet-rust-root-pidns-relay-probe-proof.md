# Root-owned SDK/Native relay probe

The Rust worker now has an explicit, unconnected-to-staging
`run_pinned_sdk_tap_root_relay_in_pidns_ineligible` path. It uses the same
outside-pinned child ELF, direct `clone3` PID/mount namespace, one-use cgroup,
private `/proc` and mount masks as the live diagnostic tap. In its new
`pidns-connect` mode, the UID/GID-10001 PID-1 child closes its inherited SDK
and report descriptors, opens the fixed Native frontdoor, passes the connected
socket to Root through one `SCM_RIGHTS` frame, closes its Native copy and
waits on the handoff control socket. Root requires EOF on the report pipe,
authenticates both held socket peers, then owns the bidirectional MCP
forwarding. A failed process/ancestry check runs **before** each Root write
and poisons the exchange. Root signals the child only after a complete
exchange, waits on its pidfd, reaps it and leaves one-use cgroup draining to
the active job owner.

The final Linux ARM64 test binary SHA-256 was
`c8e5c10d4059a86735775786ac89119dccfe08cf96a9dfd1dfdec24847ba8a1b`;
the installed Root-owned, single-link mode-0555 child ELF SHA-256 was
`a10d3027b99382e0f28871fcb593d1b95a4c1a0947b9128df22d00e5c86824c7`.
On the dedicated VM, the new Root one-family test forwarded an actual SDK
`tools/call` request and Native response through the PID-1 connector's
handed-off socket, checked two exact frames and one completed tool call, and
asserted the one-use cgroup was removed. The existing PID-1 child-forwarding
test passed with the same ELF. The VM's default worker library suite passed
101 tests with 17 Root/fixture cases ignored by default. Separate Linux tests
confirmed that a failed Root pre-forward check delivers zero request bytes
and an idle Root relay stops at its caller-supplied lifetime, which is capped
by the active job's remaining deadline. A generic Colima container run had
four expected cgroup-identity fixture failures; the same final binary passed
the full default suite on the dedicated VM. The transient guest test
executable was removed after the SHA-matched runs.

This was a transport prototype at the recorded code pin. The subsequent
[live Root relay proof](gauntlet-rust-root-relay-live-proof.md) records a
distinct staging mode, versioned journal/reader, simultaneous docs/mail tests,
host pinning and six fresh candidate roles. Failure and restart cases,
independent product-effect attribution, conformance, inference, qualification
and PR gate admission remain open.

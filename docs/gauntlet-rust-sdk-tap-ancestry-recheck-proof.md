# Per-frame SDK ancestry recheck

The opt-in PID-namespace tap launcher now retains the SDK relay-to-Bun
ancestry observation made before cloning the child. Before Root parses each
raw frame reported by that child, it reopens the live process chain, verifies
the relay's held socket credentials, pidfd, start tick and cgroup, and requires
the current chain to match the original observation. A reparented, exited or
replaced SDK relay cannot contribute another accepted frame. This extends
the existing per-frame SDK and Native peer checks without changing the
controller's Python adapter, the v2 tap journal or the passive PR gate.

The first Linux ARM64 test build had SHA-256
`4f0b81be2e1164924422ca8d77f29f9a2cc50bc8f524f4198d40b21d926c58ee`.
Its one-family Root socket test passed, but the concurrent two-family test
refused with `MCP peer process identity unavailable: Unavailable`. The first
implementation also checked ancestry after the child had closed the
exchange, when the short-lived synthetic SDK peer was allowed to exit. That
post-EOF check was removed. The check at each frame remains mandatory; an
ordinary peer exit after all frames cannot invalidate a completed exchange.

The corrected Linux ARM64 test binary SHA-256 was
`d6e09f3ed32adfd6f0acb5bd9d76349f2cb5dd8db842bca46d7c9d290a96f899`.
It passed both separately invoked Root socket tests against the installed
child ELF SHA-256
`0765420cc32cba2e6e57434852344c38dae98c935db71f7a2bd5216b20cc2119`:
one real `docs` exchange and concurrent `docs`/`mail` exchanges, including
the two-family tap journal and cgroup tombstone assertions. Its default
worker library suite passed 99 tests, with 15 Root/fixture tests ignored by
default. Linux ARM64 `cargo check --all-targets` and macOS Rustfmt passed.
The VM copies of both test binaries were removed after their verified runs;
the retained live evidence from the preceding six-role PID-namespace suite
was not changed. The VM then had 8,780,095,488 free bytes, 190,160,896 above
the 8-GiB admission floor.

This is a live process-chain check at every *reported* frame. The PID-1
child still owns forwarding and its pipe report can omit or misstate bytes;
Root does not independently observe the Native data plane or product effects.
Changed socket paths, a crash/restart readout, independently reviewed
installation and fresh six-role evidence on this tighter checker remain
open. Every result remains `execution_eligible:false`.

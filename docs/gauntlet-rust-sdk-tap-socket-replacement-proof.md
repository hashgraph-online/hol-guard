# SDK tap Native socket replacement refusal

The opt-in Root-forwarded tap now rechecks the visible Root-owned Native
frontdoor after both docs/mail session threads finish and before their wire
events can be retained. Each connection was already checked before handoff;
the final check detects a socket removed and rebound during a completed
exchange, even if its replacement has the expected owner, group and mode.

The Linux ARM64 worker test binary SHA-256 was
`fe3d6bd4ace1e7645386aa3bff39b1de14d93d86500aa102740a4dcf587f25f9`.
The fixed PID-1 connector ELF SHA-256 remained
`a10d3027b99382e0f28871fcb593d1b95a4c1a0947b9128df22d00e5c86824c7`.
On the dedicated 2-vCPU/16-GiB VM, the normal two-family Root-forwarded
exchange passed. A second two-family exchange delivered both MCP results,
then replaced the visible `docs.sock` with a new socket at the same
UID/GID/mode; the worker refused the session with
`Native frontdoor socket changed: docs.sock` and drained its tap cgroup.
The full default VM worker suite passed 101 tests with 20 intentionally
ignored. In an ARM64 Root container, the held-frontdoor test also refused a
same-metadata socket replacement. The macOS worker library passed 22 tests.
The transient VM test ELF was removed after the checks; available VM disk
returned to 8,953,798,656 bytes, above the 8-GiB admission floor.

This checks a visible replacement that persists until the final recheck.
It does not exclude a transient swap restored before recheck, prove
product-internal consumption of the forwarded bytes, attribute physical
effects to the product process, reconcile restart cleanup, or qualify the
controller/worker installation. All test and staging results remain
`execution_eligible:false`; the PR gate remains passive.

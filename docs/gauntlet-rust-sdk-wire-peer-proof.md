# Held Linux SDK MCP socket peer diagnostic

On 2026-10-21, code commit `9f791733` added a separate Linux ARM64
SO_PEERCRED and pidfd reader for the planned Rust SDK tap. The SDK-facing
socket requires exact UID/GID 10001; the Native frontdoor-facing socket
requires Root UID/GID 0. Both require caller-supplied PID, start tick and
unified cgroup pins. The reader holds a pidfd, repeats the socket credentials,
and uses the existing double-sampled `/proc` and cgroup observer to refuse
exit, PID reuse or a changed process tuple.

An additional bounded ancestry reader follows at most eight parent links in
the same cgroup, twice, from the authenticated UID-10001 relay to one
separately pinned ancestor PID/start tick. It rechecks the live peer before
and after the walk. It does not hash or authorize the ancestor executable;
the existing Rust SDK executable sampler and an outside Bun pin still need
to be joined in a live run. This reader also has no socket listener, holder
in the staging owner, one-use journal, or candidate traffic. Every JSON
projection states `execution_eligible:false`.

The cross-compiled static ARM64 worker test binary had SHA-256
`e7007beefb241992ca8578bd10430848c73572924077bc54abd33bfd4bc85043`.
Its host, guest inbox and Root-installed hashes matched; the Root copy was
mode 0500 with one link. On the running VM, the two intentionally ignored
Root-only cases were run explicitly and passed. One used a real UID/GID-10001
Python child connecting to a Unix listener and checked its held pidfd, exact
cgroup and direct parent relation; the other checked the fixed Root peer and
wrong-pin refusals. The default full worker library suite passed 84 tests,
with five intentional ignores (the two Root-only peer cases and three
existing fixtures). Warnings-denied ARM64 Clippy, Rustfmt and
`git diff --check` passed. After removing the redundant guest inbox, free
VM disk was 8,707,153,920 bytes, above the 8-GiB floor.

This is an isolated identity primitive, not independent SDK wire evidence.
The [execution checklist](gauntlet-rust-execution-checklist.md) keeps the
listener, worker handoff, journal and fresh six-role proof open.

At code pin `0dd62af7`, the reader can also discover the UID/GID-10001
relay's PID/start-tick tuple from an accepted Unix socket **after** a separate
worker observer supplies the exact agent cgroup. It checks that cgroup through
the double-sampled `/proc` observer, then repeats fixed-peer authentication
and returns a held pidfd. A real UID-10001 child on the ARM64 VM matched its
separately sampled tuple; a wrong cgroup and an invalid root cgroup refused.
The SHA-matched Root test binary was
`33195851365223cd020ba211043176babd8cc5aa820828db9041dceaa7b15a6f`,
mode 0500 with one link. Its explicit Root-only peer test passed; the full
worker library suite passed 92 tests, eight intentionally ignored, zero
failed. ARM64 warnings-denied Clippy, Rustfmt and `git diff --check` passed.
The guest transfer inbox was removed; free VM disk was 8,677,048,320 bytes.
The discovered tuple is still not a Bun executable, candidate-source or
Native/Guard effect pin, and the live staging worker does not call this path.

# Opt-in Rust staging SDK tap handoff

Code pin: `c6d142c1` (2026-10-21). This source adds a separate
`gauntlet-candidate-staging-control-tap` binary. The existing v1 staging
binary and its launch vector still call the original path. The v2 worker
requires a separately pinned Root-owned ARM64 tap-child executable, binds
one-use docs/mail listeners under its staging lease before starting Python,
and selects one live SDK Bun process by matching its kernel-observed ELF hash
to the already inventoried runner asset. An ambiguous or changed Bun process
refuses the handoff.

For each family, the worker accepts an actual UID/GID-10001 Unix peer in the
selected agent cgroup, binds its parent chain to that Bun PID, holds the
controller-owned Native frontdoor directory, and launches a pinned
UID/GID-10001 tap child in a separate limited cgroup. The Root parent
reparses the child's raw frame pipe. Completed docs and mail sessions are
fsynced to a one-use private journal; its digest enters the v2 diagnostic
report before the existing keyed `invalid-evidence` terminal. The worker
drains the tap cgroup and unlinks both exposed socket names while preserving
the empty directory as a replay tombstone. Errors remain ineligible and
cannot fall back to the direct v1 transport.

The first two-family ARM64 test exposed a legitimate close race: the SDK
relay could exit after its response, while the tap child still required its
PID to be alive after EOF. The child now checks both held peers at each
forwarded frame and accepts normal peer exit after the last frame. The
Root-side reader still requires a closed request/response ledger and EOF.
The pinned child opener now checks every Root-owned directory ancestor and
requires a 64-bit little-endian AArch64 ELF, in addition to its SHA, inode,
owner, link and mode checks.

On the idle Linux ARM64 VM, Root-owned test executable SHA-256
`61e87db8097ffbc9fa1e25d62309fa181aa39662f92a0c2eaa5883a88c6d5df8`
(mode 0500) and child SHA-256
`4a9009f2309b3a991c815250c6fb6aee64ee9319b9ec708161e23361f7183722`
(mode 0555) were copied through separate guest inboxes, independently
rehashed, and installed under `/root`. The ignored Root integration test
`candidate_staging_tap::tests::worker_owns_both_real_sdk_sessions_and_tombstones_after_drain`
passed with two real UID-10001 relay descendants, two actual Root Native
Unix servers, four independently reparsed request/response frames, a
digest-pinned Root journal readback, replay refusal, socket removal and
tap-cgroup absence. The single-session child regression also passed. The
full worker unit binary passed 94 tests with 12 deliberately ignored fixture
tests; ARM64 all-target warnings-denied Clippy, Rustfmt, `git diff --check`,
and macOS workspace `cargo check` passed. The separate v2 CLI built with
SHA-256 `6a1295d977303ab75c376ff56f14eeed2203fdca91059642439a1d8d0a68b52b`.
VM free disk after deleting transfer inboxes was 8,754,790,400 bytes,
above the 8-GiB floor.

Code pin `7f88339f` adds a separate macOS
`gauntlet-host-staging-control-tap` command. It keeps the v1 host executable
untouched, derives the fixed guest v2 worker and child paths from outside
SHA-256 pins, and uses the existing durable host prepared/ack key handoff.
The new binary passed macOS `cargo check` and warnings-denied Clippy. It has
not run a live Lima prelaunch; its output explicitly requires guest-terminal
readback and a future outside host pin for the tap-journal digest.

This is a synthetic Root/UID integration proof, not a source-matched
candidate control. The test supplies a synthetic SDK ancestor and Native
frontdoor; it does not run the candidate Bun, Guard, signed controller or
host handoff. The tap child has a separate cgroup and UID but still needs
the planned PID/mount namespace restriction. The parent constructs Native
peer metadata from its controller pin after the child authenticates that
peer; it does not independently read the child's Native socket. No fresh
v2 six-role run, outside host pin for the journal digest, signed-trace/frame
reconciliation, physical-effect scoring, conformance package, model
inference, execution eligibility or PR gate is claimed.

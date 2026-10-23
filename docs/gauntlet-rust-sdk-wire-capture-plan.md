# Rust-owned SDK MCP wire capture: execution design

This is the next implementation dependency for independently scoring the
six-role staging controls. The current source-matched Python controller
launches `private_cell_sdk_conformance.ts` in the agent container. That Bun
process launches `service_relay.py`, which connects through
`/runtime/resources/{docs,mail}.sock` to the controller-owned
`NativeMcpSupervisor`. The Rust staging worker currently samples the Bun
executable and process cgroup, while the controller signs its own Native MCP
transport events. Those two observations do not prove what bytes the SDK
relay sent or received. The read-only Rust comparison at `e6b7dc1f` checks
internal consistency of the signed trace only.

## Ownership and wire path

Add an opt-in v2 staging adapter. For that version only, the Rust worker
creates a one-use tap directory outside `/home/hx-<run>/<role>` before it
launches Python, under its existing active lease and the Python VM lock. It
binds exactly two Unix stream listeners, `docs.sock` and `mail.sock`, in a
Root-owned directory traversable only by UID/GID 10001. The sockets must be
Root-owned, group 10001, mode 0660. The worker holds descriptor references
to the directory and sockets, checks no-symlink ancestry and visible inode
identity before and after use, and removes them only after every session is
closed and both locks are held.

The Python controller continues to own the Native frontdoor at its existing
private `ROOT/front` path. Its opt-in `DeveloperProductRuntime` mounts the
Rust tap directory at `/runtime/resources` and publishes the same fixed
`docs`/`mail` endpoint declarations to the SDK. No candidate-selected path,
socket, model URL or executable enters this choice. Legacy controller calls
keep their old direct mount. The v2 adapter obtains the tap directory from a
fixed path derived from its validated one-use run ID, checks the expected
Rust-owned socket metadata, and passes that path to `run_control`; it cannot
accept an arbitrary caller path. The Rust worker's fixed plan, controller
source inventory, installed controller tree, Python adapter tests and host
manifest must be refreshed together. Do not update the active Python
release observer or current v1 staging runs in place.

Use a privilege-separated Rust data-plane child at UID/GID 10001 for the
backend connection: the existing Native frontdoor authenticates its Unix
peer as UID 10001 and must not be weakened to accept Root. The Root worker
binds the public sockets and retains the private frontdoor and journal
directory descriptors; it passes only fixed listener and frontdoor-directory
descriptors plus a private
framed evidence pipe to the child, then tracks the child with a pidfd and
reaps it before completing the job. The child gets a separate PID/mount
namespace, no capabilities, no-new-privileges, and no access to candidate
files or Root journal paths. The Root parent validates and durably records
each child-reported frame and terminal sequence. The child connects after
dropping privilege to only the fixed corresponding private frontdoor socket,
checks its server peer
PID/start tick against the controller, and keeps both endpoints held until
closure. The agent never receives a mount of the private frontdoor directory.

For each accepted SDK-side connection the child uses `SO_PEERCRED` to
require UID 10001 and reports the peer PID/start tick, cgroup, executable
hash and bounded parent ancestry while the socket is open. That peer is the
Python `service_relay.py` process, which must be linked to the already
sampled Bun PID/start tick inside the same agent Podman cgroup; equality of
UID alone is insufficient. The Root parent cross-checks these claims against
its own pidfd/cgroup observations before accepting the child's journal rows.

Forward newline-delimited JSON-RPC frames byte for byte, with a 1-MiB
per-frame ceiling no looser than the current Native frontdoor (the SDK relay
allows 2 MiB). Bound aggregate bytes,
message count, sessions and wall-clock lifetime to the existing controller
profiles (at most 12 MiB observed bytes, 1,000 messages and 16 sessions),
with a stricter per-run budget if the frozen staging script permits it.
Reject duplicate JSON keys, nonfinite numbers, partial frames, oversized
frames, unexpected family/socket pairing, UID or process changes, and a
write failure. A failure poisons that run's tap and makes the later control
`invalid-evidence`; it must not fall back to the direct controller socket.

## Evidence and scoring boundary

Write a one-use Root-only 0600 canonical tap journal with session, direction,
sequence, raw-frame SHA-256, JSON-RPC ID/method, peer PID/start tick/cgroup,
frontdoor peer identity and bounded byte counts. Retain raw frames only in a
separate Root-only private file when necessary to compare exact messages;
never put their payloads or the SDK transcript into the public dashboard.
The worker fsyncs the journal and parent directory, records its SHA-256 in
the terminal, and the Mac host retains that terminal digest outside the VM
before the job can be considered for conformance. After the run, Rust must
reopen the tap journal under outside pins and compare every captured request
and response with the independently keyed controller-signed Native audit.
The request ID and response byte digest must also bind the captured
`sdk.stdout` result and the physical synthetic-service effect.

This supplies an observation at a separate process boundary; it does not by
itself prove the Native Guard decision or an unmodified candidate. The
scorer must still require the separately pinned source, image and installed
prefix, independently observed Native contained-test effects, post-run
cleanup/cgroup absence, and a fresh source-bound conformance package. All
legacy and interrupted runs remain ineligible. A v2 tap result may only add
evidence; it cannot promote an old v1 terminal.

## Required execution order

1. Freeze the v2 transport declaration and exact Rust/Python fixture vectors
   for valid docs/mail request, response and notification frames, plus wrong
   UID, PID ancestry, cgroup, peer, duplicate ID, partial frame, timeout,
   cancellation and replay refusals.
2. Implement the descriptor-held Rust tap and one-use journal; unit-test the
   actual Unix socket relay on Linux ARM64 under the same UID/cgroup rules.
3. Add the opt-in Python adapter/runtime mount selection and source-hash
   inventory update. Rebuild and independently pin a new controller
   generation and worker executable; leave the current generation intact.
4. Run one fresh success control with host-prelaunch key and tap pins, inspect
   raw tap journal/terminal custody, then run the other five roles. Require
   exact tap/signed-trace/SDK-result/physical-effect reconciliation and
   refusal of one deliberately changed retained tap artifact.
5. Only after those six pass, implement the independent Native/Guard effect
   scorer and construct a new conformance package. Keep the dashboard and PR
   gate passive until the wider checklist's deployment and rollout exits pass.

The design is not a completed evidence claim. It adds no execution
eligibility and spends no model tokens.

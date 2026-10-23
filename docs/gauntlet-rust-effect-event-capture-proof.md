# Root close-write capture feasibility

On 2026-10-22, the isolated 2-vCPU, 16-GiB/48-GiB Linux ARM64 VM
`hol-beta-bootstrap-20261016-005` accepted a Root-only fanotify group with
`FAN_REPORT_PIDFD` and a filesystem `FAN_CLOSE_WRITE` mark. A direct kernel
probe returned a 32-byte event containing the written file descriptor, writer
PID and a live pidfd. This is the mechanism described by the Linux
[fanotify event format](https://man7.org/linux/man-pages/man7/fanotify.7.html)
and [pidfd reporting flag](https://man7.org/linux/man-pages/man2/fanotify_init.2.html).

`gauntlet-worker-state::staging_effect_events` now provides a bounded capture
primitive. It holds an outside-selected Root-owned directory descriptor and
marks its filesystem relative to that descriptor, so a changed visible path
cannot redirect the mark. It parses only the expected 32-byte close-write
event shape, refused queue overflow and more than 4096 events at this initial
code pin, and poisoned the
capture on any read or shape error. For each event it compares the event file
device with the marked filesystem, retains its inode and owner, and samples
the writer's start tick and unified cgroup twice while holding the kernel
pidfd. A writer whose pidfd or live process cannot be sampled remains
`None`, so a future scorer must treat its attribution as unknown. Event file
descriptors and pidfds are closed after sampling.

The watcher must be consumed with a final drain before it can correlate a
retained file. Given a held file descriptor and an outside cgroup pin, the
finished reader requires at least one close-write for the same device/inode,
and requires **every** such event to have a live writer in that exact cgroup
and the same file owner. It returns the distinct PID/start/cgroup tuples;
missing, unknown or foreign writers refuse. The caller still has to prove
that the writer stopped before `finish`, open the file through a trusted
no-symlink path, and independently compare its final bytes.

The final test ELF had host and guest SHA-256
`03227cbeb0ec008f63edcf6a582d8c5d7f858bd048d51b34e0e89296a37a9f87`.
Its ARM VM library suite passed 104 tests with 21 intentional fixture/Root
ignores. The separately selected Root test wrote a synthetic file under
`/home`, then matched the returned event to that file's device/inode, UID 0,
the test process PID and a nonzero start tick. Warnings-denied Rust 1.88
Clippy passed in the native ARM64 container. The retained-file correlation
matched the same writer and refused an unrelated cgroup; adding an unknown
writer event for that inode also refused. Four pre-existing library tests
that require a non-root cgroup path fail in that container because Docker
places the test process at cgroup `/`; all four passed in the VM suite.

The initial primitive was not yet wired into a staging run or host-pinned
journal. The later [live effect-event proof](gauntlet-rust-live-effect-events-proof.md)
records the opt-in Root-relay integration, a final 32,768-event cap and
16-MiB canonical journal ceiling, four fresh controls and one-use host
effect pins. The filesystem-wide mark
may observe unrelated writes. The current event
shape cannot identify a file that was deleted before post-run inode matching,
and the monitor does not capture create/delete events. An unknown writer or
missed event must remain ineligible. It does not establish that a Native
MCP call or Guard decision caused a physical effect, and it cannot score any
of the six retained controls retroactively.

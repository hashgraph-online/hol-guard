# One-use Rust-owned SDK tap listener diagnostic

On 2026-10-21, code commit `0a1f5176` added an opt-in listener primitive
under the Root-owned Rust staging journal. With the active lease held, it
requires one 16-hex run ID and creates only `<run-id>.sdk-tap/docs.sock` and
`mail.sock`. The directory is Root-owned, group 10001, mode 0710; each socket
is Root-owned, group 10001, mode 0660. Rust binds through a held directory
descriptor, fsyncs the directory and journal root, then rechecks the visible
directory/socket inodes and exact modes. A duplicate run ID fails closed; a
partial creation leaves the one-use namespace consumed for later review.

A Root-only ARM VM test used a fresh private journal and lease. It connected
through an actual Unix socket, received a byte on the held docs listener,
refused replay of the run ID, and detected a changed mail socket mode. The
test is intentionally ignored in ordinary unprivileged runs and was executed
explicitly on the VM. The smaller no-debug static ARM64 test binary was
11,492,712 bytes with SHA-256
`a2f3114841191c725a6a8874562213e107e2f52d561a0c028ea853e91514f895`;
host, guest inbox and Root-installed hashes matched, and the installed copy
was mode 0500 with one link. The two Root-only socket-peer cases also passed
explicitly. The default full worker library suite passed 84 tests with six
intentional ignores. Warnings-denied ARM64 Clippy, Rustfmt and
`git diff --check` passed. After removing the redundant guest inbox, VM
free disk was 8,787,423,232 bytes, above the 8-GiB floor.

The initial listener proof had no controller mount, UID-10001 backend child,
session accept loop, tap journal or cleanup handoff. It did not launch a candidate
or change the active Python release workflow. The [execution
checklist](gauntlet-rust-execution-checklist.md) leaves the parent SDK
transport and conformance exits open.

At code pin `e988db49`, the listener gained a bounded one-session accept
operation for exactly docs or mail. It rechecks the Root lease and both
visible socket inodes while waiting, stops on cancellation or boottime
deadline, requires a separately supplied canonical agent cgroup, and holds
the accepted UID/GID-10001 peer's pidfd/start tick. It checks cancellation,
deadline, peer and lease again before returning the socket. A Root ARM64 test
passed with a real UID-10001 Python client accessing the private tap only
through an inherited directory descriptor, modeling the container bind mount;
wrong family, invalid cgroup and cancellation refused. The final test binary
was Root-owned mode 0500, one link, SHA-256
`819d578e750b1ee3cabc684c98583e3e181851bb14ce041f72b28587879118fd`.
The full suite before the final post-accept recheck passed 92 tests with nine
intentional ignores; the exact final Root accept test, warnings-denied ARM64
Clippy, Rustfmt and `git diff --check` passed afterward. The guest inbox was
removed and free VM disk was 8,665,292,800 bytes. The staging worker still
does not invoke the accept operation or launch a backend child, so no live
SDK transport or control verdict is claimed.

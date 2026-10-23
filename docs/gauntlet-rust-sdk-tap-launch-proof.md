# Root-owned SDK tap child launch diagnostic

On 2026-10-21, code commit `dfaaf06b` added a reusable ineligible Root
launcher for one accepted SDK connection. Root opens a mode-0555, single-link
Root-owned child executable, checks its entire bounded byte content against
an outside SHA-256 pin, holds the inode and rechecks its metadata. The child
is invoked with `execveat(AT_EMPTY_PATH)` on that descriptor, an empty
environment and only the fixed SDK socket, Native directory and report FDs.
Before execution the launcher starts a new session, drops supplementary
groups and UID/GID to 10001, and sets no-new-privileges. Root requires the
outside-pinned SDK peer and ancestor before spawn, samples the child PID/start
tick/cgroup while holding a pidfd, independently reparses the bounded raw
frame pipe under a boottime deadline, and requires a successful child exit.
Cancellation, a missing terminal or a failed report refuses; the launcher
sends SIGKILL and attempts a bounded reap after failure.

The ARM64 VM Root-only test used the actual descriptor launcher against a
separately installed UID-10001 Rust child, UID-10001 Python SDK client and
Root Native socket. The request arrived byte-identically at Native; the
Root reader reconstructed the request/response pair from the private report
pipe. A wrong child-executable digest and wrong SDK start-tick pin refused
before launch. The explicit process test passed, and the full worker library
suite passed 91 tests with eight intentional ignores and no failures.
Warnings-denied ARM64 Clippy, macOS binary `cargo check`, Rustfmt and
`git diff --check` passed. The test binary's host/inbox/Root SHA-256 was
`eb5d1e92c11924bb323aa1a39df7c4fac6252962817934c45726073fc05500ba`;
the child ELF pin was
`f4fa42d64e1895fd7a10cb392886fa9562801d709e23b9519e5f577b4757ad33`.
The Root test binary was mode 0500; the child was Root-owned mode 0555,
both single-link. The guest inboxes and superseded test binaries were
removed. VM free space was 8,692,867,072 bytes, above the 8-GiB floor.

This launch is still an isolated harness. The child inherits the test
process's cgroup; the worker has not yet created and pinned a dedicated tap
cgroup or PID/mount namespace, attached the child to its active lease,
admitted real docs/mail listeners, retained raw frames in a one-use journal,
or bound the terminal and host pins. The synthetic SDK ancestor is the Root
test process, not the live Bun executable. The launch therefore establishes
no live SDK/Native causality, Guard verdict or conformance eligibility. See
the [execution checklist](gauntlet-rust-execution-checklist.md).

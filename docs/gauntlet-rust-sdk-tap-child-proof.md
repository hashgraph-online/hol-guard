# UID-10001 SDK tap child diagnostic

On 2026-10-21, code commit `8c0c2e7b` added an opt-in, single-session Rust
SDK tap child executable. It accepts only the docs or mail family and three
distinct inherited descriptors: an already accepted SDK socket, a held Native
frontdoor directory, and a raw-frame report socket. At runtime it requires
Linux ARM64, UID/GID 10001, no supplementary groups and
`PR_SET_NO_NEW_PRIVS`. It checks the directory's Root/group-10001 0710
profile, authenticates the SDK socket's pinned PID/start/cgroup and bounded
ancestor chain, connects only to the selected `docs.sock` or `mail.sock`
under that directory descriptor, and authenticates the Root Native peer's
pinned PID/start/cgroup. It then relays bounded byte-identical JSON-RPC
frames and sends their raw bytes to the separate parent reader. A completed
session requires peer and directory rechecks before the report terminal.

A Root-only ARM64 VM test launched the separately installed child as actual
UID/GID 10001 with all supplementary groups dropped and no-new-privileges.
A separate UID-10001 Python client connected to the SDK test socket. The
child connected to a Root-owned Native test socket through a held group-10001
directory descriptor. The Root test observed the child PID/start/cgroup,
checked the Native side received the exact request, and independently
reparsed the report pipe's request and response. The explicit process test
passed. The full ARM64 worker library suite passed 90 tests, with eight
intentional ignores and zero failures. Warnings-denied ARM64 Clippy,
Rustfmt, and `git diff --check` passed.

The no-debug ARM64 test binary had SHA-256
`af3d1cad0a922f4187c23403eb2d67b48d346ecc3cca6ba4902f17cb7effc467`;
the child executable had SHA-256
`f4fa42d64e1895fd7a10cb392886fa9562801d709e23b9519e5f577b4757ad33`.
Host, guest inbox and Root-installed copies matched. The test binary was
Root-owned mode 0500 and the child was Root-owned mode 0555 with one link.
The three guest inbox copies and an obsolete first test binary were removed
after the successful run. VM free space was 8,692,920,320 bytes, above the
8-GiB floor.

This is a test harness and entrypoint, not the worker's production launch.
The test uses a Root test process as the synthetic SDK ancestor, so it does
not demonstrate Bun ancestry. The Root worker does not yet bind the listener,
pin the child executable, launch it in a dedicated PID/mount namespace or
cgroup, authenticate the child and its report pipe, enforce the job deadline,
or attach this observation to a terminal and outside host pin. The Python
controller still mounts its original direct frontdoor. No live candidate,
Guard decision or conformance verdict was established. The
[execution checklist](gauntlet-rust-execution-checklist.md) keeps those exits
open.

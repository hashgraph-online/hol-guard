# One-use SDK tap child cgroup proof

Code pin `7caf8418` adds a dedicated Root-owned cgroup-v2 group derived
only from the validated 16-hex staging run ID:
`/system.slice/hol-gauntlet-rust-tap-<run-id>`. Its fixed limits are 256 MiB
memory, 32 PIDs and half a CPU. Creation refuses an existing group; the
handle exposes explicit kill and drain/remove operations, and dropping it
does not count as cleanup. A new opt-in launcher variant attaches the tap
child to that group in a pre-exec syscall before dropping to UID/GID 10001,
then requires the child's pidfd/start-tick observation to match that cgroup.
The prior test launcher remains ineligible and separate.

On the ARM64 VM, a Root test used a separately installed Root-owned
mode-0555 child ELF with SHA-256
`bf15866f83cca144e840218933cfe77ade54263d7ac00d5b937310444cd1974a`.
The test binary was Root-owned mode 0500 with SHA-256
`6f60e39d24edb45501e7c4f44243453e6a92251c94966e6d27dde9f6880bbb20`;
both had one link, and host/inbox/Root hashes matched. A real UID-10001
Python SDK peer sent a docs JSON-RPC call through the Rust child to a Root
Native socket. Root independently reparsed the exact request and response
from the report pipe, observed the child in the dedicated cgroup, refused a
duplicate group, drained/removed it, and a separate filesystem check found
the cgroup absent. The explicit Root test passed. The full worker library
suite passed 92 tests with ten intentional ignores; ARM64 warnings-denied
Clippy, macOS binary check, Rustfmt and `git diff --check` passed. Guest
transfer inboxes were removed and free disk was 8,675,430,400 bytes.

This remains an isolated synthetic exchange. The staging worker does not yet
create the group or invoke this launcher under its lease, the child has no
separate PID/mount namespace, and no live candidate, terminal-bound tap
journal, Native effect, Guard verdict or conformance package is established.

# Direct PID-namespace tap probe

The opt-in Rust diagnostic `probe_owned_tap_pid_namespace_ineligible` creates
the existing one-use, Root-owned tap cgroup with its fixed 256-MiB, 32-PID and
half-CPU limits. A direct `clone3` call uses `CLONE_NEWPID`, `CLONE_NEWNS`,
`CLONE_PIDFD` and `CLONE_INTO_CGROUP`. The fixed child becomes PID 1 in the new
namespace. Before dropping to UID/GID 10001, it makes `/` private, mounts its
1-MiB `/tmp`, masks `/home` and `/opt` with read-only inaccessible tmpfs, and
mounts a new `proc` on `/proc`. It uses no candidate path, socket or model.

Root receives the actual host PID and pidfd from `clone3`. While the child
waits on a held release socket, Root checks its start tick and exact cgroup,
distinct PID and mount namespaces, `NSpid` relation ending in PID 1, UID/GID
and no-new-privileges state, the `/tmp`/`/home`/`/opt` mount types and flags,
and a private procfs containing PID 1 but no PID 2. Root then releases,
pidfd-polls and reaps the child; failure kills the group and both paths drain
and remove the one-use cgroup. The JSON result is explicitly
`execution_eligible:false`.

The optimized Linux ARM64 test binary had SHA-256
`823da794d5e2ef34328d410e1a4f925bb96656f3954428030ebadcb3026085da`.
It was copied through a SHA-checked guest inbox and installed Root:Root,
mode 0500, one link at `/root/gauntlet-worker-pidns-test-823da794` on the
dedicated VM. Its Root-only ignored test returned host PID `1362173`, start
tick `36898981`, nested PID `1`, run ID `0014c8fb5dba2211`, all mount and
credential checks true, and cgroup removal true. A separate read found
`/sys/fs/cgroup/system.slice/hol-gauntlet-rust-tap-0014c8fb5dba2211`
absent. The same binary passed 99 default worker tests with 13 intentional
Root/fixture ignores; warnings-denied Linux all-target Clippy and macOS
all-target `cargo check` passed. The ARM container's full test run had four
unrelated failures because its Docker cgroup path is outside the tests' fixed
path grammar; the dedicated VM run is the applicable kernel result.

This diagnostic proves only the direct child lifecycle and fixed namespace
profile. The live SDK/Native relay still uses the v2 launcher and host PID
namespace. Inside the new PID namespace, an external socket peer's
`SO_PEERCRED.pid` becomes zero and the child cannot authenticate host process
start/cgroup through its private `/proc`. Before this can replace the live
launcher, Root must own those checks throughout a real relay, the child must
operate without host PID assumptions, and a fresh six-role run must establish
the new path's behavior. It does not attest frame forwarding, product effects,
Guard decisions, model inference or execution eligibility.

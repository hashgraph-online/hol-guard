# SDK tap private mount diagnostic

The opt-in Rust staging launcher now creates a new mount namespace for each
UID/GID-10001 SDK tap child, makes mount propagation private, and mounts a
1-MiB `tmpfs` over the child's `/tmp` with mode `0700`, UID/GID 10001, and
`nosuid,nodev,noexec`. It also masks `/home` and `/opt` with separate 4-KiB,
read-only, mode-`0000` tmpfs mounts. It does this after attaching the one-use
tap cgroup and before dropping privileges or executing the outside-pinned
child ELF. The SDK and Native Unix sockets are held descriptors; the child
still connects to the fixed Native socket through `/proc/self/fd/<held-dir>`.

The Root launcher reads the live child's mount namespace and
`/proc/<pid>/root/{tmp,home,opt}` after checking its PID/start tick/cgroup
and opening a pidfd. It requires a different mount namespace from the
worker, a different device for each masked path, exact owner/mode, `tmpfs`
type, and the required mount restrictions. A child in the
worker's namespace refuses. Failure aborts the diagnostic, after which the
existing cgroup owner handles kill, drain and removal.

The first SHA-matched ARM64 worker test binary
`5a37e6f807c0a71df89bb7a96986ba2dd43b4743ddff86146291f53f897e6014`
proved the private `/tmp` path. The final path-mask test binary
`16f7f5fe7f1a6b1cafaef53ed8da094f987445eec1e7267c8a394139c2be4273`
was installed separately as
`/root/gauntlet-sdk-path-mask-test-16f7f5fe-20261021` on the dedicated
16-GiB VM. Its 98 default tests passed with 12 intentional fixture ignores.
Two separately invoked Root-only tests passed against the retained pinned
child ELF `1a4bf073275aac1114e373d28735af1b717f32f38000fe991a734522a40bf089`:
one real UID-10001/Root docs socket exchange, and one concurrent docs/mail
staging handoff with journal and cgroup tombstones. Both exercised the new
Root checks for all three mounts. The Native socket remained reachable via a
held directory under the masked `/home` path, and the child ELF remained
executable from its held descriptor under masked `/opt`. Linux all-target
warnings-denied Clippy, macOS all-target
`cargo check`, and Rustfmt passed. The container's full unit suite had four
expected failures in tests that assume the VM's fixed cgroup topology; those
same tests passed in the VM suite. VM free disk after the tests was
8,662,355,968 bytes after removing the two verified transfer inboxes,
above the 8-GiB admission floor.

The same mount launcher was then exercised against the retained v3.49
candidate in six new, separate one-use staging roles. The optimized Linux
ARM64 worker was SHA-matched as
`9c98395bca4fa70096d70ee059737eb152c80b301b49e587fc2fe17216f31c63`;
the child ELF remained pinned as
`1a4bf073275aac1114e373d28735af1b717f32f38000fe991a734522a40bf089`.
The outside host retained a distinct prelaunch key and a completed tap pin
for every role. All six worker commands completed with an
`invalid-evidence` terminal and zero model requests. The host's immutable
v5 suite manifest SHA-256 was
`8a73a33023a6c78877c95c316300c79587451cf1b96a221ef7f35bc2925e80da`;
the Root-owned 0444 VM copy matched it byte-for-byte.

| Role | Run ID | Root tap journal SHA-256 | Host tap pin SHA-256 |
| --- | --- | --- | --- |
| success | `b03948619c7b3813` | `6179efd3192c0884a4605c641ea436c3d20cd4ee1aa63c8d03f7085ca0380a0d` | `8274bbdbafbf4b2ffec2b6c50187fb33677651655f907dd1e55affea18bbdd2e` |
| input-binding | `32e0d2af7c645bdb` | `801fe834c0b67b05dcb01138d99a740b3cfe4b6e4da0e27de5ed9afd9b38de69` | `4b1376aaecfa9bf4b3fca3a3af530865031335428181cf2db48436a715112bd1` |
| injection | `2fdd81d2f5f7f2e4` | `bc4aa6383b814d64df60825a3199755868989c1c8be0d54f6fabe948848ce430` | `c33dc9ec3c3d85ab2ca70306296ebc15d95fcd79caaa76d8cf5bad268a54ea02` |
| boundary | `5d0639ea83c7e0cb` | `57393009feda0d23888bff0a8c512a043e0db658859ea786a58efdae13d77983` | `f85ab99b636f9eaa6ae8f821cd9a6866567756d778c2fd13dc94f546dd981740` |
| timeout | `72d57c755c437edb` | `0e43f033af11e9e28643049dd6aa61d5cd5a36f13063b5174e005b11897f01a2` | `5036da369e3f68d7f28c39c29d58361f4dd41b71b4c0b3f55a19179e303357e0` |
| cancel | `7047955fb642632c` | `8f06a14db12259f8affbc188c3b563a8971557e969638cae472a61656a85be9a` | `d63ac5b2a645bac582f4e4cb98cc94e98597ad748793724e2a5be14040de5c32` |

The first suite read refused the timeout role's Native MCP trace. Its docs
session recorded a response frame, then forwarded an unrelated client
notification before recording delivery of that response. The reader had
required same-session adjacency. The corrected reader keeps one unmatched
frame per session and direction, requires byte-identical forwarding or
delivery, and refuses lifecycle closure with a pending pair. Its focused
regression and all 52 Linux evidence-library tests passed; warnings-denied
Linux Clippy and macOS all-target `cargo check` passed. The final optimized
reader SHA-256 was
`d2d6e8053597af513b444a40690503a8e0795196c67abde743e456baa0aaadb6`.
It accepted all six immutable records and outside tap digests: 144 frames,
six source-bound docs results, six sampled agent/gate/Bun/Native process
relations, 12 signed Native proxies, 32 physical files, five absent effects,
and absent controller/product/tap cgroups. VM free disk was 8,821,239,808
bytes after the read, above its 8-GiB admission floor.

This proves the three private path masks and non-propagating mount changes
in Root-observed synthetic socket tests, and proves that the source-matched
worker completed a live six-role transport diagnostic with those mount
operations in its launcher. The suite journal does not separately attest
each live mount. The child still shares the host PID namespace and can see
the host `/proc` view used for SDK/Native peer checks. Other world-readable
host paths are not masked. The PID/mount isolation checklist exit remains
open. All six results remain `execution_eligible:false`; they do not
establish independent Guard effects, conformance or model inference.

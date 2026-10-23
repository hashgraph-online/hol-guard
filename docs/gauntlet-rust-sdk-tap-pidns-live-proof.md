# Live PID-namespace SDK tap diagnostic

The Rust-owned SDK tap now has an explicit, opt-in `--pidns` staging path. The
existing v2 path and Python controller's `--sdk-tap-v2` adapter remain
unchanged. Root authenticates the accepted SDK relay and its Bun ancestor,
creates the same bounded one-use tap cgroup, then uses `clone3` with
`CLONE_NEWPID`, `CLONE_NEWNS`, `CLONE_PIDFD` and `CLONE_INTO_CGROUP`. The child
is PID 1 in a private namespace, mounts a new `/proc`, isolates `/tmp`, masks
`/home` and `/opt`, drops to UID/GID 10001 and keeps no supplementary groups.
It marks all inherited Root descriptors close-on-exec, passes only the held
SDK socket, Native directory, frame report and Native handoff descriptors,
and executes the outside-pinned ELF by descriptor after Root verifies the
child's live cgroup, namespaces, mounts, credentials and `/proc` view.

Inside this namespace an external Unix peer's host PID is reported as zero.
The child therefore performs bounded byte-identical forwarding without
trying to read host process identities. Root retains the SDK socket and the
Native socket received through `SCM_RIGHTS`, checks their UID/GID, pidfd,
PID/start/cgroup before parsing every reported frame, independently reparses
the complete JSON-RPC exchange, holds the child's pidfd, then reaps it under
the job deadline. The staging owner kills, drains and removes the one-use
cgroup after both docs/mail sessions. Every result remains
`invalid-evidence`/`execution_eligible:false`.

The first real Root VM tests used test binary SHA-256
`2aec981ec3497b7bacb141178a7e788fc53170f14f2ea30725484ad6d4fce445`
and child ELF SHA-256
`0765420cc32cba2e6e57434852344c38dae98c935db71f7a2bd5216b20cc2119`.
A one-family request/result and a concurrent docs/mail exchange each passed
through PID-1 children; the corresponding existing v2 tests also passed with
the new child ELF. The two-family test retained four frames, independently
observed Root Native peers and confirmed its tap cgroup absent.

The first live worker SHA-256 was
`713094b0f46dc13a1e138115521219f827e748d6fc10be86e6076a525ab3a0f4`.
Success, input-binding and injection ran with host-pinned keys and tap
journals. A boundary run `47853fe72238c7c6` had a valid exit-zero
`invalid-evidence` terminal but no tap journal: one child exceeded the
original three-second setup-ready wait under VM load. Its report retained
`PID-namespace SDK tap child not ready: Resource temporarily unavailable`.
The launcher now polls setup every 250 ms, checks cancellation, job deadline
and early pidfd exit, and refuses after a fixed 15-second setup bound.
It never treats that failed boundary attempt as a pass.

The final SHA-matched staging worker was
`85ebe0ad899bd89812bb663c8fe9e1eaa51aff3d404fcb6a30fe5bf5489c146b`;
the child ELF remained the same. Both guest files were installed Root-owned,
single-link, at the fixed digest-derived `/opt/hol-gauntlet` paths. Six fresh
role runs used the same retained v3.49.0 candidate source
`76c31929833b5571d25a56d9783e24a0997d5422`, build
`b70d59e2681c4a3f`, config
`8ef7a22ac7a4d01bd79e15fd9ed891d1328c86d62a3848a0e6e48d94594b9492`,
private manifest
`66703091ba2f7815341aa0a3535de1c52c35ec3a170c2348975ef8704a1ae2d5`,
prefix `67b80a2ba2a54872d53ba0704ad801b99eb1153ce9c8b2d6ab2ff4e2093d2e28`,
and draft controller source `7364fbc27dc95d0de97c2d9ec157fbb54f832fdb`
with installed tree `01ba175093b9e9a7a114eedde2c213e9254426f079c8ec0c2b201b9ff2f0c4ec`.

| Role | Run ID | Host-pinned tap journal SHA-256 |
| --- | --- | --- |
| success | `f1c65bdc771557b2` | `283f81bbec3ecfe8fb0ec6d825bb123cff4c38a52299ecd86e94d6ec7ae4248a` |
| input-binding | `3d75b0a15d43d19f` | `e536dea45748fc4d1ad69a637039c860854dd26d40a7175d7f4323279a6549dd` |
| injection | `92bccef2e009aced` | `f20c49c9f7cd8230cf04c1f91a602ec7d7f717708807ec05d0413a47c05ae899` |
| boundary | `6e756b7efd7ce186` | `2035bae5987172546d28886fb1c8b6b4e1011af3b9016fb1def47000c922f8ea` |
| timeout | `6fb16eb8099c11de` | `6588e51ed5ee26c04b05944084a6ca55c7384fbc6f9061bfb921ba934d2ec56c` |
| cancel | `3a0e496bda80e749` | `133d0da232e16011afe7d9b12613cb14e41b7818a49fed6f3100f8c7efae7e11` |

The one-use host v5 suite manifest SHA-256 was
`b848021f9f8ff3ae347485228d4c0ddeadef80a5f8d492ad73b2ebadaa6998f9`.
Its 3,749-byte Root-owned mode-0444 guest copy matched. The previously
SHA-matched ARM64 reader
`d2d6e8053597af513b444a40690503a8e0795196c67abde743e456baa0aaadb6`
checked all six host key and journal pins, signed records, live sampled
SDK/Bun/Native relations and the source-bound docs oracle. It returned six
matched roles, 144 matched tap frames, 12 signed Native proxy processes,
32 physical files, five absent effects, six cleanup journals and absent
cgroups. No Podman container remained after the final role. Linux
warnings-denied all-target Clippy, macOS all-target `cargo check`, the
focused Linux PID-namespace test and the host suite-pin test passed.

This closes the tap child's PID/mount namespace implementation and live
transport check, not the full Gauntlet migration. The six-role reader still
lacks independent product-side frame/effect observation and Guard-decision
causality. The controller and private-cell source remain a draft integration
generation, the fixed guest readout lacks independent VM attestation, and
there was no model inference or conformance package. The VM finished with
8,601,567,232 free bytes, only 11,632,640 above the 8-GiB admission floor;
another fresh run needs inspected disk reclamation first.

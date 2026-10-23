# Live SDK-agent container process identity diagnostic

On 2026-10-21, a read-only VM inspection during a fresh Rust-owned `success`
control found the product-cell service below the job-specific systemd slice,
while the SDK agent ran in a separate Podman scope below `machine.slice`.
The earlier [live cgroup suite](gauntlet-rust-live-kernel-staging-proof.md)
sampled the job slice but could not identify that agent process. The Rust
worker now bounds a second sampler to Root-owned
`/sys/fs/cgroup/machine.slice/libpod-<64-hex>.scope/container` directories.
It reads their kernel `cgroup.procs`, then uses a pidfd-backed double check of
each live PID's start tick and exact unified cgroup. It retains at most 64
distinct process identities; this is a periodic sample, not a complete trace.

The new worker binary SHA-256 matched on Mac and VM at
`2dfbc44f2a69d5d11ab78ff891b491c6909fd20fe778b368fe82816de139e3ec`.
The ARM64 worker test binary SHA-256 was
`a55908faa22ec451d64f15ffd939f84bcaace8a3d2dd9f59284f904e911c029b`;
77 tests passed, with three Root-only fixture tests intentionally ignored.
Warnings-denied ARM64 Clippy and Rustfmt passed.

The one-use run was `fcd8b16d3f7ad136`, under build job
`b70d59e2681c4a3f`, source
`76c31929833b5571d25a56d9783e24a0997d5422`, and provisional config
digest `8ef7a22ac7a4d01bd79e15fd9ed891d1328c86d62a3848a0e6e48d94594b9492`.
The Mac prelaunch key journal SHA-256 was
`58fb551d0514949b742dff559d04ff3063fd136067bc7a6ee858438f8eb8665b`.
The Root-owned signed record SHA-256 was
`815de2663ae1ae1cfe6996915267e0f6d22b3d99a4c95b07f08685bc840bd30c`;
the terminal-bound report SHA-256 was
`346ceea4e97974a51edc97ba4a822dd71fa11bcbb681a31d5b69ba285aeb684b`.
The report retained 23 distinct process tuples across two observed Podman
container IDs. The signed record declared SDK-agent container
`4e2d0015575b8cd3fc2483a7d7395fb36704751fc4ce6ed3fd065dfa658f79cc`,
PID `1306845`, and start tick `34272143`; the Rust kernel sample contained
that exact tuple in
`/machine.slice/libpod-4e2d0015575b8cd3fc2483a7d7395fb36704751fc4ce6ed3fd065dfa658f79cc.scope/container`.

A separate Root-only Rust verifier, SHA-256
`181ddb9ab12fd39b9f9b6767287207c2178ad204efd3cc31a48b03dda66b88de`
on host and VM, reopened the outside-pinned signed control and five exact
physical files. It matched the Mac-supplied prelaunch key/worker/start pins to
the Root terminal and report hash, required positive live controller and
product-slice samples, checked every retained container tuple's shape and
cgroup path, found the one declared agent PID/start tuple, and confirmed both
job cgroups absent after cleanup. It returned
`agent_kernel_identity_matched:true`, `sampled_container_processes:23`,
`execution_eligible:false`, and
`independent_sdk_native_guard_causality_verified:false`. Supplying an
incorrect started-marker pin refused with exit 2. The ARM64 evidence test
binary SHA-256 `897b1d708367492b53efdb31263a0363de4fa0b09ccd00572aed6de1cb6511f5`
passed all 44 library tests; warnings-denied ARM64 Clippy passed. Podman had
no retained containers afterward and the 48-GiB VM had 9,551,163,392 bytes
free, above its 8-GiB floor.

This corroborates one agent container's kernel PID, start tick, and cgroup
against a signed controller claim. Periodic polling can miss short-lived
processes. The Rust owner writes the sample summary, and the verifier depends
on caller-supplied fields independently read from the host prelaunch journal;
the guest cannot read that Mac journal itself. It does not independently
authenticate the SDK executable, an SDK tool call, the Native product
processes, or a Guard enforcement decision. The run remains an
`invalid-evidence` diagnostic with no conformance package, installed-control
pass, model inference, or CI-gate admission.

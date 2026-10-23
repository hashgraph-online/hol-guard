# Six-role SDK executable identity in Rust staging

On 2026-10-21, a fresh six-role local staging suite used the Root-owned Rust
worker to hash the running SDK gate process's executable bytes and capture its
complete command line between two pidfd/start-tick/cgroup observations. The
Root verifier matched each captured process to the signed gate PID, distinct
signed agent PID, exact Podman container/cgroup, fixed private-cell SDK
command, and a host-manifest Bun SHA-256 pin. The result is a diagnostic, not
execution admission.

The local patched 3.49.0 candidate had source
`76c31929833b5571d25a56d9783e24a0997d5422`, build job
`b70d59e2681c4a3f`, provisional config
`8ef7a22ac7a4d01bd79e15fd9ed891d1328c86d62a3848a0e6e48d94594b9492`,
private-cell manifest
`66703091ba2f7815341aa0a3535de1c52c35ec3a170c2348975ef8704a1ae2d5`,
and installed prefix tree
`67b80a2ba2a54872d53ba0704ad801b99eb1153ce9c8b2d6ab2ff4e2093d2e28`.
The fixed Mac caller SHA-256 was
`fca8331a821fe9b5a36e07f0cec7fcff25bcfe46d69bcab13afc3171441d24f0`.
The final staging-specific ARM64 worker SHA-256 was
`898e0ce4e274364296814eb1dd6fce5e8f92bbd5a00c73323f13737cf566287e`;
the VM copy was Root owned, mode 0500, one link, and SHA matched. The
controller generation/tree, interpreter and provisional assets stayed at the
[v4 proof's](gauntlet-rust-sdk-gate-process-proof.md) pins.

The config's Bun role and a separate Root read of
`/opt/hol-workflow-matrix-public-20261014-001/bun` both hashed to
`37141662ebed915a2ab89313156e455e2a1374395f5f6760d06407f49406f086`.
The fixed command was `/runtime/bun`,
`/runtime/public/private_cell_sdk_conformance.ts`,
`/runtime/public/episode.json`; its NUL-separated argument digest was
`2384aaacd0c241cb3d946dbe24b7b39db98d64023a89c327514dd11484ee3618`.
This is the staging adapter's SDK script, not the separate developer episode
script.

| Role | Run ID | Signed record SHA-256 | Root report SHA-256 |
| --- | --- | --- | --- |
| success | `31e49073894ad659` | `d969b62e479fd4d2035a0547bf8b90488f1d7ca585586ada9cae08dfa7fedc00` | `eccc42b4fc0b907952fe54869107285e64a8cf4d9d71b31dc784fd920143d391` |
| input-binding | `7dfe9e5ad361f6a7` | `180d7d3c6c99ec2ac0af75fc507ddf0b3caaa31eedd95cfeeb27c81241960c53` | `980d100e51831edf282f2d5719b578c714ae51ee8a2717d123fd2babf88da677` |
| injection | `d822f45bd1d848f5` | `94d102f4db016bf62eaceecac0260c12be0dcb0f6c866354fd70a6cef125ea1f` | `cf72303c7d38e8b9abdd6975bb75904e179fb04fe205cf17a577eb54fbe79ec3` |
| boundary | `5fbfb7eb189d5436` | `c7744d00bf7d9cbf39f9b508ea6f6d58123e611a4055dd10e71f7665c5b9495a` | `d6a3ef5fd2ce832f7851049885154e58961f81c11b82736711af82e454a86346` |
| timeout | `e4ddfa46c337f810` | `c3048256dac21d38fdf9c5e1eccf38d9c0c80440576728295df8ece85b1bacd4` | `22768e782e2477a669e712bb6cd36a5de94e61645ba02056580fd3558bdd5362` |
| cancel | `4f4af34f8fb5b34d` | `051523cfe4c2da55d34ab1cc72ba2696a6518acaf1b4709ba9f62137b64a9748` | `db59675b8dc6df00ae1553c954fe7d8468d7e80ed9aa8c36f197656a69224f3e` |

All six host calls exited zero. Each Root report recorded exactly one matching
SDK executable row with the Bun and command digests above, and each reported
controller/product cleanup. Separate `podman ps -a` checks after the roles
were empty. The Mac host tool SHA-256
`3724b8a8657861ddbe31e106aab4ce262bd8de6260d862d9529dbd6fa9d8a5c4`
reopened the six distinct prelaunch key journals and exclusively wrote a
mode-0600 v5 manifest keyed by the new success run. The host bytes, transfer,
and Root-owned mode-0444 VM copy all hashed to
`c6ac2fa675e254c4017fba79078ec9eb804be02d1c143c5ff0776484bfda7551`.
The final Root-only ARM64 verifier SHA-256 was
`d1fb6e071a17387191dc098f2a71d541e149bcf1ea9671a7a5ec6dc6f384c86b`;
the VM copy matched and was mode 0500, Root owned, one link.

The v5 verifier reopened six signed records, retained files and reports,
invalid-evidence terminals, and both cgroup roots. It returned
`hol-gauntlet-staging-suite-shadow.v5` with six live kernel roles, six signed
agent identities, six signed gate identities, six Bun executable/command
matches, 32 physical files, five absent effects, six cleanup journals, absent
post-run cgroups, and `execution_eligible:false`. A manifest digest altered
only in its last hex digit refused with exit 2. The same binary accepted the
retained v4 suite with unchanged v4 output.

The SHA-matched ARM64 worker test binary
`4b0d355bcc72f773f0602ce02ada8182e4ed7521041f27a11147203457f2d5d2`
passed 78 tests with three intentionally ignored Root-only fixtures. The
ARM64 evidence test binary
`72db606cdb82df2130e933c3503d247e6b31b265cf96a3e0604514bcf27d74af`
passed all 46 tests. The Mac host manifest test, warnings-denied ARM64
worker/evidence and Mac host Clippy, and Rustfmt passed. VM free disk after
temporary test-binary cleanup was 9,285,369,856 bytes, above the 8-GiB floor.

Two earlier diagnostics explain the fixed command requirement. A generic VM
shadow binary installed under a staging path refused its CLI before any host
key was reserved; that wrong binary was removed. A staging-specific worker
then collected no executable row because the sampler expected the developer
episode script. A separate live Root process listing showed this staging
lane's private-cell script; after the exact command was corrected, six new
one-use roles produced the v5 proof. Those earlier controls remain retained
diagnostics and are not counted in the v5 manifest.

The sampled executable bytes and command are Rust-owner observations during
the process lifetime. Polling can miss short processes, and the owner writes
its own report. The Bun digest supplied to the host manifest matched the
Root-owned config and file, but source/installer pins have not had an
independent production review. This check does not prove SDK tool calls,
Native product effects or Guard decisions. All six terminals remain
`invalid-evidence`; no fresh scored conformance package, installed-control
result, model inference or PR gate exists.

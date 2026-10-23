# Live cgroup samples for a second Rust staging suite

On 2026-10-21, the Rust-owned staging worker was extended to sample kernel
`pids.current` and `cgroup.events` while each fixed Python control ran. It
held a Root-owned cgroup descriptor, checked the controller group's identity,
and opened the job-specific systemd product slice directly under
`/sys/fs/cgroup`. The first live `success` run independently confirmed that
slice's location and `populated 1` while the control was active. A prior suite
verifier had checked the product-slice name in the wrong parent; its corrected
read-only rerun is recorded in the [suite proof](gauntlet-rust-staging-suite-proof.md).

The candidate source was `76c31929833b5571d25a56d9783e24a0997d5422`,
the provisional v7 config digest was
`8ef7a22ac7a4d01bd79e15fd9ed891d1328c86d62a3848a0e6e48d94594b9492`,
and the shadow build job was `b70d59e2681c4a3f`. The Mac caller binary SHA-256
was `fca8331a821fe9b5a36e07f0cec7fcff25bcfe46d69bcab13afc3171441d24f0`.
The new Root-owned Linux ARM64 worker was installed under its full SHA-256,
`7755af4f046ebd74efc1c0709ef47e21d7ca09eccacea20f7a97bf95cbfa9440`,
after a matching host/guest byte check. Each one-use public signing key was
durably pinned on the Mac before its controller spawned.

| Role | Run ID | Signed record SHA-256 | Samples | Peak controller tasks | Peak product-slice tasks |
| --- | --- | --- | ---: | ---: | ---: |
| success | `fe00b8b5f8b8140d` | `ffce65975b144592ca66b7ac3bdb895856f16209af433765cc8af3dcc460d860` | 331 | 47 | 109 |
| input-binding | `b0541bc45a24ec1c` | `7fc74758402d19741af06eeb2d73158c84a5a64aec33c5cfec7175be1213b204` | 469 | 49 | 111 |
| injection | `7da676bc616ffdc0` | `c81c6e9dcf633dded591155db7d7b25268652ce5eb0db34aa5dd8e6d01115a3b` | 362 | 48 | 111 |
| boundary | `66d0a27494b13d0c` | `f4feec8f0ad3b1605d588bc168cb737f8ef12cfabc2847680ab2d74cedd58532` | 333 | 46 | 108 |
| timeout | `a4d12c057ec7bd39` | `af1076817e7661508fd6c2e417bd5bb055efde0ce04aa70dd8225e62ed3a4cef` | 320 | 46 | 112 |
| cancel | `d1452bceb636b4d4` | `45c2f72a24564bdb1b70877a1445a3bd5147ae194f62a8a543bcde064b36dc22` | 377 | 46 | 112 |

Every report recorded `product_slice_observed:true` and
`product_slice_populated:true`. The six report byte hashes matched their
Root-owned `invalid-evidence` terminal hashes. A separate read-only pass
found both fixed cgroup paths absent for each run, and `podman ps -a` was
empty. The VM had 9,817,640,960 free bytes afterward, above its 8-GiB floor.

The host suite tool, SHA-256
`3cfa43a44bfb816e89b5cb1af75d945ee0ca9259cc2ee342d210e437ebb9d9e1`,
reopened all six durable prelaunch key journals and wrote a second one-use
manifest keyed by the `success` run. The private host manifest and its
Root-owned guest copy had the same SHA-256,
`82c3c6674352bc3fa4b50197d51625cb19c02a4df255f31ca9324c37f4304766`.
The Linux verifier binary, SHA-256
`64e8cdcb195f9eda995d8c22024d73b69060658d2410b4cb3c10242474286642`,
reopened the six signed records, checked 32 physical files and five absent
effects, matched six terminal and cleanup journals, required positive live
controller/product cgroup samples in every report, and verified absence of
all twelve post-run cgroup paths at their correct roots. It returned
`live_kernel_roles_sampled:6`, `signed_records:6`, `physical_files:32`,
`absent_effects:5`, `cleanup_journals:6`,
`host_prelaunch_key_pins_matched:true`, `outside_cgroups_absent:true`, and
`execution_eligible:false` under schema
`hol-gauntlet-staging-suite-shadow.v2`. The earlier v2 verifier build also
passed against the same retained suite. An unprivileged call refused with
exit 2.

The ARM64 worker library passed 76 tests with three Root-only fixture tests
ignored. The ARM64 evidence library test binary SHA-256
`715dd3ccf65164aeda306ccbde6e4aec1000ee210e53ac4338c894eb236d0ce0`
passed 43 tests; the Mac host suite test
and nine host library tests passed. Warnings-denied ARM64 worker/evidence and
Mac host Clippy, plus Rustfmt, passed. These tests and live checks establish a
bounded cgroup-activity diagnostic, not exhaustive process lineage. The
Rust owner itself writes the sample summary; the host key pins the controller
record, not each kernel sample. SDK/Native process identity, exact Guard
causality, independently attributed control verdicts, a signed conformance
package, installed controls, model inference and CI-gate admission remain
open. The result deliberately states
`independent_kernel_sdk_effects_verified:false` and
`conformance_package_created:false`.

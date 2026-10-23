# Six-role SDK-agent process attribution in Rust staging

On 2026-10-21, six one-use staging controls ran through the fixed Mac caller
and a Root-owned Rust worker on the 2-vCPU, 16-GiB, 48-GiB Linux ARM64 VM.
The `success` run began the [single-agent diagnostic](gauntlet-rust-agent-process-proof.md);
the other five roles used the same worker generation afterward. This was a
local patched 3.49.0 candidate at source
`76c31929833b5571d25a56d9783e24a0997d5422`, build job
`b70d59e2681c4a3f`, and provisional config digest
`8ef7a22ac7a4d01bd79e15fd9ed891d1328c86d62a3848a0e6e48d94594b9492`.
The two allowed release wheels still lack the required contained-completion
capability. This suite did not use either release wheel or a model provider.

Before reserving the five new runs, the installed controller generation
`2932d5a8ce25ac91` was checked against the digest independently derived
from its pinned 396-file source map,
`dbff38a80cc42858f7c52fbb3ec7037bf34b512a99d9906bf6081b7157435bde`.
The SHA-matched ARM64 read-only verifier
`e82a160a13670ce2c80cc80ecccafe0e3d9285c72925b7a0cf0583b40306fa90`
found 407 Root-owned entries and the same tree digest. The fixed interpreter
and Rust staging worker were independently rehashed on the VM at
`c86f21d0da9290ece2d7d49a3f7ed52aed59cb029abdf0ea25c79634f6cbe960`
and `2dfbc44f2a69d5d11ab78ff891b491c6909fd20fe778b368fe82816de139e3ec`.
The Mac caller remained
`fca8331a821fe9b5a36e07f0cec7fcff25bcfe46d69bcab13afc3171441d24f0`.

| Role | Run ID | Signed record SHA-256 | Process tuples | Report SHA-256 |
| --- | --- | --- | ---: | --- |
| success | `fcd8b16d3f7ad136` | `815de2663ae1ae1cfe6996915267e0f6d22b3d99a4c95b07f08685bc840bd30c` | 23 | `346ceea4e97974a51edc97ba4a822dd71fa11bcbb681a31d5b69ba285aeb684b` |
| input-binding | `064ae44c3dce7d1b` | `03d2c7cc50e5865afbed1a3c704d0407df16748baec7e617f28f5651d9e9a58f` | 24 | `754d184f713a2056c3c60fa17dd3396151ff1b028dde986f1cdd9219b5491bdc` |
| injection | `0e45faa6ff955b6b` | `ba671d5c9c55d39ee75f765f53066c2a293bd748c2d2d567f894cfae9c3ed365` | 22 | `edd3b0c8d6163e6fe7346b31b5732bf70907dcd5e9b2e65780f93428f603e7fa` |
| boundary | `d841a2108ca594b8` | `216cb1514f0a7dc6f9d7f9ca0dfffc4d8555c734ce8f60adb94f3352277811f9` | 22 | `c9767edb5b9f2b63339afd201e50cfda122cf084cf8018fd2b1a9e9fc57b1b75` |
| timeout | `68c4405f6f6cc8aa` | `4e3af169967bc2f3410e6b95b444af2c0c5790c5f464b7063aeebc561aee4448` | 26 | `65026a702ed967d923db2ada1192b297fd6fa04902358e566c3f441605fe90b8` |
| cancel | `5088048dc04fa44d` | `1b5e41304616b3858ac835f34777d53717150ad4e53bf8b65ccce2c046f7e36d` | 26 | `a649f7681615d0246eafc428e2b57cccd7602e6b4430538b2f5f4bfece77d50b` |

The Rust Mac host suite tool SHA-256 was
`23cab5564c800a18d7ffdba3091503231e33842233707ce6e66d8fa30ad8d997`.
It reopened six distinct durable prelaunch key journals and exclusively wrote
a v3 host manifest keyed by the success run. The 3,585-byte private manifest,
its guest transfer, and its Root-owned mode-0444 guest copy all hashed to
`dfeefd437c49c2afe9d55d4240d3169dd0a39233ac101c447e82b3905157348d`.
The final Root-only ARM64 suite verifier SHA-256 matched on host and VM at
`162186f6cbdb67da8c7f85e48f9833dd6205872d417dd1782ac07a21460cb0eb`.
It reopened the six signed records, exact retained physical files, reports,
terminals and both fixed cgroup parents after cleanup. It required each
signed SDK-agent container ID, PID and start tick to appear exactly once in
that role's bounded pidfd-checked Podman cgroup samples. Its final result was
`signed_records:6`, `live_kernel_roles_sampled:6`,
`live_agent_roles_sampled:6`, `physical_files:32`, `absent_effects:5`,
`cleanup_journals:6`, `outside_cgroups_absent:true`, and
`execution_eligible:false` under
`hol-gauntlet-staging-suite-shadow.v3`. A manifest digest changed only in its
last hex digit refused with exit 2. The same final verifier accepted the
retained v1 and v2 suites with their original output fields and counts,
without a new v3-only field.

The final ARM64 evidence test binary SHA-256 was
`0df9f0473271ca7a62132ef2b5cf042bf8758f9402365075abbe49a1a34361a7`;
all 44 tests passed on the VM. The Mac host suite test, warnings-denied ARM64
evidence and Mac host Clippy, and Rustfmt passed. Each new control reported
exit zero and cleanup completed, and separate `podman ps -a` checks after
the roles were empty. The VM free-space floor stayed above 8 GiB.

This proves a bounded match between six signed producer claims and the Rust
owner's periodic kernel process samples. Polling can miss short-lived
processes; the owner itself writes the report, and the guest receives host
prelaunch fields through a copied manifest. The check does not authenticate
the SDK executable or tool call, Native product processes, or a Guard decision.
All six terminals remain `invalid-evidence`. There is no independently scored
conformance package, installed-control result, model inference or PR gate.

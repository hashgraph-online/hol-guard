# Retained staging filesystem-effect audit

On 2026-10-21, a separately cross-built Linux ARM64 Rust diagnostic
`gauntlet-staging-physical-files-shadow` (host and VM SHA-256
`81b358c43b5ea5c93b132536d5d285ba875c435e06eefa80b5e36f324cc539f9`)
opened each of the six previously host-pinned signed staging records, then
read fixed physical files under its distinct Root-owned `/home/hx-<run>/<role>`
directory. Its file reads are bounded, descriptor-relative, no-symlink,
owner/mode/link checked, and repeated to reject changes during the audit.
The ARM64 unit-test binary had SHA-256
`5729f79b7e7905f60ac011bfd696a5a9ee64b7a9f337fa15efd34bfb9672f554`;
all 40 evidence library tests passed in the VM, including exact-file and
symlink-refusal cases. Warnings-denied ARM64 Clippy passed before the live run.

| Role | Signed record SHA-256 | Physical files | Absent effects |
| --- | --- | ---: | ---: |
| success | `2a3dc8717455c55e45288a42530f516762d58a5128e802b951f5e45f1fabe2b8` | 5 | 0 |
| input-binding | `6c982bd7bbaf3a931c552288c05c19c7a5255ad4c0cebd79ab282c0fe3dc4148` | 6 | 1 |
| injection | `7a4126b4d720c2146ed9b96285c0daea1796dce51c6df237fb2a5e6f84c2f788` | 6 | 0 |
| boundary | `ec3bc00e42c33ab8d8300adf78c9695ee5b715b41c9af11b3db8d9022ce3698b` | 8 | 0 |
| timeout | `d2f2a93ebb4263f2a122fd5caedb24d06c9b8360dcde522accd5b0a47205cb66` | 3 | 2 |
| cancel | `e35618941aebf84b03090504747839681e396fefe3db639d473a959314a2f4ad` | 4 | 2 |

Every role matched the SDK stdout byte hash in its record and the two exact
provider-mount effect files. The four completed roles retained the exact
contained output. Success, input-binding and injection retained a Node runtime
file whose parsed JSON matched the record. Input-binding and injection
retained the forbidden-command marker with `preserve`; input-binding had no
negative-test sink. Boundary retained the three exact canary bytes under their
expected owners and the negative-probe JSON. Timeout and cancel had no
completed contained output or late detached-child effect; cancel retained the
expected detached-ready token. The `success` audit ran alone, then two pairs
ran concurrently on the 2-vCPU/16-GiB VM, followed by cancel. All six returned
exit 0 with `physical_files_checked:true` and `execution_eligible:false`.

This is a post-run file corroboration. It cannot reconstruct the live kernel
process samples or prove which process wrote the files, that the SDK executed
as reported, that Podman isolation held throughout, or that Guard policy
caused the blocked effect. The diagnostic explicitly returns
`independent_kernel_sdk_effects_verified:false`. A live outside observer,
suite-level cleanup reconciliation, source/content review and a fresh
conformance package are still required before admission.

# Six-role SDK gate process attribution in Rust staging

On 2026-10-21, the Root-owned Rust staging suite verifier matched the signed
SDK gate PID and process start tick to a separate, pidfd-checked process in the
same sampled Podman container and cgroup as the signed SDK agent for all six
roles. The diagnostic remains ineligible for execution admission.

The local patched 3.49.0 candidate had source
`76c31929833b5571d25a56d9783e24a0997d5422`, build job
`b70d59e2681c4a3f`, provisional config
`8ef7a22ac7a4d01bd79e15fd9ed891d1328c86d62a3848a0e6e48d94594b9492`,
and Root worker generation
`2dfbc44f2a69d5d11ab78ff891b491c6909fd20fe778b368fe82816de139e3ec`.
The fixed Mac caller was
`fca8331a821fe9b5a36e07f0cec7fcff25bcfe46d69bcab13afc3171441d24f0`.
The two allowed release wheels still lack the contained-completion capability;
this suite used neither release wheel nor a model provider.

Five one-use controls and their signed record pins were retained from the
[v3 six-agent proof](gauntlet-rust-six-agent-staging-proof.md). A new `success`
control `143dfa505c8c7476` was required because the earlier success run had
already consumed its one-use host suite-manifest key. The new run exited zero,
reported completed cleanup and retained 24 bounded process tuples in 330
samples. Its signed record SHA-256 is
`4c6d3d57e09ebfd4ef6f73c682a18260b435c2b247dfa19a1e9323dedaf3a875`;
its Root report SHA-256 is
`2710e90688ae31ca62cb6e9a01c6ad242f545b2b040387125d1484832813a8c6`.
The prelaunch host key journal SHA-256 is
`a6cdce9bd7bfb40bd733ed82e8da3a1295bde1e90be86b8859af68c27f94098d`.
The signed agent PID/start tick was `1314396`/`34463951`; the signed SDK gate
PID/start tick was `1314419`/`34463958`, under Podman container
`f51e6b90db4326c2b178aa9a3cc72d7fcabbb6a026674b001833e99bb1cd2b46`.
The five retained roles each also had exactly one separate gate PID/start tuple
in their existing Root owner samples.

The Mac host manifest tool SHA-256 was
`bead1428bf93976383bd305c606f1f47b14597995c5fd84f4e81f568a6b7ca79`.
It reopened the six distinct durable prelaunch key journals, bound them to the
same source/config/worker generation, and exclusively wrote a v4 manifest
keyed by the new success run. The mode-0600 host manifest, transferred bytes
and Root-owned mode-0444 VM copy all matched SHA-256
`1ca60c418bc225aa7893e8805f39fda47143dc571fb69639cba98fa54c2d4a98`.
The final Root-only ARM64 verifier SHA-256 was
`3a48ca705f6026ffe5a801e23f8338cdea25e3988671ad1c32275a0cbc10dae6`;
host and VM binaries matched, and the VM installation was mode 0500, Root
owned, one link.

The v4 verifier reopened all six signed records, exact retained physical files,
Root reports, invalid-evidence terminals, and controller/product cgroup paths.
For each role it required the signed agent and SDK gate PID/start ticks to
appear as distinct processes in the same exact container/cgroup sample. It
returned `hol-gauntlet-staging-suite-shadow.v4` with six signed records, six
live kernel roles, six live agent roles, six live SDK gate roles, 32 physical
files, five absent effects, six cleanup journals, both cgroup roots absent,
and `execution_eligible:false`. A manifest digest altered in its last hex
digit refused with exit 2. The same v4 binary accepted the retained v3
manifest with its original v3 output fields and counts.

The SHA-matched ARM64 evidence test binary
`2c91a86d1805c6241533a4e440a2686ffb62eb7ff79563598fb6f3580369c6c5`
passed all 45 tests; the Mac host suite test, warnings-denied ARM64 evidence
and Mac host Clippy, and Rustfmt passed. A separate post-run Podman listing was
empty and VM free space remained above the 8-GiB floor.

The kernel samples are periodic and owner-reported, so they can miss short
processes. Matching a signed producer PID to a live process does not
authenticate that process's executable, SDK calls, Native product effects or
Guard decisions. The six terminals remain `invalid-evidence`; there is no
independently scored conformance package, installed-control result, model
inference or PR gate.

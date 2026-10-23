# Host-pinned six-role staging suite reconciliation

On 2026-10-21, a Mac Rust host tool read the six distinct, durable prelaunch
controller-key journal files from the private host directory. It required one
source `76c31929833b5571d25a56d9783e24a0997d5422`, revised v7 config
digest `8ef7a22ac7a4d01bd79e15fd9ed891d1328c86d62a3848a0e6e48d94594b9492`,
worker generation `c781d86ff5b481bf3b1a70561b46e538dd44b4b233174ad5c9b0b06d2dd85dc7`,
six unique run IDs and six unique public keys. The caller supplied the six
previously opened record digests. The host tool binary SHA-256 was
`b04084ca7e808bb898658988f2b3387506d5f36e34190001e684504ce5e2e761`.
It exclusively wrote a mode-0600, one-link, 3,511-byte canonical manifest
under the private host pin directory; its SHA-256 was
`a23715c6a8126e15230bc51855b8003880bc9b4e2c366bad3eaad82c3ea6ab0a`.
A separate readback matched that digest. The host assembly test, eight existing
host-key journal tests and warnings-denied native Clippy passed.

The same bytes were copied to the Linux ARM64 VM and installed at
`/opt/hol-gauntlet/rust-shadow-candidates/b70d59e2681c4a3f/suite-pins-a23715c6a8126e15.json`
as a Root-owned, one-link mode-0444 file. Guest SHA-256 readback matched the
host manifest. A separately cross-built Rust suite verifier had SHA-256
`da7f1a196c105f71d8c906e299460ed45d5293c2c63f1aaa25b3c7ed3d384c1e`
on host and guest. Its SHA-matched ARM64 unit-test binary
`93f8b5831062bd3795ef19a8907823879a320a0c845328958f6f7d51d68f3b6e`
passed 41 evidence library tests, including manifest refusal of duplicate
one-use runs; warnings-denied ARM64 Clippy passed.

The live verifier read the fixed manifest from the shadow namespace against
the separately supplied host digest. For each role, it reopened the signed
record and exact source/config/assets, checked the retained physical files,
then read the Root-only report and `invalid-evidence` terminal. It matched
terminal key, started-marker, controller-key-pin, worker-generation and report
byte digest to the host manifest and guest report. It required the six reports
to say cleanup completed, then reported each controller cgroup and product
slice absent. The product-slice path error in that first check was corrected
and rerun as described below. The original result was `signed_records:6`,
`physical_files:32`, `absent_effects:5`, `cleanup_journals:6`,
`host_prelaunch_key_pins_matched:true`, `outside_cgroups_absent:true`, and
`execution_eligible:false`. A separate post-run Podman listing was empty.
The same verifier refused an unprivileged call with exit 2.
The 48-GiB VM had 10,159,808,512 bytes free afterward.

The suite takes about nine minutes on this 2-vCPU VM because it rehashes the
large pinned SDK/asset set for every role. This is a valid diagnostic readback,
not an admitted benchmark. The host manifest's provenance depends on the
host tool's prelaunch-journal read and the outside SHA supplied to the guest;
the guest cannot independently read the Mac journal. Post-run files and
absent cgroups do not reconstruct live kernel process identity, SDK/Native
execution, or Guard causality. The verifier explicitly returns
`independent_kernel_sdk_effects_verified:false` and
`conformance_package_created:false`. Source/image review, a live outside
observer, full physical-effect scoring, fresh conformance, installed controls,
model inference and PR-gate policy remain open.

## Corrected product-slice location

The first suite verifier checked both cgroup names under `system.slice`. That
was correct for the Rust controller group but wrong for the systemd product
slice: the worker's slice guard and a fresh live VM observation place
`holgauntletrust<run>.slice` directly under `/sys/fs/cgroup`. The first suite
result therefore did not establish product-slice absence. The corrected
verifier checks the controller group under `system.slice` and the product
slice at the cgroup root, reopening each parent before accepting absence.
An ARM64 test refuses an existing or symlinked slice at the correct root.
The corrected binary SHA-256 matched on host and VM at
`5a412dd68776f57ed54086e81708d0cf679a09e823b04240a09454ab2ea36bb5`;
its ARM64 test binary SHA-256 matched at
`4eeaa30741786db92375de643efe77eb8c8ba5015fc6871fcf1d839083cabad6`.
All 42 evidence library tests and warnings-denied ARM64 Clippy passed. A
fresh read-only rerun of the six retained roles with the same host manifest
returned the same counts and `outside_cgroups_absent:true`, now checking all
twelve cgroup paths at their actual roots. This corrects the post-run absence
claim only; it does not reconstruct the roles' live processes.

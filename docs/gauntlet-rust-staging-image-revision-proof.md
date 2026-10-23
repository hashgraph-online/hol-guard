# Staging executor-image preflight and one-use config revision

The first Rust-owned `success` control, run `9234dcc85ee9f0e6`, reached the
fixed Python adapter and wrote a Root-only, signed 21,128-byte record. The Mac
host had fsynced the guest key pin before spawn. Rust retained its running,
report and `invalid-evidence` terminal journals, stopped the product slice and
removed the controller cgroup. The record SHA-256 was
`e8a10513092df4e2d3b49bfe35dfdd712824ee23bd421c4ed1c94e21a63fcfe9`.
The independent Rust opener refused it: `control_completed:false`,
`sdk_exercised:false`, and a Podman image-inspect exit 125. A direct Root
read-only Podman inspect confirmed the provisional config's exact
`sha256:ee463d528a53eb19093fd6f7bd1122123a0de957904dd7b4d90f6c50cf152b08`
image was absent. Neither that control nor its host transport exit is a
benchmark pass or a model result.

The Rust staging readiness now checks the config's exact local image ID with
a bounded, fixed `podman image inspect` and requires the reported Linux ARM64
ID to match before reserving a staging run or pinning a host key. The staging
plan, Python adapter and independent record opener derive the same distinct
config filename from both the private-cell manifest and the canonical config
digest. The older provisional file and failed record remain retained.

A new one-use Rust revision helper ran on the idle ARM VM under both worker
locks. It read the old source-matched v7 config at canonical digest
`d35d212fef57e793cbaabbd9e99f52925ca9150e4dde647bc7f24982c49499fe`,
verified all 13 inert assets and the candidate identity, and changed only the
executor image ID to the already present local Linux ARM64 image
`sha256:e43d3b4e594a7c2992ba184b330e0f1206fdc1b7d57c47d4dbff8d7d959dcfa1`.
It exclusively wrote a Root-owned, one-link mode-0444 file
`/opt/hol-gauntlet/rust-shadow-candidates/b70d59e2681c4a3f/provisional-66703091ba2f7815-8ef7a22ac7a4d01b.json`.
The new canonical digest is
`8ef7a22ac7a4d01bd79e15fd9ed891d1328c86d62a3848a0e6e48d94594b9492`,
and independent file SHA-256 readback matched
`59c3aa4fa87ee5811da34e82d47b0fdd37b854a48f7954c03c4d3ef9b3e4b281`.
The old file's SHA-256 remained
`120c16060b1710280677624379f22a67fc7d92f51791d79eab90dfa9f34f583a`.

The revision helper binary SHA-256 was
`05fda74a09cdf9e8ba941304e029ab342292d909fac72c1a6e185e11ba6ef3ff`
on the Mac, guest transfer and Root installation. A SHA-matched Linux ARM
worker test binary passed 75 tests with three intentional Root fixture
ignores, including the v7 projection test. Warnings-denied ARM Clippy, the
Python adapter tests, the integration source-inventory test and the updated
controller install-plan tests passed locally. The revised config and existing
image are diagnostic inputs; their image content has not yet been independently
approved or exercised by a successful control. Fresh signed controls,
physical-effect scoring, real inference and a conformance package remain open.

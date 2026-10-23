# Post-write process images in the Rust collector

Implementation: `fa2ca5f343e34fed4cb19be50513212f19a99879`; asynchronous
sampling fix: `da49d13413f3e01ba648b454e911cdd9e1940593`.

The [signed product readback](gauntlet-rust-signed-product-proof.md) could
identify the product namespace and provider writes, but retained contained
outputs had writers absent from the signed CLI samples. New Root-relay
captures use `hol-gauntlet-staging-effect-events.v3` to retain bounded process
images after close-write. This establishes an observed executable identity
for a fresh contained-output writer; request/decision attribution remains open.

## Capture and compatibility

The collector selects three fixed files: the remote and home provider
controls and `tasks/checkout/native-contained.txt`. A proc-fd basename is
only a filter. Selection opens the fixed role path without symlinks and
compares device, inode and opaque kernel file handle with the held event fd.
Only the exact run's product service can supply a process image.

A separate bounded thread samples the duplicated, close-on-exec pidfd while
the original event collector continues sampling writer PID/start/cgroup
tuples. It hashes the held executable and command bytes, retains only a fixed
action label, and checks UID/GID 10004, namespace PID, parent PID, NoNewPrivs,
seccomp mode and mount/PID/user namespaces. PID lifetime, process fields,
command bytes, namespaces and executable metadata are checked around the
sample. Raw command arguments are never serialized.

The executable bound is 64 MiB; proc fields are bounded to 16 KiB. At most
64 image jobs may be queued over a capture's lifetime. Overflow refuses the
capture after the current event batch is closed. The existing 32,768-event,
16-MiB and 500,000-node journal limits remain in force. The collector joins
the image thread before retaining the journal. Unavailable process images
remain explicit nulls, even when the earlier PID/start tuple was observed.

Both host and guest readers require matching v3 receipt/journal versions,
strict image fields, unique event references and matching file/PID/start
identity. Historical v1/v2 formats retain their meanings. A v3 image is
sampled **after** the event, not atomically with the writing instruction;
PID/start and before/after checks do not exclude every intervening exec.
Neither the action label nor executable hash proves Guard causality.

## Fresh VM results on 2026-10-22

The retained v3.49.0 build `b70d59e2681c4a3f`, source
`76c31929833b5571d25a56d9783e24a0997d5422`, config
`8ef7a22ac7a4d01bd79e15fd9ed891d1328c86d62a3848a0e6e48d94594b9492`
and controller generation `7364fbc27dc95d0d` were unchanged from the
[product kernel proof](gauntlet-rust-product-kernel-proof.md). The candidate
VM had 2 vCPU, 16 GiB RAM and a 48-GiB disk. No model inference ran.

| Artifact | SHA-256 |
| --- | --- |
| Final asynchronous ARM64 worker | `1c8a37cd56b5f91fb25ea8f3e17003e5dbacdffddd14e45cb9cd628d6ac553aa` |
| Root v3-compatible effect reader | `7625a0633f90f69e4289828e3550606b2b95e2e681660a73413e032ed349c90e` |
| macOS launch command | `c9493af5633ceecf11d075432977c3959042f43d0312d241e2974545b62c210c` |
| macOS joint restart command | `cafbb2dce16b2f770673de67e9d8ba93e8b8bed4bb5a39cd417f68bb07be537c` |
| Final ARM64 worker tests | `9b42482aa3b141f8e16cd1178f5f68e6ee3ad98b1908663cd494e4f1bd36a57d` |

The first worker (`f8cce55c702aed45e08227b2369d8581979ab13c85c2b0c5ba3500f417cc7e19`)
sampled images inline. Run `f742b1c1d850e807` captured a contained writer,
but the delayed event loop lost the short-lived home-provider writer. Its
signed readback correctly refused with `final effect has an unknown or
foreign writer`. This failure remains retained under journal
`5a29a2cc2d78d95b1c693e05b747c383b42b568e26ddc0409df129267181c293`
and report `84eca1e3c41507468edc29864a09038035d8c5d296b63dac7982442379751494`.
The asynchronous fix addresses this observed interference; it does not
recover missing historical observations.

The final success run `3da328ac01870040` exited zero and verified controller
and product-slice cleanup. It retained 24 SDK frames and 9,304 close-write
events, with 168 unknown writers elsewhere. The host pinned journal
`c7247324aade227887d36241f02b2ceb70b2c896c46e332095985a36d0ebf308`,
report `88c22e0058cc7d7ce000487f686e4a588fb046b54d22c53458291e7ec35b0f4e`
and terminal `37b6d22fea2ae5d7c9fa697c64d92fed5f459e2c3e5f7a4b3b9e271bb5a467b8`.
Joint signed readback accepted both provider files with one known write each.
Their process images were unavailable; their PID/start tuples were known.

The contained-output image at event 4948 identified PID 1440453/start
43526094, namespace PID 64, parent PID 1440452 and action `serve-managed`.
Its executable SHA-256 was
`533d72c30de62b460556c7330067e1078b353b094ee2fc3f1edf0f6d6af83eed`,
matching the `native` asset in the independently digest-checked runner config.
Its argv hash was `8543465670244c52cc02d557eda4507b68d3d5a53c30a1493807fc99b5dd9574`.

A separate read-only audit checked the pinned journal/report and opened the
retained output through no-symlink descriptors. The file contained the exact
20 bytes `private plane effect`, SHA-256
`93313832ed89058af22413b62b883ac6225572fc7e1b7551e8c224893ba542cc`.
Device 64769, inode 3466694 and kind-1 handle `c6e53400d4fa30b8` matched
exactly one event. That writer's cgroup and three sampled namespaces matched
the independently retained product observation. This diagnostic comparison
has not yet been composed into a trusted Rust contained-effect verifier.

## Validation and next exits

- All five contracts and 18 host library tests passed on macOS, including
  v1/v2/v3 custody, altered image references, missing observations and downgrades.
- The final ARM64 test executable passed 114 default tests in the isolated
  test VM, with 24 explicit tests ignored. The privileged keyed-journal test
  then passed for both v2 and v3. Four focused writer tests passed in the ARM
  container, including asynchronous ordering and overflow refusal.
- ARM64 warnings-denied Clippy passed for contracts, host and worker, all
  targets/features; the worker check was repeated after the asynchronous fix.
- The new host and Root reader also accepted the original v2 success run
  `a7deb0326f5e460f` under its existing pins. Its evidence was not regenerated.

The candidate VM had 8,808,865,792 bytes available after these runs. Parent
milestones remain 24 complete/38 open. Next work must compose contained-file,
Native asset, signed request/decision and process evidence in Rust, extend
live coverage beyond this success control, and handle deletion/replacement
and genuinely unknown writers. All results remain `execution_eligible:false`
and `guard_causality_verified:false`; the release observer and PR gate stay passive.

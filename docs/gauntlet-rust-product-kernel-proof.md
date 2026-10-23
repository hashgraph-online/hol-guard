# Independently sampled product service and task mounts

Follow-up: [v2 file generation proof](gauntlet-rust-file-generation-proof.md)
records six newer runs with opaque kernel handles. The v1 observations below
retain their original refusals and limits.

Implementation source: `849dda6e6ffec0b60f685fc3c231101078e3f903`.

The Rust staging worker now discovers the private product service directly
under the run-ID-derived cgroup slice. Its expected service identity no longer
comes from the filesystem event journal. During a live run it holds a pidfd,
finds the UID/GID-10004 namespace init, requires no-new-privileges and filtered
seccomp, and checks PID/start/cgroup before and after collecting its namespaces,
executable hash, argv hash and mount inventory hash. Mount, PID, network, IPC,
UTS and cgroup namespaces must differ from the observer; the user namespace
must be the observer's initial user namespace.

Through the held `/proc/PID/root` descriptor, the observer opens the three
fixed task paths with `openat2` beneath/no-symlink resolution. Each physical
UID/GID-10001 directory must have the same device, inode and mode in the
product view, with UID/GID 10004 there. The checkout requires mode 0755; both
providers require 0700. Each destination must have one `rw,nosuid,nodev`
mountinfo entry. Process root, namespace descriptors, executable, argv,
mountinfo, process identity and physical task paths are rechecked. The new
`live_product_activity` report field is separate from the unchanged v3 SDK
kernel-sample schema. It records one successful point-in-time sample, or an
explicit missing observation; it does not claim continuous monitoring.

This observes the ownership distinction described by the Linux kernel's
[idmapping documentation](https://www.kernel.org/doc/html/latest/filesystems/idmappings.html).
It does not independently verify the entire private-cell mount inventory,
LSM policy, capability state, network policy or all process descendants.

The read-only effect reader's `--kernel-report-sha` mode takes the host-pinned
report digest, validates the keyed completed terminal, derives the service
from the independent kernel sample, and rechecks the retained provider parent
against the sampled task inode. It then checks the held final file's exact
24 bytes and all matching close-write records. A missing sample, unknown or
foreign writer, wrong source/role/report/event digest, or changed task parent
refuses. The old caller-cgroup diagnostic remains available with its original
schema and `idmap_kernel_verified:false`.

The host joint restart command accepts `--kernel-effect-reader READER_SHA`.
It selects a fixed SHA-named Root reader that checks its own executable,
passes only the durable host key/report/event pins, verifies both provider
readbacks, and rereads the three host pins before returning. This produces
`hol-gauntlet-host-staging-kernel-effect-restart-readback.v1`, with
`execution_eligible:false` and `guard_causality_verified:false` throughout.

## Live validation on 2026-10-22

The VM was `hol-beta-bootstrap-20261016-004`, with 2 vCPU, 16 GiB RAM and
48 GiB disk. The retained v3.49.0 build was `b70d59e2681c4a3f`, candidate
source `76c31929833b5571d25a56d9783e24a0997d5422`, config
`8ef7a22ac7a4d01bd79e15fd9ed891d1328c86d62a3848a0e6e48d94594b9492`,
private manifest `66703091ba2f7815341aa0a3535de1c52c35ec3a170c2348975ef8704a1ae2d5`,
and prefix `67b80a2ba2a54872d53ba0704ad801b99eb1153ce9c8b2d6ab2ff4e2093d2e28`.
The separately installed draft controller generation was `7364fbc27dc95d0d`,
tree `01ba175093b9e9a7a114eedde2c213e9254426f079c8ec0c2b201b9ff2f0c4ec`.

| Artifact | SHA-256 |
| --- | --- |
| Final ARM64 staging worker | `2226f7d9470f4c9d175b6dd6838efddac82a612c5019c13ffc9eee13144338a5` |
| Root effect reader with executable self-check | `87fe31228eb663f75e68bc3821c88238c49ece04ac7efcd641155db4392f92a1` |
| macOS joint restart command | `c5de1db636b69eea239be38be0dcc0c52d998aa85d68bb9b4756f520e5c5b565` |
| ARM64 worker test binary | `4d85b6f60a9fdf1d69487172645377d082ee6ef21f02aebf2e9cfe87bebf6226` |

The first collector build (`93616b6a…`) incorrectly required a 0700 checkout.
Run `ef49f4e2aaeb3b77` completed and cleaned up but retained a null product
observation. Inspection of the pinned controller and live physical paths
confirmed the intended 0755 checkout. The exact-mode fix was tested before
the final worker was built. The new readback refuses that earlier report;
it does not retroactively manufacture a product sample.

| Final worker role | Run ID | Event journal SHA-256 | Total / unknown writers | Kernel-bound provider readback |
| --- | --- | --- | ---: | --- |
| input-binding | `7636b7b343ef8fd8` | `7178df9075d559a01ef8783f8c7ef7f9faeae932ba1110a18013f3e38e64d72d` | 13,824 / 165 | Both matched; 2 remote and 1 home close-writes |
| success | `9320e0380c322974` | `e9291544a395b4dfaddbca9551f1e32c52734d626e9b5a33db07d57a4d73d465` | 9,718 / 171 | Both refused: unknown writer |
| injection | `3fb8757a1a190de7` | `4c19148c2ed1b49eb29dd4b75dd4f8020e790a5d0d67e6364d24748566a35ecd` | 10,522 / 132 | Both matched; 1 close-write each |
| boundary | `0dc8300cb0ba049d` | `e47ff702a35b7c6dd112e4ddbf24ab35fe950b8689b5b8e3cd20faa840d0436e` | 9,213 / 146 | Both matched; 1 close-write each |
| timeout | `320bbd6718768d12` | `4097c47c121fa05b0fd74c8e82aeeb7caf94a29146a2414a25d44ca53450a530` | 9,100 / 146 | Both matched; 2 remote and 1 home close-writes |
| cancel | `67dde1772fc720c7` | `6656c4ab95e1702fd9b51cf2264e032304ea3591edf5118412f59a52574ca58f` | 8,981 / 165 | Home matched 2 close-writes; remote refused an unknown writer |

All six final runs exited zero, verified cleanup, retained 24 tap frames each,
and sampled the product init with all three task mappings. The strict reader
matched 9 of 12 provider files and refused 3. The original joint restart mode
verified terminal/tap/effect custody for all six runs; the stricter mode also
verified both provider files for input-binding, injection, boundary and
timeout. These are apparatus observations, not six independently passed
Guard controls.

The input-binding sample identified product init PID 1422967/start tick
42795944 in `hol-product-cell-282a044d747f4e3088366704bb38d676.service`,
with three matching task mappings. Its independently pinned report digest is
`e1261ed1372bbea8013ee9ba3f9837218055f0881b1c1e4096bd1ef36de5d201`.
Changing that digest or the Root reader digest refused with exit 2.

The success role demonstrates a remaining limit. Its final remote/home
inodes matched 125/85 filesystem events, each including one unknown writer
with reported PID 1424421 and no available pidfd (sequences 2607/2606).
The reader retained the refusal even though other events named known product
processes. Earlier writes to a reused inode are also possible because the
v1 journal stores device/inode without a file generation or retained file
handle. That is a limitation, not a confirmed explanation of these events.
Unknown writers and file replacement/reuse must be resolved before these
observations can support an independent control verdict.

The cancel role's remote file also refused: its 76 matching events included
one unknown writer, PID 1429099 at sequence 2682, without a pidfd. Its home
file matched two known product writes. No unknown writer was inferred from
another event that happened to carry the same PID.

The SHA-matched worker test binary passed 109 default tests on the separate
16-GiB ARM64 test VM `hol-beta-bootstrap-20261016-005`; 23 explicit
Root/fixture tests remained ignored. The four new worker tests cover
namespace-init selection, exact modes and owners, mount flags/duplicates,
and changed run/service/idmap inputs. The complete macOS host `--all-targets`
suite passed, including the new host parser's changed hash/surface/writer
refusals. Linux ARM64 warnings-denied Clippy passed for both crates.

After removing four verified, unused guest transfer copies while preserving
their installed and host counterparts, the campaign VM had 8,617,914,368
bytes free, only 27,979,776 bytes above the 8-GiB admission floor. Further
campaigns require more disk headroom; retained run evidence was preserved.

The tested host restart command for the input-binding run is:

```sh
/Users/construct/Documents/projects/hol-guard-refinement/gauntlet-rust-integration-20261020/ci/gauntlet-rs/target/release/gauntlet-host-staging-effect-restart-readback \
  /Users/construct/Documents/projects/hol-guard-refinement/rust-gauntlet-mount-pins-20261021 \
  7636b7b343ef8fd8 \
  76c31929833b5571d25a56d9783e24a0997d5422 \
  8ef7a22ac7a4d01bd79e15fd9ed891d1328c86d62a3848a0e6e48d94594b9492 \
  2226f7d9470f4c9d175b6dd6838efddac82a612c5019c13ffc9eee13144338a5 \
  37b5a2bfadbd3d9dd0b98ff3d4770cec16e6c35dc16904c8fdd6f3c99616c879 \
  --kernel-effect-reader 87fe31228eb663f75e68bc3821c88238c49ece04ac7efcd641155db4392f92a1
```

These are draft artifacts and passive observations. The host pins bind
retained bytes; they do not independently attest the VM or review the
controller/worker. Matching provider effects does not bind them to a
particular authenticated MCP request or HOL Guard decision. No new model
inference, conformance package, eligible benchmark verdict, observer cutover
or required PR gate is claimed.

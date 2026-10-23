# Kernel file identity in staging effect journals

Implementation source: `8a4fd0dea972866548413853085a486b56f5871f`.

The earlier device/inode-only journal could conflate writes to different
files when an inode was reused during a run. New captures use
`hol-gauntlet-staging-effect-events.v2` and a matching v2 receipt. Each row
retains the opaque kernel handle obtained through its fanotify file descriptor
with `name_to_handle_at(AT_EMPTY_PATH)`. The reader compares handle type and
bytes, together with the independently checked device and inode, to a handle
queried through the held final-file descriptor. The Linux API documents
[opaque handles as object identities](https://man7.org/linux/man-pages/man2/name_to_handle_at.2.html).
The mount ID is excluded because physical and idmapped views use different
mount IDs. No open-by-handle operation or pathname supplied by an event is used.

A missing handle remains null in the journal. Correlation refuses a matching
inode with a missing handle, an unknown writer for the matching handle, or a
foreign writer. It may exclude a different handle on the same inode because
that identifies another filesystem object. It never infers a writer from
another event for the same PID. Handles are bounded to 128 bytes, and the
32,768-event, 16-MiB and 500,000-node ceilings remain enforced. Unsupported
filesystems cannot obtain the stronger file-identity result.

Historical v1 journals keep their original parser and diagnostic meaning.
New fixed-file and kernel-bound readbacks use v2 only when they check the
handle, reporting `file_generation_verified:true`. Host readers enforce the
matching receipt/journal version and exact field sets. Both versions remain
`execution_eligible:false` and `guard_causality_verified:false`.

## Fresh six-role VM proof

On 2026-10-22, all six roles completed on
`hol-beta-bootstrap-20261016-004` (2 vCPU, 16 GiB RAM, 48 GiB disk), using
v3.49.0 build `b70d59e2681c4a3f`, source
`76c31929833b5571d25a56d9783e24a0997d5422`, config
`8ef7a22ac7a4d01bd79e15fd9ed891d1328c86d62a3848a0e6e48d94594b9492`
and the separately installed controller generation `7364fbc27dc95d0d`.
The private/prefix/controller pins are the same as the
[preceding product kernel proof](gauntlet-rust-product-kernel-proof.md).

| Artifact | SHA-256 |
| --- | --- |
| ARM64 staging worker | `14c7a9ff0beafbba19e75229d57138b1e230f7de5e6f5d45e313684df043f298` |
| Root effect reader | `6a8beb24f2400ba8aaedefb003494a05559115f29b62dd0edec738d97d46d396` |
| macOS joint restart command | `eb7cc159a083adcf96d0e7d327ac441aebe228725d30f1221677febc76924cf8` |
| ARM64 worker test binary | `a7b8f5dcf8c3550e8a1bb3377b5f5855a3a81e5fc55f09f533b151f10c919f82` |

| Role | Run ID | Total events / unknown writers | Host-pinned event journal SHA-256 |
| --- | --- | ---: | --- |
| success | `a7deb0326f5e460f` | 9,534 / 150 | `a54e07996e3213f12df7de8150035c9959803ae1549e6fa38b9a49214b12c5cb` |
| cancel | `1961236a91a67e30` | 9,059 / 132 | `8c4844929790e3106686bb2a5402dbaad0556228e952641ef28de9d015eb499e` |
| input-binding | `9d3ae13e0c83ebc0` | 13,933 / 164 | `87a98f8b9cbf065d96c8da7469a107940c8a5c22608cf83aa99e7fa6b5e502ec` |
| injection | `f5283eefdcf54842` | 10,660 / 143 | `2cb719014b03719323f3cb0d025297f702fa0994e253d6b2adca18aa887b5f37` |
| boundary | `ed3da355ee7bd682` | 9,635 / 157 | `b288c653c572e2a00ad0462e721407d16577a161901040b7965cc013798c7df3` |
| timeout | `4a6fba876d2d1aa0` | 9,246 / 142 | `925977f576bdc926c10a1782161b1fc378340ffd5760f59191410f9ff006b061` |

Every run exited zero, verified controller/product cleanup, retained 24 SDK
tap frames and an independent product/task-mount sample, and returned
`verified-ineligible-terminal` through the joint restart reader. All twelve
provider files matched one known product write each, including their exact
24-byte contents, file handle, observed service cgroup and task ID mapping.
All 62,067 event rows had handles. The 888 unknown writers elsewhere in the
filesystem-wide capture remain unknown; their count is not a Guard result.

The boundary run directly demonstrated the old ambiguity. Its final remote
inode matched 123 events across five handles; its final home inode matched
79 events across five handles. Each retained handle had exactly one known
product write. The remote unknown writer at sequence 2725/PID 1435430 had
handle `54e2340055db25b3`, distinct from final `54e234000e301f75`. The home
unknown writer at sequence 2727 had `55e23400b58d2104`, distinct from final
`55e23400eaa67135`. All were kind 1 handles on device 64769. The reader
excluded these other objects without identifying either unknown writer.
Across the six journals, 80/77/87/83/92/77 device/inode pairs respectively
had multiple handles. This establishes reuse in these new captures; earlier
v1 reports still lack the information needed to resolve their refusals.

The boundary report is pinned at
`2564d0036df4127451b8524458b24dcb9fd3628a8adcfd9bd52179cce9239783`.
The tested restart command is:

```sh
/Users/construct/Documents/projects/hol-guard-refinement/gauntlet-rust-integration-20261020/ci/gauntlet-rs/target/release/gauntlet-host-staging-effect-restart-readback \
  /Users/construct/Documents/projects/hol-guard-refinement/rust-gauntlet-mount-pins-20261021 \
  ed3da355ee7bd682 \
  76c31929833b5571d25a56d9783e24a0997d5422 \
  8ef7a22ac7a4d01bd79e15fd9ed891d1328c86d62a3848a0e6e48d94594b9492 \
  14c7a9ff0beafbba19e75229d57138b1e230f7de5e6f5d45e313684df043f298 \
  37b5a2bfadbd3d9dd0b98ff3d4770cec16e6c35dc16904c8fdd6f3c99616c879 \
  --kernel-effect-reader 6a8beb24f2400ba8aaedefb003494a05559115f29b62dd0edec738d97d46d396
```

## Tests and remaining scope

The separate ARM64 test VM passed 110 default worker tests, with 24 explicit
Root/fixture tests ignored in that invocation. Three relevant privileged
tests then passed separately: handle identity across rename/unlink and
replacement, live fanotify writer/file correlation, and keyed v2 journal
retention/readback. Synthetic matching tests refuse an unknown writer for the
same handle, a missing handle and a version mismatch. Host tests cover both
journal versions, one-use pins, changed evidence and v2 shape refusals.
The full macOS contracts/host `--all-targets --offline` suite and ARM64
warnings-denied Clippy for contracts, host and worker passed.

Five unused guest transfer binaries were archived under the private host
`rust-gauntlet-transfer-archive-20261022` directory and SHA-checked before
removing their guest copies. No run evidence or installed artifact was
removed. After the six runs the VM had 8,870,756,352 bytes available.

This completes the file-generation ambiguity check for the two fixed
provider files. It does not capture every deletion/replacement event, resolve
unknown writers for the matching object, or bind a write to an authenticated
MCP request and Guard decision. Native effects, fresh conformance, model
campaigns, reviewed installation and observer cutover remain open. The gate
stays passive.

The later [signed product readback](gauntlet-rust-signed-product-proof.md)
joins these same six retained runs to the controller's signed process and
task mappings under the original host key pins. It does not rerun or promote
the historical captures, and it records the remaining contained-writer gap.

The [v3 writer-image extension](gauntlet-rust-writer-image-proof.md) adds
bounded post-event executable/command samples while preserving these file
handle checks. Its fresh success run identified a contained-output writer
whose executable matched the pinned Native asset; request attribution remains open.


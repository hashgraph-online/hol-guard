# Signed product records and independent kernel effects

Implementation source: `058e71798f7123150b92f1da815606d63f81b01a`.

The optional signed readback joins the [kernel file-generation proof](gauntlet-rust-file-generation-proof.md) to the controller's signed product record. The Root reader verifies both Ed25519 envelopes using the one-use public key retained by the host before launch. It matches the signed session and source to the outside run pins, then matches the product PID/start tick, six namespace identities, NUL-delimited command bytes, complete mount-table bytes and all three task mappings to the independently collected, host-report-pinned kernel sample. Signed task declarations must also satisfy the existing idmap and mount-floor reader.

This is a comparison between independently collected kernel evidence and a signed report. A correctly signed but different process, namespace, command or mapping refuses. A missing generation, unknown matching writer or foreign writer still refuses in the underlying file reader. Both provider surfaces must refer to the same signed record and process. The old readback mode preserves its schemas and does not claim this new relation.

The controller's direct provider probes run before the SDK request. Their writes cannot be counted as Guard-mediated tool effects, even though their physical provenance is now joined to the signed product record. Every result remains `guard_causality_verified:false` and `execution_eligible:false`.

## Retained six-role validation

On 2026-10-22 the new readers successfully reopened all six runs from the file-generation proof on `hol-beta-bootstrap-20261016-004` (2 vCPU, 16 GiB RAM, 48 GiB disk). These are new readbacks of retained runs; no controller, benchmark campaign or model generation was rerun. The original key, tap, effect, report and terminal pins were neither rewritten nor recreated.

| Artifact | SHA-256 |
| --- | --- |
| New ARM64 Root effect reader | `0a31c5b92f1bc593144b78a32fd9372019ddf71e68ee383ac1eab899ede18cb0` |
| New macOS joint restart command | `37eaefd12fb5cf4f6b3423e0a1ab09d482e2dd3f5d8843f3bdee987936bedffb` |
| Original capture worker, unchanged | `14c7a9ff0beafbba19e75229d57138b1e230f7de5e6f5d45e313684df043f298` |
| Existing Root tap restart reader, unchanged | `37b5a2bfadbd3d9dd0b98ff3d4770cec16e6c35dc16904c8fdd6f3c99616c879` |

The ARM reader was SHA-checked on the host, after transfer, and at its new Root-owned mode-0500 installation path. It also checks its running executable against the supplied reader hash. Its path is `/opt/hol-gauntlet/rust-staging-effect-file-shadow-0a31c5b92f1bc593144b78a32fd9372019ddf71e68ee383ac1eab899ede18cb0`.

| Role | Run ID | Matched product PID / start tick | Stable control record SHA-256 |
| --- | --- | --- | --- |
| success | `a7deb0326f5e460f` | 1430647 / 43019204 | `ebc37adf184faf2a7372a8451226b3d0f6b67770c20649b1b5757b40e804f0f4` |
| cancel | `1961236a91a67e30` | 1431785 / 43033841 | `2b335bfe28d3696e3290f7b27cc517cc05caa42e153d9e68988014e15f3a6248` |
| input-binding | `9d3ae13e0c83ebc0` | 1432910 / 43049711 | `8b0bb9e5b22278aecdd63422287c0befe56dec65dca8459ed0a536d2b23af865` |
| injection | `f5283eefdcf54842` | 1434199 / 43059361 | `c985dd6f1dd7c1fb0a3efcdd7f569c159a1386b0e5bb74a00344c327bb411042` |
| boundary | `ed3da355ee7bd682` | 1435363 / 43066969 | `ba9793fff29e8f4bab022b789ede252a8a55160bc79d965ccfdcbe31544c6d4c` |
| timeout | `4a6fba876d2d1aa0` | 1436470 / 43074139 | `23879951c6c1083482c0c4f9c773e0e0ac9c52a33c2f6ff016d420bf35555791` |

All six returned `verified-ineligible-terminal`. Each matched three task mappings, six signed namespace IDs and the two exact provider files, for twelve file checks total. Each file had one close-write from a live-sampled process in the independently observed product cgroup. The command retains the original effect-journal statistics and reconciles the same host key/tap/effect pins before and after readback. It does not upgrade the terminal outcome.

The macOS binary is also retained, with its SHA-256 rechecked, at the private mode-0500 path used below. The tested command for the success role was:

```sh
/Users/construct/Documents/projects/hol-guard-refinement/rust-gauntlet-mount-pins-20261021/gauntlet-signed-product-host-20261022 \
  /Users/construct/Documents/projects/hol-guard-refinement/rust-gauntlet-mount-pins-20261021 \
  a7deb0326f5e460f \
  76c31929833b5571d25a56d9783e24a0997d5422 \
  8ef7a22ac7a4d01bd79e15fd9ed891d1328c86d62a3848a0e6e48d94594b9492 \
  14c7a9ff0beafbba19e75229d57138b1e230f7de5e6f5d45e313684df043f298 \
  37b5a2bfadbd3d9dd0b98ff3d4770cec16e6c35dc16904c8fdd6f3c99616c879 \
  --signed-control-effect-reader 0a31c5b92f1bc593144b78a32fd9372019ddf71e68ee383ac1eab899ede18cb0
```

The source, config, build and controller pins are unchanged from the file-generation proof. The new schema is `hol-gauntlet-host-staging-signed-kernel-effect-restart-readback.v1`, containing two `hol-gauntlet-staging-signed-kernel-bound-effect.v1` rows. Each contains the exact-field `hol-gauntlet-staging-signed-product-relation.v1` result.

## Verification

- Three new relation tests passed on macOS and Linux ARM64. They cover all six accepted roles, altered signed process/source/task/namespace/command/privilege claims, a consistently re-signed substitute task inode, duplicate observations, unsigned inner records, wrong outside keys and malformed run paths.
- All eighteen macOS host library tests passed. The host validator refuses mismatched source/key/run/process fields, missing file generation, unknown fields, eligibility promotion and older responses in signed mode.
- The focused ARM64 worker sample test passed. ARM64 Clippy passed with warnings denied for evidence, host and worker, including all targets and features. Rustfmt and diff whitespace checks passed.
- The new binary's old `--kernel-effect-reader` mode successfully returned the original v1 host envelope with v2 provider rows and no signed-relation field. Selecting the prior reader `6a8beb24…` for the new signed mode refused with exit 2 at the provider readback. An initial overlapping readback hit the exclusive lease; after the first handle completed, the serialized older-reader check reached and refused the intended provider stage.

These test counts describe this change. The original 110-worker-test VM run and privileged capture tests belong to the prior worker pin and are not claimed as rerun here.

## Next attribution gap observed

A separate read-only VM audit checked journal and record bytes against the hashes above, opened each retained `native-contained.txt`, queried its current opaque file handle, and selected events for that exact device/inode/handle. All four files contained the expected 20 bytes, SHA-256 `93313832ed89058af22413b62b883ac6225572fc7e1b7551e8c224893ba542cc`. Each had one known product-cgroup writer:

| Role | Writer PID / start tick | Final kind-1 handle | Event sequence |
| --- | --- | --- | ---: |
| success | 1430710 / 43019712 | `76de3400617968af` | 5222 |
| input-binding | 1432973 / 43050218 | `b2e03400fcfe536a` | 5126 |
| injection | 1434266 / 43059864 | `d7e1340020fec513` | 5151 |
| boundary | 1435545 / 43067823 | `02e3340022230c7f` | 5287 |

None of those four PID/start pairs appeared in the signed `executions[].kernel_process_samples` or identity-bearing `cell_observations`. A shared product cgroup therefore cannot by itself connect the final file write to the sampled contained CLI or its Guard review. The retained v2 writer tuple has no executable, command, parent chain or request identity, so those missing facts cannot be reconstructed from this journal.

Next work must capture the actual effect writer's live process identity and execution/request relation, including any persistent worker that applies a contained result, and bind it to the authenticated SDK/Native exchange. The audit does not identify that worker's executable or prove why it wrote the file. Cancellation/timeout absence, deletion/replacement observation, Guard-decision causality, fresh conformance, real inference, reviewed installation and final observer cutover remain open.

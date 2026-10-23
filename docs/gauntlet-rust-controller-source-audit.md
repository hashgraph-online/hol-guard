# Retained VM controller source audit

On 2026-10-20, the idle Linux ARM64 VM's v7 deployment manifest named the Root-owned controller directory `/opt/hol-gauntlet/controller-01abe774177c980b`. The read-only Rust deployment diagnostic verified the manifest/config digests and Root-owned directory ancestry, but intentionally did not claim the controller's Python source bytes matched a reviewed Git generation.

To assess that remaining boundary, the read-only [comparison script](../ci/gauntlet-rs/proofs/compare_vm_controller.py) was copied to the VM and verified against local SHA-256 `b7963063a863d1403eb6fbfed26e91e48e2fd0d5bc8e52c552fb9c638910dab4`. It compared each present source file's SHA-256 against both the 420-file pinned PR #5263 [baseline manifest](../ci/gauntlet-rs/parity-manifest.v1.json) and the then-425-file [integration source map](../ci/gauntlet-rs/integration-source-delta.v1.json). The same script returned 425/425 matches against that pre-merge integration map when run on this branch's local source tree. The map now contains 426 files after the upstream case-retry merge; no new retained-VM controller comparison has been claimed. On the VM, the exact unprivileged command was:

```text
python3 /home/construct.guest/compare-vm-controller.py /home/construct.guest/gauntlet-parity-manifest-v1.json /home/construct.guest/gauntlet-integration-source-delta-v1.json /opt/hol-gauntlet/controller-01abe774177c980b
```

| Comparison | Listed | Matching | Absent | Different | Symlinked | Unlisted Python |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| Pinned #5263 source | 420 | 313 | 63 | 44 | 0 | 1 |
| Current integration tree | 425 | 307 | 68 | 50 | 0 | 1 |

The unlisted installed file is `ci/gauntlet/workflow_bootstrap.py` (SHA-256 `aff56d907f0ced2aaf2e3e444bea6485ddbbc44d367c5a670b493615a028da90`). Its header describes a VM bootstrap script; a read-only search found no other Python source in that installed controller referring to `workflow_bootstrap`. The absent files include modules and development assets that the installer may have intentionally omitted, while the different files include runtime modules such as `__main__.py`. The comparison alone cannot determine why those differences exist or certify that the installed controller is unsafe. It establishes that neither reviewed Git source map is an exact provenance claim for this installed directory.

Before a Rust worker can launch or interpret this controller generation, capture the installer's intended exact file set and hashes in a separate reviewed, outside-pinned manifest; verify every executable/importable controller file and reject unlisted executable source. Alternatively build a fresh immutable controller generation from reviewed merged source and pin its installed artifact bytes. Keep the current Python observer and worker authoritative until one of those paths and the remaining worker checks pass. The asset-inventory parity proof remains valid as a read-only comparison of both readers on the **same retained files**; it does not establish controller-source identity or qualify a Rust execution result.

A later [read-only Rust whole-tree verifier](gauntlet-rust-controller-tree-proof.md) now checks an externally pinned Root-owned controller generation and refuses extra files, symlinks and hardlinks on an isolated VM fixture. It does not supply the missing reviewed digest for this retained installation or change the execution decision above.

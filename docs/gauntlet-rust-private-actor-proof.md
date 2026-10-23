# Rust private-cell actor process relation

`gauntlet-evidence::verify_private_actor` checks a supplied private-cell actor process observation against Python's `_actor` rule: positive PID and numeric start time, exact LSM label and namespace tuple, only FDs 0/1/2, four saved UID/GID 10004 slots, no supplementary group, no new privileges, zero capability masks and, for the filtered phase, seccomp mode 2 with at least two filters. It always returns `execution_eligible: false`.

The reproducible generator `ci/gauntlet-rs/proofs/generate_private_actor_vectors.py` extracts `_actor` from `private_cell_custody.py` SHA-256 `2de9c8c27d2b8f883291900ed3fe29f0f9aa7a318b03a195c4f20ba4f5a22cbb`. Fixture `private_actor_v1.json` SHA-256 `7d62bf9dca99523cc80ddbcb18dec2eefdc0f56626731bb6e4f7b56c9bca110e` has 20 Python outcomes: four accepted and 16 refused with matching messages. The targeted Rust parity test and warnings-denied Clippy passed in the pinned native ARM64 Rust 1.88 image.

The process identity, status, FDs and LSM label are supplied fields, not separately collected Linux observations. This is a boundary subproof; it cannot establish live product-cell containment or a Guard verdict.

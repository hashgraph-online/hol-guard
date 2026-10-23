# Rust product kernel-identity relation

`gauntlet-evidence::verify_product_kernel_identity` matches Python's `_kernel` relation for reported product UID 10004 and MCP UID 10005. It checks exact effective UID/GID, zero capabilities, no-new-privileges, the MCP saved UID/GID/group/capability sets, same boot, numeric start time and distinct controller/agent mount, PID and network namespaces. It returns `execution_eligible: false`.

The reproducible generator `ci/gauntlet-rs/proofs/generate_product_kernel_identity_vectors.py` extracts the actual `_kernel`, `_require` and namespace constant from `product_custody.py` SHA-256 `21888997033c9e3629c8490c53e929725ee431b696af9e7bb26f5346cb94864d`. Fixture `product_kernel_identity_v1.json` SHA-256 `e0ad9a7d2385e5c51af559891d0681d8c21e1d2b24819bb0f748afa363e9f965` contains 25 Python outcomes: four accepted and 21 refused with matching messages. The targeted Rust parity test and warnings-denied Clippy passed in the pinned native ARM64 Rust 1.88 image.

The identity is supplied data. Neither a controller signature nor a live `/proc` observation is bound here, and namespace uniqueness alone does not prove containment. This is one prerequisite for private-cell and Native hook custody, not a successful benchmark or control verdict.

# Rust private-cell network topology relation

`gauntlet-evidence::verify_private_network_topology` matches Python's loopback-only `validate_topology` over supplied `/proc/<pid>/net` device, IPv4 route, IPv6 route and IPv6 address text. It rejects extra interfaces, external IPv4 routes, nonzero IPv6 next hops and non-loopback IPv6 addresses. The kernel's explicit IPv6 unreachable default-route reject stub remains allowed. It returns `execution_eligible: false`.

The generator `ci/gauntlet-rs/proofs/generate_private_network_vectors.py` extracts the exact Python function from `product_vm_network.py` SHA-256 `4fd620041feeddeaaf5f699102450a0ae145c38da13dcc946f1087378360ff9a`. Fixture `private_network_v1.json` SHA-256 `7bc7b4443a4d4e7d6793f4d3d330896ca4369b7bb41e828bdbdcee8243040583` contains 20 cases: four accepted and 16 refused with matching reasons. A Rust-only test also enforces Python's 65,536-byte read budget. Both targeted tests and warnings-denied Clippy passed in the pinned native ARM64 Rust 1.88 image.

This checks supplied text, not a verified namespace-scoped `/proc` descriptor or a live product process. The private-cell custody and deterministic-verdict exits remain open.

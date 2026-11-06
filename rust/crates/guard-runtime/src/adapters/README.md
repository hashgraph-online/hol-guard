# Native harness adapter modules

- `detection/`: native, bounded app and config detection for each supported harness, plus detection tests.
- `adapter_inventory.rs`: adapter-related inventory.
- `adapter_vectors_tests.rs`: detection fixture parity.
- `hook_adapter_op.rs` and `hook_adapter_op_tests.rs`: resident hook normalization entrypoint and tests.

`src/main.rs` retains the existing Rust module names using explicit `#[path]` declarations. Keep source-to-fixture paths relative to their new physical directories. The native decision and policy authority must not be moved into Python.

See [adapter contributions](../../../../../docs/guard/adapter-contributions.md).

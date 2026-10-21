# Native hook adapter modules

`hook/` groups the hook payload preparation, normalization, redaction, Python-compatible wire parsing, and vector tests. The crate's `lib.rs` uses explicit `#[path]` declarations so existing `guard_command::hook_adapter_*` module names and imports do not change.

Changes to action normalization or fail-closed behavior require matching native tests and recorded fixtures under `rust/crates/guard-command/testdata/`. Do not duplicate security decisions in Python.

See [adapter contributions](../../../../../docs/guard/adapter-contributions.md).

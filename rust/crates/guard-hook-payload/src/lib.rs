//! Hook payload normalization, ordered JSON/value compatibility and payload
//! preparation, extracted from `guard-command`'s `adapters/hook/` surface so
//! the payload domain compiles independently of the command facade.
//!
//! The module names intentionally keep their production `hook_adapter_*`
//! paths: `guard-command` re-exports them at its crate root, so existing
//! `crate::hook_adapter_*` call sites keep resolving unchanged.
#![forbid(unsafe_code)]

pub mod hook_adapter_cline_tables;
pub mod hook_adapter_prepare;
pub mod hook_adapter_prepare_cline;
pub mod hook_adapter_prepare_cursor;
pub mod hook_adapter_pyjson;
pub mod hook_adapter_pytext;
pub mod hook_adapter_value;

mod shlex_quote;
pub use shlex_quote::shlex_quote;

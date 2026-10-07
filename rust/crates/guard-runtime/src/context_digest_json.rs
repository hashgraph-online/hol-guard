//! CPython-exact canonical JSON for approval-context digest material.
//!
//! The codec now lives in `guard-contracts::canonical_json` so `guard-command`
//! (binding digests) and `guard-runtime` share one byte-parity implementation.
//! This module is a thin shim preserving the `pub(super)` surface and the
//! `ERR_COMPONENT` error literal that `context_digest` callers already map.

use serde_json::Value;

use super::context_digest::ERR_COMPONENT;
use guard_contracts::CONTEXT_COMPONENT_MAX_BYTES;

/// Write `value` exactly as CPython `json.dumps(..., sort_keys=True,
/// separators=(",", ":"), ensure_ascii=True, allow_nan=False)` would.
pub(super) fn write_canonical_json_with_limit(
    value: &Value,
    out: &mut Vec<u8>,
    limit: usize,
) -> Result<(), &'static str> {
    guard_contracts::write_canonical_json_with_limit(value, out, limit, ERR_COMPONENT)
}

/// Unbounded canonical JSON with the approval-context byte limit applied.
pub(super) fn write_canonical_json(value: &Value, out: &mut Vec<u8>) -> Result<(), &'static str> {
    guard_contracts::write_canonical_json_with_limit(
        value,
        out,
        CONTEXT_COMPONENT_MAX_BYTES,
        ERR_COMPONENT,
    )
}

/// Escape a string body the way CPython's `ensure_ascii` encoder does.
pub(super) fn write_json_string(text: &str, out: &mut Vec<u8>) {
    guard_contracts::write_json_string(text, out);
}

/// Format a finite float exactly as CPython `repr()`/`json.dumps` does.
#[allow(dead_code)]
pub(super) fn python_float_repr(value: f64) -> String {
    guard_contracts::python_float_repr(value)
}

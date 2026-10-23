//! Exact pure output binding from the pinned Python contained sink. This
//! authenticates byte consistency within a supplied execution record, not the
//! Native process or physical source of those bytes.

use crate::crypto::sha256;
use crate::{canonical_value, EvidenceError, Result};
use serde_json::{json, Value};

const MAX_STREAM_BYTES: usize = 8 * 1024 * 1024;
const MAX_DELIVERY_BYTES: usize = 1024 * 1024 - 16_384;
const BOUNDED: EvidenceError =
    EvidenceError::Invalid("bounded actual contained result required for output binding");
const DIGEST: EvidenceError =
    EvidenceError::Invalid("captured contained output differs from its byte digest");
const DELIVERY: EvidenceError =
    EvidenceError::Invalid("captured contained output exceeds native review/delivery bound");

/// Reproduce Python `contained_output_binding.captured_output` on an already
/// obtained execution JSON value. No filesystem, process or SDK is accessed.
pub fn captured_contained_output(result: &Value) -> Result<Value> {
    let object = result.as_object().ok_or(BOUNDED)?;
    let exit_code = object
        .get("exit_code")
        .and_then(Value::as_i64)
        .filter(|code| (-255..=255).contains(code))
        .ok_or(BOUNDED)?;
    let stdout = object
        .get("stdout")
        .and_then(Value::as_str)
        .ok_or(BOUNDED)?;
    let stderr = object
        .get("stderr")
        .and_then(Value::as_str)
        .ok_or(BOUNDED)?;
    for (name, value) in [("stdout", stdout), ("stderr", stderr)] {
        let raw = value.as_bytes();
        if raw.len() > MAX_STREAM_BYTES
            || object.get(&format!("{name}_sha256")) != Some(&Value::String(sha256(raw)))
        {
            return Err(DIGEST);
        }
    }
    let text = format!("Exit code: {exit_code}\nSTDOUT:\n{stdout}\nSTDERR:\n{stderr}");
    if text.len() > MAX_DELIVERY_BYTES {
        return Err(DELIVERY);
    }
    let result_digest = sha256(&canonical_value(result)?);
    let output_sha256 = sha256(text.as_bytes());
    Ok(json!({
        "schema": "controller-contained-output.v1",
        "tool_response": [{"type": "text", "text": text}],
        "is_error": exit_code != 0,
        "result_digest": result_digest,
        "output_sha256": output_sha256,
    }))
}

//! Request-bound resident access to the shared shell helper kernels.
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::time::{Duration, Instant};

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ShellHelpersRequest {
    schema: String,
    request_id: String,
    action: String,
    input: Value,
    timeout_ms: u64,
}

pub(crate) fn evaluate(request: &ShellHelpersRequest) -> Result<Vec<u8>, String> {
    if request.schema != "guard-shell-helpers-request.v1"
        || request.request_id.is_empty()
        || request.request_id.len() > 128
        || request.timeout_ms == 0
        || request.timeout_ms > 10_000
    {
        return Err("shell_helpers_invalid_request".into());
    }
    let deadline = Instant::now() + Duration::from_millis(request.timeout_ms);
    let material = serde_json::to_value(request).map_err(|_| "shell_helpers_invalid_request")?;
    let mut canonical = Vec::new();
    crate::context_digest_json::write_canonical_json_with_limit(
        &material,
        &mut canonical,
        guard_contracts::MAX_NATIVE_REQUEST_BYTES,
    )
    .map_err(|_| "shell_helpers_invalid_request")?;
    let result = guard_command::shell_helpers::evaluate(&request.action, &request.input)
        .map_err(str::to_owned)?;
    if Instant::now() >= deadline {
        return Err("shell_helpers_deadline".into());
    }
    crate::resident_protocol::encode_response(
        &json!({"schema":"guard-shell-helpers-result.v1","request_id":request.request_id,"request_sha256":guard_policy_snapshot::digest_bytes(&canonical),"status":"ok","code":"ok","result":result}),
    )
}

#[cfg(test)]
#[path = "shell_helpers_vectors_tests.rs"]
mod tests;

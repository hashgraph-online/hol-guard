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
    let observed = if request.action == "heredocs_page" {
        match request.input.as_object() {
            Some(fields) if fields.len() == 2 && fields.contains_key("command") && fields.contains_key("offset") => {
                guard_command::shell_helpers::evaluate("heredocs", &json!({"command":request.input["command"]})).and_then(|value| {
                    let rows = value.as_array().ok_or("shell_helpers_invalid")?;
                    let offset = usize::try_from(request.input["offset"].as_u64().ok_or("shell_helpers_invalid")?).map_err(|_| "shell_helpers_invalid")?;
                    if offset > rows.len() { return Err("shell_helpers_invalid"); }
                    let end = (offset + 1024).min(rows.len());
                    Ok(json!({"items":rows[offset..end],"next_offset":if end < rows.len() {Some(end)} else {None}}))
                })
            }
            _ => Err("shell_helpers_invalid"),
        }
    } else {
        guard_command::shell_helpers::evaluate(&request.action, &request.input)
    };
    let (code, result) = match observed {
        Ok(value) => ("ok", value),
        Err(code) => (code, Value::Null),
    };
    if Instant::now() >= deadline {
        return reply(request, &canonical, "shell_helpers_deadline", Value::Null);
    }
    match reply(request, &canonical, code, result) {
        Err(code) if code == "native_response_too_large" => reply(
            request,
            &canonical,
            "shell_helpers_response_bounds",
            Value::Null,
        ),
        answer => answer,
    }
}

fn reply(
    request: &ShellHelpersRequest,
    canonical: &[u8],
    code: &str,
    result: Value,
) -> Result<Vec<u8>, String> {
    crate::resident_protocol::encode_response(&json!({
        "schema":"guard-shell-helpers-result.v1", "request_id":request.request_id,
        "request_sha256":guard_policy_snapshot::digest_bytes(canonical), "status":"ok", "code":code, "result":result,
    }))
}

#[cfg(test)]
#[path = "shell_helpers_vectors_tests.rs"]
mod tests;

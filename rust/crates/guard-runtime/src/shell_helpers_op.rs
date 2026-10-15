//! Request-bound resident access to the shared shell helper kernels.
use base64ct::{Base64, Encoding};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::VecDeque;
use std::sync::{Arc, Mutex, OnceLock};
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
    let decoded = unpack_claims(&request.input);
    let observed = decoded.and_then(|input| prepared_result(&request.action, &input, deadline));
    let (code, result) = match observed {
        Ok(value) => ("ok", Some(value)),
        Err(code) => (code, None),
    };
    let result_offset = request
        .input
        .get("result_offset")
        .map_or(Some(0), Value::as_u64);
    let result = if let Some(result) = result {
        match result_offset.and_then(|offset| usize::try_from(offset).ok()) {
            Some(offset) => match page_result(&result, offset) {
                Ok(value) => value,
                Err(code) => return reply(request, &canonical, code, Value::Null),
            },
            None => return reply(request, &canonical, "shell_helpers_invalid", Value::Null),
        }
    } else {
        Value::Null
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

fn unpack_claims(input: &Value) -> Result<Value, &'static str> {
    let mut fields = input.as_object().ok_or("shell_helpers_invalid")?.clone();
    fields.remove("result_offset");
    for (packed, plain) in [
        ("command_chunks", "command"),
        ("spans_chunks", "spans_json"),
    ] {
        if let Some(value) = fields.remove(packed) {
            if fields.contains_key(plain) {
                return Err("shell_helpers_invalid");
            }
            let chunks = value.as_array().ok_or("shell_helpers_invalid")?;
            if chunks.len() > 128 {
                return Err("shell_helpers_bounds");
            }
            let mut joined = String::new();
            for chunk in chunks {
                let chunk = chunk.as_str().ok_or("shell_helpers_invalid")?;
                if chunk.len() > 1024 * 1024
                    || joined.len().saturating_add(chunk.len()) > 6 * 1024 * 1024
                {
                    return Err("shell_helpers_bounds");
                }
                joined.push_str(chunk);
            }
            fields.insert(plain.into(), json!(joined));
        }
    }
    Ok(Value::Object(fields))
}

struct PreparedResult {
    value: Value,
    bytes: Vec<u8>,
    digest: String,
}

type PageCache = VecDeque<(String, Instant, Arc<PreparedResult>)>;
static PAGE_CACHE: OnceLock<Mutex<PageCache>> = OnceLock::new();

fn prepared_result(
    action: &str,
    input: &Value,
    deadline: Instant,
) -> Result<Arc<PreparedResult>, &'static str> {
    let key = guard_policy_snapshot::digest_bytes(
        &serde_json::to_vec(&json!([action, input])).map_err(|_| "shell_helpers_invalid")?,
    );
    let cache = PAGE_CACHE.get_or_init(|| Mutex::new(VecDeque::new()));
    {
        let mut entries = cache.lock().map_err(|_| "shell_helpers_invalid")?;
        entries.retain(|entry| entry.1.elapsed() < Duration::from_secs(8));
        if let Some(entry) = entries.iter().find(|entry| entry.0 == key) {
            return Ok(Arc::clone(&entry.2));
        }
    }
    let value = if action == "heredocs_page" {
        let fields = input.as_object().ok_or("shell_helpers_invalid")?;
        if fields.len() != 2 || !fields.contains_key("command") || !fields.contains_key("offset") {
            return Err("shell_helpers_invalid");
        }
        let full = prepared_result("heredocs", &json!({"command": input["command"]}), deadline)?;
        let rows = full.value.as_array().ok_or("shell_helpers_invalid")?;
        let offset = usize::try_from(input["offset"].as_u64().ok_or("shell_helpers_invalid")?)
            .map_err(|_| "shell_helpers_invalid")?;
        if offset > rows.len() {
            return Err("shell_helpers_invalid");
        }
        let end = offset.saturating_add(1024).min(rows.len());
        json!({"items": rows[offset..end], "next_offset": if end < rows.len() {Some(end)} else {None}})
    } else {
        guard_command::shell_helpers::evaluate_with_deadline(action, input, Some(deadline))?
    };
    let bytes = serde_json::to_vec(&value).map_err(|_| "shell_helpers_invalid")?;
    if bytes.len() > 64 * 1024 * 1024 {
        return Err("shell_helpers_response_bounds");
    }
    let digest = guard_policy_snapshot::digest_bytes(&bytes);
    let result = Arc::new(PreparedResult {
        value,
        bytes,
        digest,
    });
    if action == "heredocs"
        || action == "heredocs_page"
        || (result.bytes.len() > 256 * 1024 && !matches!(action, "normalization" | "trusted_path"))
    {
        let mut entries = cache.lock().map_err(|_| "shell_helpers_invalid")?;
        if entries.len() == 2 {
            entries.pop_front();
        }
        entries.push_back((key, Instant::now(), Arc::clone(&result)));
    }
    Ok(result)
}

fn page_result(result: &PreparedResult, offset: usize) -> Result<Value, &'static str> {
    const PAGE_BYTES: usize = 256 * 1024;
    const MAX_BYTES: usize = 64 * 1024 * 1024;
    let bytes = &result.bytes;
    if bytes.len() > MAX_BYTES || offset > bytes.len() {
        return Err("shell_helpers_response_bounds");
    }
    if bytes.len() <= PAGE_BYTES {
        if offset != 0 {
            return Err("shell_helpers_invalid");
        }
        return Ok(result.value.clone());
    }
    let end = offset.saturating_add(PAGE_BYTES).min(bytes.len());
    Ok(json!({
        "fragment_b64":Base64::encode_string(&bytes[offset..end]),
        "byte_offset":offset,"total_bytes":bytes.len(),
        "next_offset":if end < bytes.len() {Some(end)} else {None},
        "result_sha256":result.digest,
    }))
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

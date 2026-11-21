//! The `guard-cigar-bridge.v1` line protocol between the supervisor and a bridge.
//!
//! Same rules as the Python adapters this replaces: one JSON request per line
//! up to 1 MiB, one JSON reply per line up to 4 MiB. A wrong schema or request
//! id, an oversized or unterminated line, or an oversized reply ends the
//! session. Replies never carry error text, source text or local paths.

use serde_json::{json, Value};
use std::io::{BufRead, Read, Write};

pub(crate) const SCHEMA: &str = "guard-cigar-bridge.v1";
const MAX_REQUEST: usize = 1024 * 1024;
const MAX_REPLY: usize = 4 * 1024 * 1024;
/// Reply code for a request the bridge could not carry out.
pub(crate) const REQUEST_FAILED: &str = "BridgeRequestFailed";

/// Read one newline-terminated line of at most `limit` bytes.
pub(crate) fn read_line(reader: &mut impl BufRead, limit: usize) -> Option<Vec<u8>> {
    let mut line = Vec::new();
    let read = reader
        .take(limit as u64 + 1)
        .read_until(b'\n', &mut line)
        .ok()?;
    if read == 0 || read > limit || line.last() != Some(&b'\n') {
        return None;
    }
    Some(line)
}

/// Serve requests until stdin ends, a frame is refused, or `dispatch` asks to
/// stop after replying. `dispatch` returns the reply and whether to stop.
pub(crate) fn serve(
    input: &mut impl BufRead,
    output: &mut impl Write,
    mut dispatch: impl FnMut(&Value) -> (Result<Value, &'static str>, bool),
) {
    while let Some(line) = read_line(input, MAX_REQUEST) {
        let (id, outcome, stop) = match serde_json::from_slice::<Value>(&line) {
            Ok(frame) => {
                let Some(id) = frame.get("id").and_then(Value::as_u64).filter(|id| *id > 0) else {
                    return;
                };
                if frame.get("schema").and_then(Value::as_str) != Some(SCHEMA) {
                    return;
                }
                match frame.get("request").filter(|request| request.is_object()) {
                    Some(request) => {
                        let (outcome, stop) = dispatch(request);
                        (id, outcome, stop)
                    }
                    None => (id, Err(REQUEST_FAILED), false),
                }
            }
            Err(_) => (0, Err(REQUEST_FAILED), false),
        };
        let reply = match outcome {
            Ok(result) => json!({"schema": SCHEMA, "id": id, "ok": true, "result": result}),
            Err(code) => json!({"schema": SCHEMA, "id": id, "ok": false, "error": code}),
        };
        let Ok(mut encoded) = serde_json::to_vec(&reply) else {
            return;
        };
        encoded.push(b'\n');
        if encoded.len() > MAX_REPLY
            || output.write_all(&encoded).is_err()
            || output.flush().is_err()
        {
            return;
        }
        if stop {
            return;
        }
    }
}

/// A string member of a request, or the generic request failure.
pub(crate) fn text<'a>(request: &'a Value, key: &str) -> Result<&'a str, &'static str> {
    request
        .get(key)
        .and_then(Value::as_str)
        .ok_or(REQUEST_FAILED)
}

/// Any member of a request, or the generic request failure.
pub(crate) fn member(request: &Value, key: &str) -> Result<Value, &'static str> {
    request.get(key).cloned().ok_or(REQUEST_FAILED)
}

/// A member that may be absent or null, sent to the worker as `{}`.
pub(crate) fn or_empty(request: &Value, key: &str) -> Value {
    null_to_empty(request.get(key).cloned().unwrap_or(Value::Null))
}

/// `null` becomes `{}`, as the Python adapters sent `value or {}`.
pub(crate) fn null_to_empty(value: Value) -> Value {
    if value.is_null() {
        json!({})
    } else {
        value
    }
}

//! Privacy-safe correlation for observing a real installed hook invocation.
//!
//! A probe ID requests diagnostics only. It never grants approval, changes a
//! decision, or enables a fallback. Commands remain classification inputs.

use serde_json::{json, Map, Value};

const PROBE_FIELD: &str = "guard_transition_probe";
const PROBE_SCHEMA: &str = "hol-guard.transition-hook-probe.v1";
const OBSERVATION_SCHEMA: &str = "hol-guard.transition-hook-observation.v1";
const REQUEST_PREFIX: &str = "transition-hook-";

fn lowercase_hex(text: &str) -> bool {
    text.bytes()
        .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
}

/// `str(uuid.UUID(text)) == text`: the canonical lowercase hyphenated form.
fn canonical_uuid(text: &str) -> bool {
    text.len() == 36
        && text.split('-').map(str::len).eq([8, 4, 4, 4, 12])
        && text.split('-').all(lowercase_hex)
}

fn request_id(text: &str) -> bool {
    text.strip_prefix(REQUEST_PREFIX)
        .is_some_and(|rest| rest.len() == 32 && lowercase_hex(rest))
}

/// The `(operation_id, request_id)` a payload's probe names, if it is valid.
fn probe(payload: &Value) -> Option<(&str, &str)> {
    let fields: &Map<String, Value> = payload.get(PROBE_FIELD)?.as_object()?;
    if fields.len() != 3 {
        return None;
    }
    let text = |name: &str| fields.get(name).and_then(Value::as_str);
    let (schema, operation, request) =
        (text("schema")?, text("operation_id")?, text("request_id")?);
    (schema == PROBE_SCHEMA && canonical_uuid(operation) && request_id(request))
        .then_some((operation, request))
}

/// The request identity a valid transition probe asks the edge to echo.
pub(crate) fn probe_request_id(payload: &Value) -> Option<&str> {
    probe(payload).map(|(_, request)| request)
}

/// The observation a native receipt makes of the probe it answers: valid, and
/// a live, enforcing `PreToolUse` of exactly that probe.
fn observation(operation: &str, request: &str, receipt: &Value) -> Option<Value> {
    if !crate::edge::standalone_receipt(receipt, &Value::Null) {
        return None;
    }
    let text = |name: &str| receipt.get(name).and_then(Value::as_str);
    let recorded = text("request_id") == Some(request)
        && text("event_name") == Some("PreToolUse")
        && matches!(text("harness"), Some("codex" | "omp"))
        && text("payload_kind") == Some("inline")
        && receipt.get("observe_mode") == Some(&Value::Bool(false));
    recorded.then(|| {
        json!({
            "schema": OBSERVATION_SCHEMA,
            "operation_id": operation,
            "request_id": request,
            "native_receipt": receipt,
        })
    })
}

/// The probe a payload names, with the observation `receipt` makes of it
/// (`null` for no receipt or one that does not answer it). `None` when the
/// payload names no valid probe.
pub(crate) fn observe(payload: &Value, receipt: &Value) -> Option<Value> {
    let (operation, request) = probe(payload)?;
    Some(json!({
        "operation_id": operation,
        "request_id": request,
        "observation": observation(operation, request, receipt),
    }))
}

#[cfg(test)]
#[path = "transition_hook_observation_tests.rs"]
mod tests;

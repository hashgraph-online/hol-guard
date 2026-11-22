//! Fixed hook envelopes used when the native renderer is unavailable.
//!
//! The JSON contract is shared with the daemon adapter. Keeping the template
//! expansion here lets the native renderer answer the outage path without
//! making Python choose a harness envelope.

use serde_json::{Map, Value};

const CONTRACT: &str = include_str!(
    "../../../../../src/codex_plugin_scanner/guard/contracts/hook-fail-closed-envelopes.v1.json"
);

fn contract() -> Value {
    serde_json::from_str(CONTRACT).expect("hook fail-closed contract parses")
}

fn compact_event(event: &str) -> String {
    event.trim().to_ascii_lowercase().replace(['_', '-'], "")
}

fn kind(event: &str, document: &Value) -> String {
    let compact = compact_event(event);
    document["events"]
        .get(&compact)
        .and_then(Value::as_str)
        .or_else(|| {
            document["event_prefixes"].as_object().and_then(|prefixes| {
                prefixes
                    .iter()
                    .find(|(prefix, _)| compact.starts_with(prefix.as_str()))
                    .and_then(|(_, value)| value.as_str())
            })
        })
        .unwrap_or("lifecycle")
        .to_owned()
}

fn fill(value: &Value, reason: &str, reason_code: &str, event: &str) -> Value {
    match value {
        Value::String(text) => match text.as_str() {
            "$reason" => Value::String(reason.to_owned()),
            "$reason_code" => Value::String(reason_code.to_owned()),
            "$event_name" => Value::String(event.to_owned()),
            _ => value.clone(),
        },
        Value::Object(map) => Value::Object(
            map.iter()
                .map(|(key, value)| (key.clone(), fill(value, reason, reason_code, event)))
                .collect(),
        ),
        Value::Array(items) => Value::Array(
            items
                .iter()
                .map(|value| fill(value, reason, reason_code, event))
                .collect(),
        ),
        _ => value.clone(),
    }
}

/// Render the contract's fixed response for a harness and event.
pub fn response(
    harness: &str,
    event: &str,
    reason: &str,
    reason_code: &str,
    prompt_reason: Option<&str>,
) -> Result<Map<String, Value>, &'static str> {
    let document = contract();
    let response_kind = kind(event, &document);
    let selected_reason = if response_kind == "prompt" {
        prompt_reason
            .filter(|value| !value.is_empty())
            .or_else(|| document["defaults"]["prompt_reason"].as_str())
            .unwrap_or(reason)
    } else {
        reason
    };
    let envelopes = document["envelopes"]
        .get(&response_kind)
        .and_then(Value::as_object)
        .ok_or("native_hook_render_invalid")?;
    let template = envelopes
        .get(&super::canonical_hook_harness(harness))
        .or_else(|| envelopes.get("*"))
        .ok_or("native_hook_render_invalid")?;
    fill(template, selected_reason, reason_code, event)
        .as_object()
        .cloned()
        .ok_or("native_hook_render_invalid")
}

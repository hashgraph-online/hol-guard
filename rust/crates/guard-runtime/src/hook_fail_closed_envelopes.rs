//! Shared fail-closed hook envelope helpers.

use serde_json::{json, Value};

/// The daemon's fixed hook replies, declared once for every harness.
pub(crate) const ENVELOPES: &str = include_str!(
    "../../../../src/codex_plugin_scanner/guard/contracts/hook-fail-closed-envelopes.v1.json"
);

/// The envelope with its whole-string placeholders filled.
pub(crate) fn envelope(kind: &str, harness: &str, values: &[(&str, &str)]) -> Value {
    let contract: Value = serde_json::from_str(ENVELOPES).unwrap_or(Value::Null);
    let table = &contract["envelopes"][kind];
    let harness = harness.trim().to_lowercase().replace('_', "-");
    let template = table
        .get(harness.as_str())
        .or_else(|| table.get("*"))
        .cloned()
        .unwrap_or_else(|| json!({}));
    fill(template, values)
}

/// `_event_kind`: the envelope family an event name belongs to.
pub(crate) fn event_kind(contract: &Value, event: &str) -> String {
    let compact: String = event
        .trim()
        .to_lowercase()
        .chars()
        .filter(|character| *character != '_' && *character != '-')
        .collect();
    if let Some(kind) = contract["events"]
        .get(compact.as_str())
        .and_then(Value::as_str)
    {
        return kind.to_owned();
    }
    contract["event_prefixes"]
        .as_object()
        .into_iter()
        .flatten()
        .find(|(prefix, _)| compact.starts_with(prefix.as_str()))
        .and_then(|(_, kind)| kind.as_str())
        .unwrap_or("lifecycle")
        .to_owned()
}

/// Fill whole-string contract placeholders without interpreting payload text.
pub(crate) fn fill(template: Value, values: &[(&str, &str)]) -> Value {
    match template {
        Value::String(text) => values
            .iter()
            .find(|(placeholder, _)| *placeholder == text)
            .map_or(Value::String(text), |(_, value)| json!(value)),
        Value::Object(map) => Value::Object(
            map.into_iter()
                .map(|(key, value)| (key, fill(value, values)))
                .collect(),
        ),
        Value::Array(items) => {
            Value::Array(items.into_iter().map(|item| fill(item, values)).collect())
        }
        other => other,
    }
}

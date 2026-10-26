//! Credential denials shared by native contained-execution profiles.
pub(super) use crate::credential_patterns::patterns;
use serde_json::{json, Value};

pub(super) fn seatbelt_string(value: &str) -> String {
    format!(
        "\"{}\"",
        value
            .replace('\\', "\\\\")
            .replace('"', "\\\"")
            .replace('\n', "\\n")
            .replace('\r', "\\r")
    )
}

pub(super) fn denials(hide_metadata: bool) -> Vec<String> {
    let operation = if hide_metadata {
        "file-read*"
    } else {
        "file-read-data"
    };
    patterns()
        .iter()
        .map(|v| format!("(deny {operation} (regex {}))", seatbelt_string(v)))
        .collect()
}

pub(super) fn evaluate(operation: &str, input: &Value) -> Option<Value> {
    let value = match operation {
        "seatbelt_string" => json!(seatbelt_string(input.get("value")?.as_str()?)),
        "credential_patterns" => json!(patterns()),
        "credential_denials" => json!(denials(
            input
                .get("hide_metadata")
                .and_then(Value::as_bool)
                .unwrap_or(false)
        )),
        _ => return None,
    };
    Some(json!({"value":value}))
}

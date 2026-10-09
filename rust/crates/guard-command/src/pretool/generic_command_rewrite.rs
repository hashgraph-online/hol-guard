use super::extract::{parse_strict_nested_json, EMBEDDED_ARGUMENT_KEYS, MAX_PRE_TOOL_DEPTH};
use serde_json::Value;

const PROJECTED_COMMAND_KEYS: [&str; 7] = [
    "command",
    "cmd",
    "command_line",
    "commandLine",
    "shell_command",
    "shellCommand",
    "commands",
];

/// Rewrite every command copy the generic extractor reads.
///
/// Harnesses such as ZCode send the same tool input under both `tool_input`
/// and `toolInput`, sometimes once as an object and once JSON-encoded, and
/// a command value may be a one-element array. Projecting only one copy made
/// extraction see two different commands and block the call as ambiguous.
/// Only strings equal to the extracted command are replaced, so unrelated
/// strings stay untouched and any copy left unrewritten still fails closed.
pub(super) fn payload_with_command(payload: &Value, original: &str, command: &str) -> Value {
    let mut projected = payload.clone();
    rewrite_maps(&mut projected, original, command, 0);
    projected
}

fn rewrite_maps(value: &mut Value, original: &str, command: &str, depth: usize) {
    if depth > MAX_PRE_TOOL_DEPTH {
        return;
    }
    let next = depth.saturating_add(1);
    match value {
        Value::Object(record) => {
            for key in PROJECTED_COMMAND_KEYS {
                if let Some(slot) = record.get_mut(key) {
                    rewrite_command_value(slot, original, command, next);
                }
            }
            // Extraction also reads an encoded `parameters` string as a
            // command value, so a JSON array there may carry the command.
            if let Some(slot @ Value::String(_)) = record.get_mut("parameters") {
                rewrite_encoded(slot, |parsed| {
                    rewrite_command_value(parsed, original, command, next);
                });
            }
            for key in EMBEDDED_ARGUMENT_KEYS
                .into_iter()
                .filter(|key| *key != "parameters")
            {
                if let Some(slot @ Value::String(_)) = record.get_mut(key) {
                    rewrite_encoded(slot, |parsed| rewrite_maps(parsed, original, command, next));
                }
            }
            for child in record.values_mut() {
                rewrite_maps(child, original, command, next);
            }
        }
        Value::Array(items) => {
            for child in items {
                rewrite_maps(child, original, command, next);
            }
        }
        Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_) => {}
    }
}

/// Mirror the shapes `command_from_value` accepts: strings, JSON-encoded
/// strings, arrays and objects carrying command keys.
fn rewrite_command_value(slot: &mut Value, original: &str, command: &str, depth: usize) {
    if depth > MAX_PRE_TOOL_DEPTH {
        return;
    }
    match slot {
        Value::String(text) if encoded_json(text) => {
            rewrite_encoded(slot, |parsed| {
                rewrite_command_value(parsed, original, command, depth.saturating_add(1));
            });
        }
        Value::String(text) => {
            if text.trim() == original {
                *slot = command.into();
            }
        }
        Value::Array(items) => {
            for item in items {
                rewrite_command_value(item, original, command, depth.saturating_add(1));
            }
        }
        Value::Object(_) => rewrite_maps(slot, original, command, depth),
        Value::Null | Value::Bool(_) | Value::Number(_) => {}
    }
}

fn encoded_json(text: &str) -> bool {
    let trimmed = text.trim();
    trimmed.starts_with('[') || trimmed.starts_with('{')
}

/// Decode a JSON-encoded string, rewrite it and re-encode only on change.
fn rewrite_encoded(slot: &mut Value, rewrite: impl FnOnce(&mut Value)) {
    let Some(text) = slot.as_str().filter(|text| encoded_json(text)) else {
        return;
    };
    let Ok(mut parsed) = parse_strict_nested_json(text.trim().as_bytes()) else {
        return;
    };
    let before = parsed.clone();
    rewrite(&mut parsed);
    if parsed != before {
        if let Ok(encoded) = serde_json::to_string(&parsed) {
            *slot = encoded.into();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::payload_with_command;
    use serde_json::json;

    #[test]
    fn rewrites_array_and_json_encoded_copies_but_not_other_strings() {
        let payload = json!({
            "tool_input": {"command": ["ls > /dev/null"], "description": "ls > /dev/null"},
            "toolInput": "{\"command\":\"ls > /dev/null\"}",
            "arguments": "{\"cmd\":\"[\\\"ls > /dev/null\\\"]\"}",
            "commands": "ls > /dev/null && rm -rf /",
        });
        let projected = payload_with_command(&payload, "ls > /dev/null", "ls");
        assert_eq!(projected["tool_input"]["command"], json!(["ls"]));
        assert_eq!(projected["tool_input"]["description"], "ls > /dev/null");
        assert_eq!(projected["toolInput"], "{\"command\":\"ls\"}");
        assert_eq!(projected["arguments"], "{\"cmd\":\"[\\\"ls\\\"]\"}");
        assert_eq!(projected["commands"], "ls > /dev/null && rm -rf /");
    }

    #[test]
    fn rewrites_json_array_parameters_command() {
        let payload = json!({
            "parameters": "[\"ls > /dev/null\"]",
            "arguments": "[\"ls > /dev/null\"]",
        });
        let projected = payload_with_command(&payload, "ls > /dev/null", "ls");
        assert_eq!(projected["parameters"], "[\"ls\"]");
        assert_eq!(projected["arguments"], "[\"ls > /dev/null\"]");
    }

    #[test]
    fn leaves_undecodable_encoded_copies_unchanged() {
        let payload = json!({"command": "ls > /dev/null", "toolInput": "{\"command\": "});
        let projected = payload_with_command(&payload, "ls > /dev/null", "ls");
        assert_eq!(projected["command"], "ls");
        assert_eq!(projected["toolInput"], "{\"command\": ");
    }
}

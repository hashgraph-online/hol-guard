use super::super::sensitive_command;
use crate::MAX_COMMAND_BYTES;
use serde_json::{Map, Value};
use std::collections::HashSet;

pub(super) const MAX_PRE_TOOL_DEPTH: usize = 32;
const MAX_PRE_TOOL_KEYS: usize = 512;
const MAX_PRE_TOOL_ARRAY_ITEMS: usize = 256;
const MAX_PRE_TOOL_STRINGS: usize = 128;
const MAX_NESTED_JSON_OBJECT_ITEMS: usize = 256;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum GenericExtractionError {
    Malformed,
    Ambiguous,
    Bounds,
}

#[derive(Debug, Default)]
pub(super) struct GenericSignals {
    pub(super) command: Option<String>,
    pub(super) tool_name: Option<String>,
    pub(super) package_present: bool,
    pub(super) package_values: Vec<String>,
    pub(super) path_values: Vec<String>,
    pub(super) url_values: Vec<String>,
    pub(super) prompt_present: bool,
    pub(super) env_reference: bool,
    pub(super) benign_prompt: bool,
    pub(super) guard_bypass_intent: bool,
    pub(super) prompt_injection_intent: bool,
    pub(super) exfil_intent: bool,
    pub(super) destructive_intent: bool,
    pub(super) subprocess_intent: bool,
    pub(super) content_sensitive: bool,
    pub(super) sensitive_target: bool,
    pub(super) independent_sensitive_target: bool,
    pub(super) event_hint: Option<String>,
}

fn bounded_payload(
    value: &Value,
    depth: usize,
    keys: &mut usize,
) -> Result<(), GenericExtractionError> {
    if depth > MAX_PRE_TOOL_DEPTH {
        return Err(GenericExtractionError::Bounds);
    }
    match value {
        Value::Object(record) => {
            *keys = keys.saturating_add(record.len());
            if *keys > MAX_PRE_TOOL_KEYS {
                return Err(GenericExtractionError::Bounds);
            }
            for child in record.values() {
                bounded_payload(child, depth.saturating_add(1), keys)?;
            }
        }
        Value::Array(items) => {
            if items.len() > MAX_PRE_TOOL_ARRAY_ITEMS {
                return Err(GenericExtractionError::Bounds);
            }
            for child in items {
                bounded_payload(child, depth.saturating_add(1), keys)?;
            }
        }
        Value::String(text) => {
            if text.len() > MAX_COMMAND_BYTES || text.chars().count() > MAX_COMMAND_BYTES {
                return Err(GenericExtractionError::Bounds);
            }
        }
        Value::Null | Value::Bool(_) | Value::Number(_) => {}
    }
    Ok(())
}

fn collect_maps<'a>(value: &'a Value, output: &mut Vec<&'a Map<String, Value>>) {
    match value {
        Value::Object(record) => {
            output.push(record);
            for child in record.values() {
                collect_maps(child, output);
            }
        }
        Value::Array(items) => {
            for child in items {
                collect_maps(child, output);
            }
        }
        Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_) => {}
    }
}

fn bounded_string(value: &Value) -> Result<String, GenericExtractionError> {
    let text = value
        .as_str()
        .ok_or(GenericExtractionError::Malformed)?
        .trim();
    if text.is_empty() {
        return Err(GenericExtractionError::Malformed);
    }
    if text.len() > MAX_COMMAND_BYTES || text.chars().count() > MAX_COMMAND_BYTES {
        return Err(GenericExtractionError::Bounds);
    }
    Ok(text.to_owned())
}

fn append_strings(output: &mut Vec<String>, value: &Value) -> Result<(), GenericExtractionError> {
    if output.len() >= MAX_PRE_TOOL_STRINGS {
        return Err(GenericExtractionError::Bounds);
    }
    match value {
        Value::String(_) => output.push(bounded_string(value)?),
        Value::Array(items) => {
            if items.len() > MAX_PRE_TOOL_ARRAY_ITEMS {
                return Err(GenericExtractionError::Bounds);
            }
            for item in items {
                if output.len() >= MAX_PRE_TOOL_STRINGS {
                    return Err(GenericExtractionError::Bounds);
                }
                output.push(bounded_string(item)?);
            }
        }
        _ => return Err(GenericExtractionError::Malformed),
    }
    Ok(())
}

fn collect_key_strings(
    maps: &[&Map<String, Value>],
    keys: &[&str],
) -> Result<Vec<String>, GenericExtractionError> {
    let mut output = Vec::new();
    for record in maps {
        for key in keys {
            if let Some(value) = record.get(*key) {
                append_strings(&mut output, value)?;
            }
        }
    }
    Ok(output)
}

fn unique_string(values: Vec<String>) -> Result<Option<String>, GenericExtractionError> {
    let Some(first) = values.first() else {
        return Ok(None);
    };
    if values.iter().any(|value| value != first) {
        return Err(GenericExtractionError::Ambiguous);
    }
    Ok(Some(first.clone()))
}

fn command_from_value(value: &Value) -> Result<Vec<String>, GenericExtractionError> {
    command_from_value_at_depth(value, 0)
}

fn command_from_value_at_depth(
    value: &Value,
    depth: usize,
) -> Result<Vec<String>, GenericExtractionError> {
    if depth > MAX_PRE_TOOL_DEPTH {
        return Err(GenericExtractionError::Bounds);
    }
    match value {
        Value::String(text) => {
            let trimmed = text.trim();
            if trimmed.starts_with('[') || trimmed.starts_with('{') {
                let parsed = parse_strict_nested_json(trimmed.as_bytes())?;
                return command_from_value_at_depth(&parsed, depth.saturating_add(1));
            }
            Ok(vec![bounded_string(value)?])
        }
        Value::Array(items) => {
            if items.len() != 1 {
                return Err(GenericExtractionError::Ambiguous);
            }
            command_from_value_at_depth(&items[0], depth.saturating_add(1))
        }
        Value::Object(record) => {
            let mut output = Vec::new();
            let mut found = false;
            for key in [
                "command",
                "cmd",
                "shell_command",
                "shellCommand",
                "commands",
            ] {
                if let Some(item) = record.get(key) {
                    found = true;
                    output.extend(command_from_value_at_depth(item, depth.saturating_add(1))?);
                }
            }
            if !found {
                return Err(GenericExtractionError::Malformed);
            }
            Ok(output)
        }
        _ => Err(GenericExtractionError::Malformed),
    }
}

fn collect_commands(
    maps: &[&Map<String, Value>],
) -> Result<Option<String>, GenericExtractionError> {
    let mut values = Vec::new();
    for record in maps {
        for key in [
            "command",
            "cmd",
            "shell_command",
            "shellCommand",
            "commands",
        ] {
            if let Some(value) = record.get(key) {
                values.extend(command_from_value(value)?);
            }
        }
        if let Some(value @ Value::String(text)) = record.get("parameters") {
            let trimmed = text.trim_start();
            if trimmed.starts_with('[') || trimmed.starts_with('{') {
                values.extend(command_from_value(value)?);
            }
        }
    }
    unique_string(values)
}

fn collect_tool_names(payload: &Value) -> Result<Option<String>, GenericExtractionError> {
    let Some(root) = payload.as_object() else {
        return Err(GenericExtractionError::Malformed);
    };
    let mut values = Vec::new();
    for key in [
        "tool_name",
        "toolName",
        "toolname",
        "tool",
        "name",
        "action",
        "operation",
    ] {
        if let Some(value) = root.get(key) {
            if !value.is_object() {
                values.push(bounded_string(value)?);
            }
        }
    }
    for key in ["tool_call", "toolCall", "preToolUse", "pre_tool_use"] {
        let Some(Value::Object(record)) = root.get(key) else {
            continue;
        };
        for name_key in ["tool_name", "toolName", "toolname", "name", "tool"] {
            if let Some(value) = record.get(name_key) {
                if !value.is_object() {
                    values.push(bounded_string(value)?);
                }
            }
        }
    }
    unique_string(values)
}

fn collect_event_hint(root: &Map<String, Value>) -> Result<Option<String>, GenericExtractionError> {
    unique_string(collect_key_strings(
        &[root],
        &[
            "event",
            "eventName",
            "hook_event_name",
            "hookEventName",
            "hook_name",
            "hookName",
        ],
    )?)
}

fn sensitive_text(values: &[String]) -> bool {
    values.iter().any(|value| sensitive_command(value))
}

#[path = "generic_prompt.rs"]
mod prompt;
use prompt::{
    benign_prompt_text, destructive_prompt_intent, exfil_prompt_intent, guard_bypass_prompt,
    prompt_injection_intent, prompt_sensitive_text, subprocess_prompt_intent,
};

#[path = "generic_nested_json.rs"]
mod nested_json;
use nested_json::parse_strict_nested_json;

#[path = "generic_signals.rs"]
mod signals;
pub(super) use signals::extract_generic_signals;

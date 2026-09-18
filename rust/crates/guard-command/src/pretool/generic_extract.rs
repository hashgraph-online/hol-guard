use super::super::sensitive_command;
use crate::MAX_COMMAND_BYTES;
use serde::de::{DeserializeSeed, Deserializer, MapAccess, SeqAccess, Visitor};
use serde_json::{Map, Value};
use std::collections::HashSet;
use std::fmt;

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

#[derive(Clone, Copy)]
struct StrictNestedJsonSeed {
    depth: usize,
}

impl<'de> DeserializeSeed<'de> for StrictNestedJsonSeed {
    type Value = Value;

    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: Deserializer<'de>,
    {
        if self.depth > MAX_PRE_TOOL_DEPTH {
            return Err(serde::de::Error::custom(
                "native_pre_tool_nested_depth_exceeded",
            ));
        }
        deserializer.deserialize_any(StrictNestedJsonVisitor { depth: self.depth })
    }
}

struct StrictNestedJsonVisitor {
    depth: usize,
}

impl<'de> Visitor<'de> for StrictNestedJsonVisitor {
    type Value = Value;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("bounded JSON without duplicate object keys")
    }

    fn visit_bool<E>(self, value: bool) -> Result<Self::Value, E> {
        Ok(Value::Bool(value))
    }

    fn visit_i64<E>(self, value: i64) -> Result<Self::Value, E> {
        Ok(Value::Number(value.into()))
    }

    fn visit_u64<E>(self, value: u64) -> Result<Self::Value, E> {
        Ok(Value::Number(value.into()))
    }

    fn visit_f64<E>(self, value: f64) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        serde_json::Number::from_f64(value)
            .map(Value::Number)
            .ok_or_else(|| E::custom("native_pre_tool_nested_number_invalid"))
    }

    fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        self.visit_string(value.to_owned())
    }

    fn visit_string<E>(self, value: String) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        if value.len() > MAX_COMMAND_BYTES {
            return Err(E::custom("native_pre_tool_nested_string_too_large"));
        }
        Ok(Value::String(value))
    }

    fn visit_none<E>(self) -> Result<Self::Value, E> {
        Ok(Value::Null)
    }

    fn visit_unit<E>(self) -> Result<Self::Value, E> {
        Ok(Value::Null)
    }

    fn visit_some<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: Deserializer<'de>,
    {
        StrictNestedJsonSeed { depth: self.depth }.deserialize(deserializer)
    }

    fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        let mut output = Vec::new();
        while let Some(value) = sequence.next_element_seed(StrictNestedJsonSeed {
            depth: self.depth.saturating_add(1),
        })? {
            if output.len() >= MAX_PRE_TOOL_ARRAY_ITEMS {
                return Err(serde::de::Error::custom(
                    "native_pre_tool_nested_array_too_wide",
                ));
            }
            output.push(value);
        }
        Ok(Value::Array(output))
    }

    fn visit_map<A>(self, mut object: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut output = Map::new();
        let mut seen = HashSet::new();
        while let Some(key) = object.next_key::<String>()? {
            if key.len() > MAX_COMMAND_BYTES {
                return Err(serde::de::Error::custom(
                    "native_pre_tool_nested_key_too_large",
                ));
            }
            if !seen.insert(key.clone()) {
                return Err(serde::de::Error::custom(
                    "native_pre_tool_nested_duplicate_key",
                ));
            }
            if output.len() >= MAX_NESTED_JSON_OBJECT_ITEMS {
                return Err(serde::de::Error::custom(
                    "native_pre_tool_nested_object_too_wide",
                ));
            }
            let value = object.next_value_seed(StrictNestedJsonSeed {
                depth: self.depth.saturating_add(1),
            })?;
            output.insert(key, value);
        }
        Ok(Value::Object(output))
    }
}

fn parse_strict_nested_json(bytes: &[u8]) -> Result<Value, GenericExtractionError> {
    let mut deserializer = serde_json::Deserializer::from_slice(bytes);
    let value = StrictNestedJsonSeed { depth: 0 }
        .deserialize(&mut deserializer)
        .map_err(|error| {
            let message = error.to_string();
            if message.contains("duplicate_key") {
                GenericExtractionError::Ambiguous
            } else if message.contains("depth_exceeded")
                || message.contains("too_wide")
                || message.contains("too_large")
            {
                GenericExtractionError::Bounds
            } else {
                GenericExtractionError::Malformed
            }
        })?;
    deserializer
        .end()
        .map_err(|_| GenericExtractionError::Malformed)?;
    Ok(value)
}

#[derive(Debug, Default)]
pub(super) struct GenericSignals {
    pub(super) command: Option<String>,
    pub(super) tool_name: Option<String>,
    pub(super) package_present: bool,
    pub(super) path_values: Vec<String>,
    pub(super) url_values: Vec<String>,
    pub(super) prompt_present: bool,
    pub(super) sensitive_target: bool,
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

pub(super) fn extract_generic_signals(
    payload: &Value,
) -> Result<GenericSignals, GenericExtractionError> {
    let mut keys = 0usize;
    bounded_payload(payload, 0, &mut keys)?;
    let Some(root) = payload.as_object() else {
        return Err(GenericExtractionError::Malformed);
    };
    let mut maps = Vec::new();
    collect_maps(payload, &mut maps);
    let command = collect_commands(&maps)?;
    let tool_name = collect_tool_names(payload)?;
    let path_values = collect_key_strings(
        &maps,
        &[
            "path",
            "paths",
            "file",
            "files",
            "file_path",
            "filePath",
            "file_paths",
            "target_file",
            "targetFile",
            "target_directory",
            "targetDirectory",
        ],
    )?;
    let package_values = collect_key_strings(
        &maps,
        &[
            "package",
            "package_name",
            "packageName",
            "package_manager",
            "packageManager",
        ],
    )?;
    let url_values = collect_key_strings(&maps, &["url", "urls", "uri", "href", "endpoint"])?;
    let prompt_values = collect_key_strings(
        &maps,
        &["prompt", "user_prompt", "userPrompt", "message", "query"],
    )?;
    let text_values = collect_key_strings(&maps, &["text"])?;
    let event_hint = collect_event_hint(root)?;
    let sensitive_target = sensitive_text(&path_values)
        || sensitive_text(&url_values)
        || sensitive_text(&prompt_values)
        || sensitive_text(&text_values)
        || command.as_deref().is_some_and(sensitive_command);
    Ok(GenericSignals {
        command,
        tool_name,
        package_present: !package_values.is_empty(),
        path_values,
        url_values,
        prompt_present: !prompt_values.is_empty(),
        sensitive_target,
        event_hint,
    })
}

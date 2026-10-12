//! Cursor hook payload preparation.

use crate::hook_adapter_prepare::*;
use crate::hook_adapter_pytext::py_strip;
use crate::hook_adapter_value::{parse_python_json, OMap, OValue, PyJsonError};

const CURSOR_EVENT_KEYS: &[&str] = &[
    "hook_event_name",
    "hookEventName",
    "hook_name",
    "hookName",
    "event",
    "eventName",
];

/// `_tool_input_dict`.
fn tool_input_dict(value: Option<&OValue>) -> Result<OMap, AdapterError> {
    match value {
        Some(OValue::Map(map)) => Ok(map.clone()),
        Some(OValue::List(items)) => Ok(arguments_map(items)),
        Some(OValue::Str(text)) if !py_strip(text).is_empty() => match parse_python_json(text) {
            Ok(OValue::Map(map)) => Ok(map),
            Ok(OValue::List(items)) => Ok(arguments_map(&items)),
            Ok(_) => Ok(OMap::new()),
            Err(PyJsonError::Decode) => {
                let mut raw = OMap::new();
                raw.insert("raw", OValue::str(py_strip(text)));
                Ok(raw)
            }
            Err(PyJsonError::Unsupported) => Err(PyJsonError::Unsupported.into()),
        },
        _ => Ok(OMap::new()),
    }
}

fn arguments_map(items: &[OValue]) -> OMap {
    let mut map = OMap::new();
    map.insert("arguments", OValue::List(items.to_vec()));
    map
}

fn setdefault_stripped(map: &mut OMap, key: &str, value: Option<&OValue>) {
    if let Some(text) = value.and_then(OValue::non_blank_str) {
        map.set_default(key, OValue::str(py_strip(text)));
    }
}

fn cursor_shell_payload(normalized: &OMap, event: &str) -> Result<OMap, AdapterError> {
    let mut payload = normalized.clone();
    payload.insert("hook_event_name", OValue::str(event));
    payload.set_default("tool_name", OValue::str("Shell"));
    let mut tool_input = tool_input_dict(payload.get("tool_input"))?;
    setdefault_stripped(&mut tool_input, "command", payload.get("command"));
    setdefault_stripped(&mut tool_input, "working_directory", payload.get("cwd"));
    payload.insert("tool_input", OValue::Map(tool_input));
    Ok(payload)
}

fn cursor_mcp_payload(normalized: &OMap, event: &str) -> Result<OMap, AdapterError> {
    let mut payload = normalized.clone();
    payload.insert("hook_event_name", OValue::str(event));
    let tool_input = tool_input_dict(payload.get("tool_input"))?;
    payload.insert("tool_input", OValue::Map(tool_input));
    match payload.get("tool_name").and_then(OValue::non_blank_str) {
        Some(name) => {
            let stripped = py_strip(name).to_owned();
            payload.insert("tool_name", OValue::Str(stripped));
        }
        None => payload.set_default("tool_name", OValue::str("MCP")),
    }
    Ok(payload)
}

fn infer_cursor_event(payload: &OMap) -> OMap {
    let mut normalized = payload.clone();
    if !raw_event_name(&normalized, CURSOR_EVENT_KEYS).is_empty() {
        return normalized;
    }
    if normalized
        .get("file_path")
        .and_then(OValue::non_blank_str)
        .is_some()
    {
        normalized.insert("hook_event_name", OValue::str("beforeReadFile"));
    } else if normalized
        .get("command")
        .and_then(OValue::non_blank_str)
        .is_some()
    {
        normalized.insert("hook_event_name", OValue::str("beforeShellExecution"));
    } else if normalized.get_non_null("tool_name").is_some()
        || normalized.get_non_null("tool_input").is_some()
    {
        normalized.insert("hook_event_name", OValue::str("preToolUse"));
    }
    normalized
}

fn cursor_file_payload(
    normalized: &mut OMap,
    tool: &str,
    source_event: Option<&str>,
) -> Result<(), AdapterError> {
    normalized.insert("hook_event_name", OValue::str("PreToolUse"));
    normalized.insert("tool_name", OValue::str(tool));
    let mut tool_input = tool_input_dict(normalized.get("tool_input"))?;
    if let Some(path) = normalized.get("file_path").and_then(OValue::non_blank_str) {
        tool_input.set_default("file_path", OValue::str(py_strip(path)));
        tool_input.set_default("path", OValue::str(py_strip(path)));
    }
    normalized.insert("tool_input", OValue::Map(tool_input));
    if let Some(source) = source_event {
        normalized.insert("cursor_source_hook_event", OValue::str(source));
    }
    Ok(())
}

pub(crate) fn prepare_cursor(payload: &OMap) -> Result<OMap, AdapterError> {
    let mut normalized = infer_cursor_event(payload);
    let raw_event = raw_event_name(&normalized, CURSOR_EVENT_KEYS);
    match raw_event.as_str() {
        "aftershellexecution" => cursor_shell_payload(&normalized, "afterShellExecution"),
        "aftermcpexecution" => cursor_mcp_payload(&normalized, "afterMCPExecution"),
        "beforeshellexecution" => {
            let mut prepared = cursor_shell_payload(&normalized, "PreToolUse")?;
            prepared.insert(
                "cursor_source_hook_event",
                OValue::str("beforeShellExecution"),
            );
            Ok(prepared)
        }
        "beforemcpexecution" => {
            let mut prepared = cursor_mcp_payload(&normalized, "PreToolUse")?;
            let mut tool_input = tool_input_dict(prepared.get("tool_input"))?;
            for key in ["url", "command"] {
                setdefault_stripped(&mut tool_input, key, normalized.get(key));
            }
            prepared.insert("tool_input", OValue::Map(tool_input));
            prepared.insert(
                "cursor_source_hook_event",
                OValue::str("beforeMCPExecution"),
            );
            Ok(prepared)
        }
        "beforereadfile" => {
            cursor_file_payload(&mut normalized, "Read", None)?;
            Ok(normalized)
        }
        "beforewritefile" => {
            cursor_file_payload(&mut normalized, "Write", Some("beforeWriteFile"))?;
            Ok(normalized)
        }
        "pretooluse" => {
            normalized.insert("hook_event_name", OValue::str("PreToolUse"));
            Ok(normalized)
        }
        _ => Ok(normalized),
    }
}

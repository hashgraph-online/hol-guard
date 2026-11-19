//! Hook payload facts normalized by the resident.

use serde::Deserialize;
use serde_json::{json, Map, Value};

use crate::claude_hook_bridge_render::py_strip;
use crate::resident_protocol::encode_response;

pub(crate) const HOOK_PAYLOAD_FACTS_FEATURE: &str = "hook-payload-facts-v1";
const REQUEST_SCHEMA: &str = "guard-hook-payload-facts-request.v1";
const RESULT_SCHEMA: &str = "guard-hook-payload-facts-result.v1";

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct HookPayloadFactsRequestV1 {
    pub(crate) schema: String,
    pub(crate) request_id: String,
    pub(crate) payload: Value,
}

pub(crate) fn runtime_event(payload: &Map<String, Value>) -> String {
    for key in [
        "event",
        "eventName",
        "hook_event_name",
        "hookEventName",
        "hook_name",
        "hookName",
    ] {
        let Some(raw) = payload.get(key).and_then(Value::as_str).map(py_strip) else {
            continue;
        };
        if raw.is_empty() {
            continue;
        }
        let compact: String = raw
            .to_lowercase()
            .chars()
            .filter(|character| *character != '_' && *character != '-')
            .collect();
        return match compact.as_str() {
            "pretool"
            | "pretooluse"
            | "pretoolcall"
            | "beforeshellexecution"
            | "beforereadfile"
            | "beforewritefile"
            | "beforemcpexecution" => "PreToolUse",
            "posttool"
            | "posttooluse"
            | "posttoolcall"
            | "aftershellexecution"
            | "afterreadfile"
            | "afterwritefile"
            | "aftermcpexecution" => "PostToolUse",
            "permissionrequest" | "permissionrequestv2" => "PermissionRequest",
            "prompt" | "userpromptsubmit" | "userpromptsubmitted" => "UserPromptSubmit",
            _ => raw,
        }
        .to_owned();
    }
    "PreToolUse".to_owned()
}

fn text(value: Option<&Value>) -> Option<String> {
    value
        .and_then(Value::as_str)
        .map(py_strip)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
}

fn raw_text(value: Option<&Value>) -> Option<String> {
    value
        .and_then(Value::as_str)
        .filter(|value| !py_strip(value).is_empty())
        .map(ToOwned::to_owned)
}

pub(crate) fn tool_input(payload: &Map<String, Value>) -> Option<Map<String, Value>> {
    ["tool_input", "toolInput"]
        .iter()
        .find_map(|key| payload.get(*key).and_then(Value::as_object).cloned())
}

pub(crate) fn command(
    payload: &Map<String, Value>,
    input: Option<&Map<String, Value>>,
) -> Option<String> {
    let candidates = input
        .into_iter()
        .chain(payload.get("arguments").and_then(Value::as_object))
        .chain(std::iter::once(payload));
    for candidate in candidates {
        for key in ["command", "cmd", "shell_command", "shellCommand"] {
            if let Some(value) = raw_text(candidate.get(key)) {
                return Some(value);
            }
        }
    }
    None
}

fn tool_name(payload: &Map<String, Value>) -> String {
    ["tool_name", "toolName", "tool"]
        .iter()
        .find_map(|key| text(payload.get(*key)))
        .unwrap_or_else(|| "tool".to_owned())
}

fn launch_target(
    input: Option<&Map<String, Value>>,
    command: Option<&str>,
    tool_name: &str,
) -> String {
    if let Some(command) = command {
        return command.to_owned();
    }
    if let Some(input) = input {
        for key in ["url", "path", "file_path", "target"] {
            if let Some(value) = text(input.get(key)) {
                return value;
            }
        }
    }
    format!("tool:{tool_name}")
}

pub(crate) fn evaluate(request: &HookPayloadFactsRequestV1) -> Result<Vec<u8>, String> {
    if request.schema != REQUEST_SCHEMA
        || request.request_id.is_empty()
        || request.request_id.len() > 128
    {
        return Err("hook_payload_facts_payload_invalid".to_owned());
    }
    let payload = request
        .payload
        .as_object()
        .ok_or_else(|| "hook_payload_facts_payload_invalid".to_owned())?;
    let input = tool_input(payload);
    let command = command(payload, input.as_ref());
    let tool_name = tool_name(payload);
    encode_response(&json!({
        "schema": RESULT_SCHEMA,
        "result": {
            "request_id": request.request_id,
            "event_name": runtime_event(payload),
            "tool_input": input.as_ref().map(|value| Value::Object(value.clone())),
            "command": command,
            "tool_name": tool_name.clone(),
            "launch_target": launch_target(input.as_ref(), command.as_deref(), &tool_name),
        },
    }))
}

#[cfg(test)]
#[path = "hook_payload_facts_op_tests.rs"]
mod tests;

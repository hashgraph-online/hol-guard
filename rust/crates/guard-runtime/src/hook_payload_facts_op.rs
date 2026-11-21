//! Hook payload facts normalized by the native runtime.

use serde::Deserialize;
use serde_json::{json, Map, Value};

use crate::claude_hook_bridge_render::py_strip;
use crate::resident_protocol::encode_response;

pub(crate) const HOOK_PAYLOAD_FACTS_FEATURE: &str = "hook-payload-facts-v1";
pub(crate) const CLI_ADMISSION_FEATURE: &str = "native-hook-cli-admission-v1";
pub(crate) const CLI_ADMISSION_COMMAND: &str = "hook-cli-admission";
const REQUEST_SCHEMA: &str = "guard-hook-payload-facts-request.v1";
const RESULT_SCHEMA: &str = "guard-hook-payload-facts-result.v1";
const COMMAND_ONLY_KEYS: [&str; 14] = [
    "command",
    "cmd",
    "shell_command",
    "shellCommand",
    "description",
    "timeout",
    "timeout_ms",
    "timeoutMs",
    "run_in_background",
    "runInBackground",
    "workdir",
    "cwd",
    "working_directory",
    "workingDirectory",
];

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct HookPayloadFactsRequestV1 {
    pub(crate) schema: String,
    pub(crate) request_id: String,
    pub(crate) payload: Value,
}

const HINT_SECONDS: &str = "guard_remaining_seconds";
const HINT_MILLISECONDS: &str = "guard_remaining_ms";
const MIN_HOOK_BUDGET_SECONDS: f64 = 0.1;
const HOOK_TRANSPORT_RESERVE_SECONDS: f64 = 0.25;
const MAX_CLI_HOOK_BUDGET_SECONDS: f64 = 10.0;

pub(crate) fn remaining_hint(payload: &Map<String, Value>, allow_negative: bool) -> Option<f64> {
    [(HINT_SECONDS, 1.0), (HINT_MILLISECONDS, 1000.0)]
        .into_iter()
        .find_map(|(key, scale)| {
            payload
                .get(key)
                .and_then(Value::as_f64)
                .filter(|value| value.is_finite() && (allow_negative || *value >= 0.0))
                .map(|value| value / scale)
        })
}

pub(crate) fn take_remaining_hint(payload: &mut Map<String, Value>) -> (Option<f64>, bool) {
    let hint = remaining_hint(payload, true);
    let has_seconds = payload.remove(HINT_SECONDS).is_some();
    let has_milliseconds = payload.remove(HINT_MILLISECONDS).is_some();
    (hint, !has_seconds && !has_milliseconds)
}

pub(crate) fn hook_budget_seconds(value: f64, maximum: f64) -> f64 {
    (value.clamp(MIN_HOOK_BUDGET_SECONDS, maximum) - HOOK_TRANSPORT_RESERVE_SECONDS)
        .max(MIN_HOOK_BUDGET_SECONDS)
}

pub(crate) fn cli_admission(input: &[u8]) -> Result<Value, String> {
    const MAX_INPUT_BYTES: usize = 64 * 1024;
    if input.len() > MAX_INPUT_BYTES {
        return Err("hook_cli_admission_request_too_large".to_owned());
    }
    let payload: Map<String, Value> = serde_json::from_slice(input)
        .map_err(|_| "hook_cli_admission_request_invalid".to_owned())?;
    let maximum = MAX_CLI_HOOK_BUDGET_SECONDS;
    let budget = hook_budget_seconds(remaining_hint(&payload, false).unwrap_or(maximum), maximum);
    Ok(json!({"event_name": runtime_event(&payload), "budget_seconds": budget}))
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
    let command_only = input.as_ref().is_some_and(|value| {
        value
            .keys()
            .all(|key| COMMAND_ONLY_KEYS.contains(&key.as_str()))
    });
    let response = json!({
        "schema": RESULT_SCHEMA,
        "result": {
            "request_id": request.request_id,
            "event_name": runtime_event(payload),
            "command_only": command_only,
            "command": command,
            "tool_name": tool_name.clone(),
            "launch_target": launch_target(input.as_ref(), command.as_deref(), &tool_name),
        },
    });
    let encoded = serde_json::to_vec(&response)
        .map_err(|_| "hook_payload_facts_response_invalid".to_owned())?;
    if encoded.len() > guard_contracts::MAX_NATIVE_RESPONSE_BYTES {
        return Err("hook_payload_facts_response_too_large".to_owned());
    }
    encode_response(&response)
}

#[cfg(test)]
#[path = "hook_payload_facts_op_tests.rs"]
mod tests;

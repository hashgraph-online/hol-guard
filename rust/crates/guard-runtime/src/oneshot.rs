#![forbid(unsafe_code)]

use guard_command::pretool::{evaluate_pre_tool, PreToolDecisionV1};
use guard_command::{parse_command, CommandModelRequestV1};
use guard_contracts::{NativeHookRequestV1, NATIVE_PROTOCOL_VERSION};
use guard_hook_core::review_post_tool;
use serde_json::Value;

fn mapping_string<'a>(value: &'a Value, key: &str) -> Option<&'a str> {
    value
        .get(key)
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|item| !item.is_empty())
}

fn extract_pre_tool_command(value: &Value) -> Result<String, String> {
    if let Some(event_name) = mapping_string(value, "event_name") {
        if event_name != "PreToolUse" {
            return Err("native_pre_tool_unsupported_event".to_owned());
        }
    }
    if let Some(version) = value.get("protocol_version") {
        let protocol_version = version
            .as_u64()
            .ok_or_else(|| "native_pre_tool_invalid_protocol".to_owned())?;
        if protocol_version != u64::from(NATIVE_PROTOCOL_VERSION) {
            return Err("native_pre_tool_invalid_protocol".to_owned());
        }
    }
    let command_holders = [
        value,
        value.get("payload").unwrap_or(&Value::Null),
        value
            .get("payload")
            .and_then(|payload| payload.get("tool_input"))
            .unwrap_or(&Value::Null),
        value
            .get("payload")
            .and_then(|payload| payload.get("arguments"))
            .unwrap_or(&Value::Null),
        value.get("tool_input").unwrap_or(&Value::Null),
    ];
    for holder in command_holders {
        for key in ["command", "cmd", "shell_command", "shellCommand"] {
            if let Some(command) = mapping_string(holder, key) {
                return Ok(command.to_owned());
            }
        }
    }
    Err("native_pre_tool_command_missing".to_owned())
}

pub(crate) fn pre_tool_response(request_id: Option<&str>, decision: PreToolDecisionV1) -> Value {
    serde_json::json!({
        "authority": "rust",
        "request_id": request_id.unwrap_or(""),
        "decision": &decision.decision,
        "policy_action": &decision.minimum_action,
        "minimum_action": &decision.minimum_action,
        "reason_code": &decision.reason_code,
        "reason": &decision.reason,
        "explicitly_benign": decision.explicitly_benign,
        "command_model": &decision.command_model,
    })
}

pub(crate) fn evaluate_hook_bytes(bytes: &[u8]) -> Result<Vec<u8>, String> {
    let value = crate::strict_json_value(bytes)?;
    let request: NativeHookRequestV1 =
        serde_json::from_value(value).map_err(|_| "native_request_invalid_json".to_owned())?;
    crate::encode_response(&review_post_tool(&request))
}

pub(crate) fn evaluate_command_model_request(
    request: &CommandModelRequestV1,
) -> Result<Vec<u8>, String> {
    crate::encode_response(&parse_command(request)?)
}

pub(crate) fn evaluate_command_model_bytes(bytes: &[u8]) -> Result<Vec<u8>, String> {
    let value = crate::strict_json_value(bytes)?;
    let request: CommandModelRequestV1 = serde_json::from_value(value)
        .map_err(|_| "native_command_model_invalid_json".to_owned())?;
    evaluate_command_model_request(&request)
}

pub(crate) fn evaluate_pre_tool_bytes(bytes: &[u8]) -> Result<Vec<u8>, String> {
    let value = crate::strict_json_value(bytes)?;
    let command = extract_pre_tool_command(&value)?;
    let dialect = mapping_string(&value, "dialect").unwrap_or("posix");
    let transport = mapping_string(&value, "transport").unwrap_or("shell_string");
    let extraction_provenance =
        mapping_string(&value, "extraction_provenance").unwrap_or("guard-shell");
    let request = CommandModelRequestV1 {
        command,
        dialect: dialect.to_owned(),
        transport: transport.to_owned(),
        extraction_provenance: extraction_provenance.to_owned(),
    };
    let decision = evaluate_pre_tool(&request)?;
    let request_id = mapping_string(&value, "request_id");
    crate::encode_response(&pre_tool_response(request_id, decision))
}

pub(crate) fn evaluate_pre_tool_request(
    request: &CommandModelRequestV1,
) -> Result<Vec<u8>, String> {
    crate::encode_response(&pre_tool_response(None, evaluate_pre_tool(request)?))
}

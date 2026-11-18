//! Hook payload facts normalized by the resident.

use serde::Deserialize;
use serde_json::{json, Map, Value};

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
        let Some(raw) = payload.get(key).and_then(Value::as_str).map(str::trim) else {
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
    encode_response(&json!({
        "schema": RESULT_SCHEMA,
        "result": {
            "request_id": request.request_id,
            "event_name": runtime_event(payload),
        },
    }))
}

#[cfg(test)]
#[path = "hook_payload_facts_op_tests.rs"]
mod tests;

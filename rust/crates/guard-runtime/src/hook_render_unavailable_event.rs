//! Render an unavailable hook with or without a running resident.

use serde::Deserialize;
use serde_json::{json, Map, Value};

use crate::claude_hook_bridge_render::py_strip;
use crate::policy_store::PolicySnapshotStore;

pub(crate) const CLI_FEATURE: &str = "native-hook-unavailable-event-v1";
pub(crate) const CLI_COMMAND: &str = "hook-unavailable-event";
const MAX_CLI_REQUEST_BYTES: usize = 64 * 1024;
const INVALID: &str = "native_hook_render_invalid";

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CliRequest {
    harness: String,
    payload: Map<String, Value>,
}

pub(crate) fn cli(input: &[u8]) -> Result<Value, String> {
    if input.len() > MAX_CLI_REQUEST_BYTES {
        return Err("hook_unavailable_event_request_too_large".to_owned());
    }
    let request: CliRequest =
        serde_json::from_slice(input).map_err(|_| "hook_unavailable_event_request_invalid")?;
    render(&request.harness, &request.payload, &Map::new(), None)
        .map(Value::Object)
        .map_err(str::to_owned)
}

pub(super) fn render(
    harness: &str,
    payload: &Map<String, Value>,
    params: &Map<String, Value>,
    store: Option<&PolicySnapshotStore>,
) -> Result<Map<String, Value>, &'static str> {
    let availability = crate::hook_payload_facts_op::availability_response(payload);
    let event = availability["event_name"].as_str().ok_or(INVALID)?;
    let permission = availability["permission_request"] == Value::Bool(true);
    let response = response(harness, event, permission, params)?;
    let activity_recorded = params.get("record_post_tool_activity") == Some(&Value::Bool(true))
        && matches!(event, "PostToolUse" | "PostToolUseFailure")
        && store
            .and_then(|store| {
                let home =
                    crate::resident_state::private_root_for_state_base(store.state_base()).ok()?;
                crate::hook_evidence_writer_op::record_direct(&home, |writer| {
                    crate::edge_receipt::queue_post_tool_activity(writer, harness, event, payload)
                })
            })
            .unwrap_or(false);
    Ok(Map::from_iter([
        ("event_name".to_owned(), Value::String(event.to_owned())),
        ("response".to_owned(), response),
        (
            "activity_recorded".to_owned(),
            Value::Bool(activity_recorded),
        ),
    ]))
}

fn response(
    harness: &str,
    event: &str,
    permission: bool,
    params: &Map<String, Value>,
) -> Result<Value, &'static str> {
    let normalized_harness = py_strip(harness).to_lowercase().replace('_', "-");
    if permission {
        match normalized_harness.as_str() {
            "claude-code" => {
                return Ok(json!({
                    "guard_permission_passthrough": true,
                    "hookSpecificOutput": {"hookEventName": "PermissionRequest"},
                }));
            }
            "codex" | "copilot" | "devin" | "zcode" | "muse" => {
                return Ok(json!({"hookSpecificOutput": {"hookEventName": "PermissionRequest"}}));
            }
            _ => {}
        }
    }
    let reason = params
        .get("reason")
        .and_then(Value::as_str)
        .unwrap_or("HOL Guard could not identify this hook event safely.");
    let reason_code = params
        .get("reason_code")
        .and_then(Value::as_str)
        .unwrap_or(match event {
            "PreToolUse" => "native_pre_tool_unavailable",
            "PostToolUse" => "native_post_tool_unavailable",
            _ => "native_hook_event_unavailable",
        });
    let prompt_reason = params.get("prompt_reason").and_then(Value::as_str);
    guard_command::hook_responses::fail_closed::response(
        harness,
        event,
        reason,
        reason_code,
        prompt_reason,
    )
    .map(Value::Object)
    .map_err(|_| INVALID)
}

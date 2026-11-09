//! `memory_decision_event` runner-authority kind: builds the
//! `guard.memory-decision.v1` event for one resolved approval. Ported from
//! `memory_decision_event.build_memory_decision_event` with its redaction,
//! display and fingerprint rules.
//!
//! Python ships the request's string fields, `action_envelope_json` (a mapping
//! or its JSON text) and `risk_signals` already passed through `str()`, then
//! wraps the returned fields in its dataclass. A request without an id or an
//! action that is not a decision answers `{"event": null}`.

use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};

use crate::claude_guard_question::python_lower;
use crate::cloud_request_text::{optional_string, py_strip, py_truthy};
use crate::memory_pattern::{verdict, MemoryRequest};
use crate::runner_authority_op::{KindResult, ERR_INVALID};

const FILE_ACTION_TYPES: [&str; 4] = [
    "file_read",
    "file_read_request",
    "file_write",
    "file_write_request",
];
const GENERIC_FRAGMENTS: [&str; 6] = ["bash", "rg", "cat", "tool", "mcp", "skill"];
const APPROVAL_WRAPPER: &str = "hol-guard approvals approve ";

pub(crate) fn dispatch(args: &Value) -> KindResult {
    let (Some(Value::Object(request)), Some(action), Some(resolved_at)) = (
        args.get("request"),
        args.get("action").and_then(Value::as_str),
        args.get("resolved_at").and_then(Value::as_str),
    ) else {
        return Err(ERR_INVALID);
    };
    let redaction_enabled = match args.get("redaction_enabled") {
        None | Some(Value::Null) => false,
        Some(Value::Bool(enabled)) => *enabled,
        Some(_) => return Err(ERR_INVALID),
    };
    Ok(json!({ "event": event(request, action, resolved_at, redaction_enabled) }))
}

fn event(
    request: &Map<String, Value>,
    action: &str,
    resolved_at: &str,
    redaction_enabled: bool,
) -> Value {
    let text = |key: &str| optional_string(request.get(key));
    let Some(request_id) = text("request_id") else {
        return Value::Null;
    };
    let Some(decision_action) = decision_action(action) else {
        return Value::Null;
    };
    let raw_command = text("raw_command_text");
    let artifact_id = text("artifact_id");
    let artifact_name = text("artifact_name");
    let artifact_type = text("artifact_type");
    let harness = text("harness");
    let redaction_state = match (raw_command, redaction_enabled) {
        (None, _) => "withheld",
        (Some(_), true) => "enabled",
        (Some(_), false) => "disabled",
    };
    let command_display = match raw_command {
        Some(raw) => raw.to_owned(),
        None => action_envelope(request.get("action_envelope_json"))
            .and_then(|envelope| envelope_display(&envelope))
            .or_else(|| {
                [
                    text("launch_target"),
                    artifact_name,
                    artifact_id,
                    text("review_command"),
                ]
                .into_iter()
                .flatten()
                .find(|value| !value.starts_with(APPROVAL_WRAPPER) && !is_generic_fragment(value))
                .map(str::to_owned)
            })
            // With no raw command the state is always `withheld`.
            .unwrap_or_else(|| "Command withheld".to_owned()),
    };
    // A withheld command never falls back to `review_command`: it usually
    // holds the approval wrapper and would make an over-broad fingerprint.
    let pattern = verdict(&MemoryRequest {
        command: raw_command,
        artifact_type,
        artifact_id,
        artifact_name,
        harness,
    })
    .pattern;
    let project_id = ["project_id", "projectId", "workspace_path", "workspacePath"]
        .into_iter()
        .find_map(text);
    let risk_signals: Vec<&str> = match request.get("risk_signals") {
        Some(Value::Array(items)) => items
            .iter()
            .filter_map(Value::as_str)
            .map(py_strip)
            .filter(|item| !item.is_empty())
            .collect(),
        _ => Vec::new(),
    };
    json!({
        "event_id": event_id(request_id, decision_action, resolved_at),
        "harness_id": harness,
        "project_id": project_id,
        "request_id": request_id,
        "queue_group_id": text("queue_group_id"),
        "action_identity": text("action_identity"),
        "decision_action": decision_action,
        "decision_reason": text("resolution_reason").or_else(|| text("reason")),
        "command_display": command_display,
        "command_raw": if redaction_state == "disabled" { raw_command } else { None },
        "redaction_state": redaction_state,
        "artifact_type": artifact_type,
        "artifact_id": artifact_id,
        "artifact_name": artifact_name,
        "risk_summary": text("risk_summary").or_else(|| text("risk_headline")),
        "risk_signals": risk_signals,
        "memory_pattern": pattern,
    })
}

fn decision_action(action: &str) -> Option<&'static str> {
    match python_lower(py_strip(action)).as_str() {
        "approve" | "approved" | "allow" | "allowed" => Some("approved"),
        "block" | "blocked" | "deny" | "denied" | "reject" | "rejected" => Some("blocked"),
        "dismiss" | "dismissed" | "keep_asking" | "keep-asking" => Some("dismissed_keep_asking"),
        _ => None,
    }
}

/// `_mapping_or_none`: a mapping, or non-blank JSON text that parses to one.
fn action_envelope(value: Option<&Value>) -> Option<Map<String, Value>> {
    match value? {
        Value::Object(envelope) => Some(envelope.clone()),
        Value::String(text) if !py_strip(text).is_empty() => {
            match serde_json::from_str::<Value>(text).ok()? {
                Value::Object(envelope) => Some(envelope),
                _ => None,
            }
        }
        _ => None,
    }
}

/// `_display_from_action_envelope`. Each lookup mirrors Python's
/// `envelope.get(a) or envelope.get(b)`: the first truthy value wins even when
/// it is not a string.
fn envelope_display(envelope: &Map<String, Value>) -> Option<String> {
    let first = |keys: &[&str]| {
        keys.iter()
            .filter_map(|key| envelope.get(*key))
            .find(|value| py_truthy(value))
    };
    let text = |keys: &[&str]| optional_string(first(keys)).map(str::to_owned);
    let action_type = text(&["action_type", "actionType"]);
    if let Some(action_type) = action_type
        .as_deref()
        .filter(|kind| FILE_ACTION_TYPES.contains(kind))
    {
        let path = first_string(first(&["target_paths", "targetPaths"]))
            .or_else(|| text(&["path", "file_path", "filePath"]));
        if let Some(path) = path {
            let verb = if action_type.contains("read") {
                "Read"
            } else {
                "Write"
            };
            return Some(format!("{verb} {path}"));
        }
    }
    if action_type.as_deref() == Some("mcp_tool") {
        let server = text(&["mcp_server", "mcpServer"]);
        let tool = text(&["mcp_tool", "mcpTool", "tool_name"]);
        if let (Some(server), Some(tool)) = (&server, &tool) {
            return Some(format!("mcp {server}.{tool}"));
        }
        if let Some(tool) = tool.filter(|tool| !is_generic_fragment(tool)) {
            return Some(format!("mcp {tool}"));
        }
    }
    let manager = text(&["package_manager", "packageManager"]);
    let package = text(&["package_name", "packageName"]);
    if let (Some(manager), Some(package)) = (manager, package) {
        return Some(format!("{manager} install {package}"));
    }
    let url = text(&["url", "uri", "endpoint", "host"]);
    let method = text(&["method"]);
    match (url, method) {
        (Some(url), Some(method)) => return Some(format!("{} {url}", method.to_uppercase())),
        (Some(url), None) => return Some(url),
        _ => {}
    }
    text(&["tool_name", "toolName"]).filter(|tool| !is_generic_fragment(tool))
}

fn first_string(value: Option<&Value>) -> Option<String> {
    match value? {
        Value::String(_) => optional_string(value).map(str::to_owned),
        Value::Array(items) => items
            .iter()
            .find_map(|item| optional_string(Some(item)))
            .map(str::to_owned),
        _ => None,
    }
}

fn is_generic_fragment(value: &str) -> bool {
    GENERIC_FRAGMENTS.contains(&python_lower(py_strip(value)).as_str())
}

fn event_id(request_id: &str, action: &str, occurred_at: &str) -> String {
    let digest = Sha256::digest(format!(
        "memory_decision:{request_id}:{action}:{occurred_at}"
    ));
    format!("guard-memory-decision-{}", &hex::encode(digest)[..32])
}

#[cfg(test)]
#[path = "memory_decision_event_tests.rs"]
mod tests;

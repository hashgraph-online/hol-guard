//! Lifecycle hooks the resident answers as the daemon does.
//!
//! The edge reviews tool, prompt and permission hooks only. For any other
//! event, such as Claude Code's `Stop`, Kimi's `SessionStart` or Cline's
//! `TaskStart`, the daemon asks its resident, receives the edge's refusal,
//! and returns `fail_closed_response`: a constant that carries no verdict
//! and depends only on the harness and the event name. This module returns
//! that same constant without the daemon round trip. It never answers a
//! hook the daemon handles itself or answers a lifecycle hook with a deny.
//!
//! Claude Code's `PermissionRequest` is the exception the daemon answers
//! from the session's permission notice. Without a notice row its answer is
//! also a constant, which this module returns. With the daemon's integrity
//! key bound, the resident verifies the notice and marks it seen as the
//! daemon does, then renders the daemon's answer; without the key, or when
//! a row is signed under another key, the session keeps the daemon path.
//!
//! Codex's, Copilot's, Devin's and ZCode's `PermissionRequest` get the
//! daemon's constant passthrough: no decision, so the harness shows its own
//! approval prompt. Each asks it only for a call whose `PreToolUse` hook
//! already reached Guard.
//!
//! Claude Code's `permission_prompt` notification is answered the same way:
//! the notice, when there is one, is verified and marked seen, and the event
//! the daemon records for every such prompt is written in that transaction.
//! Every other Claude notification gets the constant.

use std::path::Path;

use serde_json::{json, Map, Value};

use super::claude_permission_text::{
    notification_tool_name, permission_prompt_event, permission_prompt_notification_response,
    permission_request_response, PERMISSION_PROMPT_EVENT,
};
use super::workspace::python_strip;
use super::{
    HookDirectDefer, CLAUDE_CODE, CURSOR, EVENT_NAME_FIELDS, GROK, PAYLOAD_REFERENCE_FIELDS,
    TRANSITION_PROBE_FIELD,
};
use crate::hook_authority_state_op::{
    claude_permission_notice_direct, claude_permission_prompt_direct,
};
use crate::policy_bundle_time::micros_to_utc_isoformat;
use crate::policy_store::PolicySnapshotStore;

/// The daemon's `reason_code` when the edge does not review an event.
const UNAVAILABLE_REASON_CODE: &str = "native_hook_event_unavailable";
/// `_DECISION_HARNESSES` among the harnesses the resident answers.
const DECISION_HARNESSES: [&str; 4] = ["hermes", "openclaw", "pi", "omp"];
/// Events `fail_closed_response` answers with a deny, or the daemon handles
/// itself.
const DAEMON_EVENTS: [&str; 3] = [
    "permissionrequest",
    "permissionrequestv2",
    "copilotpermissionrequest",
];
/// `runtime_hook_event_name` keeps an unmapped name as sent, so only this
/// exact spelling reaches the daemon's permission prompt handler.
const NOTIFICATION: &str = "Notification";
const PERMISSION_PROMPT: &str = "permission_prompt";
/// Harnesses whose `PermissionRequest` the daemon passes through.
const PASSTHROUGH_PERMISSION_HARNESSES: [&str; 4] = ["codex", "copilot", "devin", "zcode"];
/// The events `runtime_hook_event_name` names `PermissionRequest`.
const CLAUDE_PERMISSION_EVENTS: [&str; 2] = ["permissionrequest", "permissionrequestv2"];
/// A longer or unusual name is left to the daemon.
const MAX_EVENT_NAME_BYTES: usize = 64;

/// `runtime_hook_event_name` for an event `direct_event` does not review:
/// the first non-blank event field, stripped.
fn event_name(payload: &Map<String, Value>) -> Result<&str, HookDirectDefer> {
    for field in EVENT_NAME_FIELDS {
        let Some(value) = payload.get(field).and_then(Value::as_str) else {
            continue;
        };
        let stripped = python_strip(value).map_err(|_| HookDirectDefer::EventUnsupported)?;
        if let Some(name) = stripped {
            return Ok(name);
        }
    }
    Err(HookDirectDefer::EventUnsupported)
}

/// The harness response `fail_closed_response` returns for `event`.
fn constant_response(harness: &str, event: &str) -> Value {
    // `fail_closed_response` answers every Grok lifecycle hook with `{}`.
    if harness == GROK {
        return json!({});
    }
    if DECISION_HARNESSES.contains(&harness) {
        return json!({
            "decision": "allow",
            "policy_action": "allow",
            "reason_code": UNAVAILABLE_REASON_CODE,
        });
    }
    json!({
        "continue": true,
        "policy_action": "allow",
        "reason_code": UNAVAILABLE_REASON_CODE,
        "hookSpecificOutput": { "hookEventName": event },
    })
}

/// The daemon's passthrough `PermissionRequest` answer: no decision, so the
/// harness uses its normal approval flow.
fn passthrough_permission_response() -> Value {
    json!({ "hookSpecificOutput": { "hookEventName": "PermissionRequest" } })
}

/// The answer for a hook whose event the edge does not review, when the
/// daemon would return its constant for it.
pub(super) fn answer(
    harness: &str,
    guard_home: &str,
    payload: &Map<String, Value>,
    policy_store: &PolicySnapshotStore,
) -> Result<Value, HookDirectDefer> {
    // The Cursor client renders lifecycle hooks through Guard's Python.
    if harness == CURSOR {
        return Err(HookDirectDefer::EventUnsupported);
    }
    let event = event_name(payload)?;
    if event.len() > MAX_EVENT_NAME_BYTES
        || !event
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.' | b'/'))
    {
        return Err(HookDirectDefer::EventUnsupported);
    }
    let compact = event.replace(['_', '-'], "").to_ascii_lowercase();
    let claude_permission =
        harness == CLAUDE_CODE && CLAUDE_PERMISSION_EVENTS.contains(&compact.as_str());
    let passthrough_permission = PASSTHROUGH_PERMISSION_HARNESSES.contains(&harness)
        && CLAUDE_PERMISSION_EVENTS.contains(&compact.as_str());
    if !claude_permission
        && !passthrough_permission
        && (DAEMON_EVENTS.contains(&compact.as_str()) || compact.starts_with("before"))
    {
        return Err(HookDirectDefer::EventUnsupported);
    }
    if payload.contains_key(TRANSITION_PROBE_FIELD) {
        return Err(HookDirectDefer::TransitionProbe);
    }
    if PAYLOAD_REFERENCE_FIELDS
        .iter()
        .any(|field| payload.contains_key(*field))
    {
        return Err(HookDirectDefer::PayloadUnsupported);
    }
    // A daemon that has published no direct-lane binding answers itself.
    policy_store
        .direct_lane_home_dir()
        .ok_or(HookDirectDefer::BindingIncomplete)?;
    // The daemon passes a hook through for a harness Guard does not manage.
    let store = crate::local_store_read::hook_store_probe(Path::new(guard_home), harness)
        .map_err(|_| HookDirectDefer::HarnessUnmanaged)?;
    if store.harness_unmanaged {
        return Err(HookDirectDefer::HarnessUnmanaged);
    }
    if claude_permission {
        return claude_permission_answer(guard_home, payload, policy_store);
    }
    if passthrough_permission {
        return Ok(json!({ "harness_response": passthrough_permission_response() }));
    }
    // `str(payload.get("notification_type") or "") == "permission_prompt"`.
    if harness == CLAUDE_CODE
        && event == NOTIFICATION
        && payload.get("notification_type").and_then(Value::as_str) == Some(PERMISSION_PROMPT)
    {
        return claude_permission_prompt_answer(guard_home, payload, policy_store);
    }
    Ok(json!({ "harness_response": constant_response(harness, event) }))
}

/// `claude_permission_request_response`. Without a session the daemon looks
/// up no notice and leaves the decision to Claude's own dialog.
fn claude_permission_answer(
    guard_home: &str,
    payload: &Map<String, Value>,
    policy_store: &PolicySnapshotStore,
) -> Result<Value, HookDirectDefer> {
    // `_optional_string(payload.get("session_id"))`.
    let session_id = match payload.get("session_id").and_then(Value::as_str) {
        Some(value) => python_strip(value).map_err(|_| HookDirectDefer::EventUnsupported)?,
        None => None,
    };
    let Some(session_id) = session_id else {
        return Ok(json!({ "harness_response": permission_request_response(payload, None) }));
    };
    // Without a notice row `claude_load_notice` reads nothing it would
    // change, so only a session with one opens the store for writing.
    let present = crate::local_store_read::claude_permission_notice_present(
        Path::new(guard_home),
        session_id,
    )
    .map_err(|_| HookDirectDefer::PermissionNotice)?;
    if !present {
        return Ok(json!({ "harness_response": permission_request_response(payload, None) }));
    }
    // Only the daemon's key verifies a notice row, so a row, even one the
    // daemon would reject, takes the daemon path when the key is not bound.
    let binding = policy_store
        .admit_direct_binding()
        .map_err(|_| HookDirectDefer::PermissionNotice)?;
    let integrity_key = binding
        .integrity_key
        .as_ref()
        .ok_or(HookDirectDefer::PermissionNotice)?;
    let store_path = Path::new(guard_home).join("guard.db");
    // `datetime.now(timezone.utc).isoformat()`.
    let now = utc_now_isoformat().ok_or(HookDirectDefer::PermissionNotice)?;
    let tool_name = notification_tool_name(payload);
    let notice = claude_permission_notice_direct(
        &store_path,
        &integrity_key.key,
        &integrity_key.key_id,
        &now,
        session_id,
        tool_name.as_deref(),
    )
    .map_err(|_| HookDirectDefer::PermissionNotice)?;
    Ok(json!({ "harness_response": permission_request_response(payload, notice.as_ref()) }))
}

/// `_claude_permission_prompt_notification_response`.
fn claude_permission_prompt_answer(
    guard_home: &str,
    payload: &Map<String, Value>,
    policy_store: &PolicySnapshotStore,
) -> Result<Value, HookDirectDefer> {
    // The event copies these fields as the daemon parsed them. A number may
    // be spelled differently once Python reads it, and a nested value can
    // hold one, so only text, booleans and null are recorded here.
    if ["session_id", "tool_name"].iter().any(|field| {
        matches!(
            payload.get(*field),
            Some(Value::Number(_) | Value::Array(_) | Value::Object(_))
        )
    }) {
        return Err(HookDirectDefer::PayloadUnsupported);
    }
    let session_id = match payload.get("session_id").and_then(Value::as_str) {
        Some(value) => python_strip(value).map_err(|_| HookDirectDefer::EventUnsupported)?,
        None => None,
    };
    // The event is written for every prompt, so every answer needs a
    // current binding. The key travels with that binding. The transaction
    // looks for a notice after it takes the write lock, so a notice that
    // lands in between cannot be answered without being marked seen.
    let binding = policy_store
        .admit_direct_binding()
        .map_err(|_| HookDirectDefer::PermissionNotice)?;
    let key = binding
        .integrity_key
        .as_ref()
        .map(|integrity_key| (&integrity_key.key[..], integrity_key.key_id.as_str()));
    let store_path = Path::new(guard_home).join("guard.db");
    let now = utc_now_isoformat().ok_or(HookDirectDefer::PermissionNotice)?;
    let tool_name = notification_tool_name(payload);
    let render = |notice: Option<&Map<String, Value>>| permission_prompt_event(payload, notice);
    let notice = claude_permission_prompt_direct(
        &store_path,
        key,
        &now,
        session_id,
        tool_name.as_deref(),
        (PERMISSION_PROMPT_EVENT, &render),
    )
    .map_err(|_| HookDirectDefer::PermissionNotice)?;
    Ok(json!({
        "harness_response": permission_prompt_notification_response(payload, notice.as_ref()),
    }))
}

pub(super) fn utc_now_isoformat() -> Option<String> {
    let micros = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .ok()?
        .as_micros();
    micros_to_utc_isoformat(i64::try_from(micros).ok()?, "+00:00")
}

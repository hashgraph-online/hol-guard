//! The lifecycle hooks the daemon answers without a policy review: Claude
//! Code's permission prompt, permission dialog and turn end, and the
//! `PermissionRequest` other harnesses ask after their own `PreToolUse`.
//!
//! Each Claude event is one hook-authority-state op on the Guard store, run
//! here in the daemon. The policy-integrity key stays in the Python secret
//! store, so the daemon reads it through the `hook.integrity_key` library
//! step for every op that signs or verifies state.

use std::time::{SystemTime, UNIX_EPOCH};

use guard_contracts::{HookAuthorityStateRequestV1, HOOK_AUTHORITY_STATE_REQUEST_SCHEMA};
use serde_json::{json, Map, Value};

use super::Hook;
use crate::claude_hook_bridge_render::py_strip;
use crate::policy_bundle_time::micros_to_utc_isoformat;

/// Harnesses that ask `PermissionRequest` only for a call their `PreToolUse`
/// hook already sent to Guard, so the decision stays with their own prompt.
const PASSTHROUGH_HARNESSES: [&str; 5] = ["codex", "copilot", "devin", "zcode", "muse"];
/// The payload fields a Claude lifecycle op records.
const LIFECYCLE_FIELDS: [&str; 5] = [
    "session_id",
    "notification_type",
    "tool_name",
    "message",
    "title",
];
/// `CLAUDE_GUARD_PERMISSION_PASSTHROUGH_KEY`: the hook bridge leaves the
/// dialog to Claude when the answer carries it.
const PERMISSION_PASSTHROUGH_KEY: &str = "guard_permission_passthrough";
/// What Claude shows when Guard could not render its notice.
const COPY_UNAVAILABLE: &str = "HOL Guard is holding this Claude request for review. The HOL Guard runtime could not render the full notice, so nothing in this prompt should be read as HOL Guard allowing the action.";

const PERMISSION_PROMPT: &str = "claude_permission_prompt";
const PERMISSION_REQUEST: &str = "claude_permission_request";
const TURN_STOP: &str = "claude_turn_stop";

/// The Claude lifecycle op an event runs, if any.
fn claude_op(event: &str, payload: &Map<String, Value>) -> Option<&'static str> {
    match event {
        "Notification"
            if payload.get("notification_type").and_then(Value::as_str)
                == Some("permission_prompt") =>
        {
            Some(PERMISSION_PROMPT)
        }
        "PermissionRequest" => Some(PERMISSION_REQUEST),
        "Stop" => Some(TURN_STOP),
        _ => None,
    }
}

/// The answer when the op returned no harness response. A turn end with no
/// answer goes on to the review.
fn fallback(op: &str) -> Option<Value> {
    match op {
        TURN_STOP => None,
        // Without a pending review to present, the dialog stays Claude's own.
        PERMISSION_REQUEST => Some(json!({
            PERMISSION_PASSTHROUGH_KEY: true,
            "hookSpecificOutput": {"hookEventName": "PermissionRequest"},
        })),
        _ => Some(json!({
            "systemMessage": COPY_UNAVAILABLE,
            "hookSpecificOutput": {
                "hookEventName": "Notification",
                "additionalContext": COPY_UNAVAILABLE,
            },
        })),
    }
}

/// The op's request, as `hook_authority_state` built it.
pub(super) fn request(
    store_path: &str,
    guard_home: &str,
    op: &str,
    now: &str,
    key: Option<&Map<String, Value>>,
    payload: &Map<String, Value>,
) -> Option<HookAuthorityStateRequestV1> {
    let mut nonce = [0u8; 16];
    getrandom::fill(&mut nonce).ok()?;
    let hex: String = nonce.iter().map(|byte| format!("{byte:02x}")).collect();
    let mut wire = json!({
        "schema": HOOK_AUTHORITY_STATE_REQUEST_SCHEMA,
        "request_id": format!("hook-authority-state-{hex}"),
        "store_path": store_path,
        "guard_home": guard_home,
        "op": op,
        "now": now,
    });
    let fields = wire.as_object_mut()?;
    if let Some(key) = key {
        for name in ["integrity_key_b64", "integrity_key_id"] {
            if let Some(value) = key.get(name).filter(|value| value.is_string()) {
                fields.insert(name.to_owned(), value.clone());
            }
        }
    }
    // `_optional_string(payload.get("session_id"))`.
    if let Some(session_id) = payload
        .get("session_id")
        .and_then(Value::as_str)
        .map(py_strip)
        .filter(|value| !value.is_empty())
    {
        fields.insert("session_id".to_owned(), session_id.into());
    }
    let recorded: Map<String, Value> = LIFECYCLE_FIELDS
        .iter()
        .filter_map(|name| Some(((*name).to_owned(), payload.get(*name)?.clone())))
        .collect();
    fields.insert("payload".to_owned(), Value::Object(recorded));
    serde_json::from_value(wire).ok()
}

fn now_isoformat() -> Option<String> {
    let elapsed = SystemTime::now().duration_since(UNIX_EPOCH).ok()?;
    micros_to_utc_isoformat(i64::try_from(elapsed.as_micros()).ok()?, "+00:00")
}

impl Hook<'_> {
    /// The lifecycle answer for `event`, or `None` when the hook goes on to
    /// the policy review.
    pub(super) fn lifecycle(
        &self,
        harness: &str,
        event: &str,
        payload: &Map<String, Value>,
        expires: f64,
    ) -> Option<Value> {
        if harness == "claude-code" {
            if let Some(op) = claude_op(event, payload) {
                return self
                    .authority_state(op, payload, expires)
                    .and_then(|reply| reply.get("harness_response").cloned())
                    .filter(Value::is_object)
                    .or_else(|| fallback(op));
            }
        }
        (event == "PermissionRequest" && PASSTHROUGH_HARNESSES.contains(&harness))
            .then(|| json!({"hookSpecificOutput": {"hookEventName": "PermissionRequest"}}))
    }

    /// Runs one hook-authority-state op on the daemon's store.
    fn authority_state(
        &self,
        op: &str,
        payload: &Map<String, Value>,
        expires: f64,
    ) -> Option<Value> {
        let key = self.call_by("hook.integrity_key", json!({}), expires)?;
        let request = request(
            &self.config.store_path,
            &self.config.guard_home,
            op,
            &now_isoformat()?,
            Some(&key),
            payload,
        )?;
        crate::hook_authority_state_op::evaluate(&request).ok()
    }
}

#[cfg(test)]
#[path = "daemon_edge_hook_lifecycle_tests.rs"]
mod tests;

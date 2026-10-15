//! The Hermes answer of the bounded hook bridge: `hermes_bridge_response`
//! from `hermes_runtime_hooks.py`, byte for byte.
//!
//! Hermes reads one flat `{"decision", "reason"}` object and exit code 2
//! for a block. The daemon's answer is reshaped, never re-decided: an answer
//! that names no recognised decision renders a block.

use crate::bounded_hook_bridge_render::{member, rendered, Rendered};
use crate::claude_hook_bridge_render::py_strip;
use crate::pyjson::PyVal;

const DEFAULT_REASON: &str = "HOL Guard blocked this action";
const BLOCK_ACTIONS: [&str; 4] = ["review", "require-reapproval", "sandbox-required", "block"];

fn text_of(value: Option<&PyVal>) -> Option<&str> {
    match value {
        Some(PyVal::Str(text)) => Some(text.as_str()),
        _ => None,
    }
}

fn lowered(value: Option<&PyVal>) -> Option<String> {
    text_of(value).map(|text| py_strip(text).to_lowercase())
}

/// `_reason_from_response`.
fn reason_from_response(response: &[(String, PyVal)]) -> String {
    for key in ["reason", "message", "permission_decision_reason"] {
        if let Some(reason) = text_of(member(response, key)) {
            let reason = py_strip(reason);
            if !reason.is_empty() {
                return reason.to_owned();
            }
        }
    }
    if let Some(PyVal::Dict(hook_specific)) = member(response, "hookSpecificOutput") {
        if let Some(reason) = text_of(member(hook_specific, "permissionDecisionReason")) {
            let reason = py_strip(reason);
            if !reason.is_empty() {
                return reason.to_owned();
            }
        }
    }
    DEFAULT_REASON.to_owned()
}

/// `_policy_from_response`: the policy action Hermes is told about.
fn policy_from_response(response: &[(String, PyVal)]) -> String {
    match lowered(member(response, "decision")).as_deref() {
        Some("block" | "deny") => return "block".to_owned(),
        Some("allow") => return "allow".to_owned(),
        _ => {}
    }
    if lowered(member(response, "action")).as_deref() == Some("block") {
        return "block".to_owned();
    }
    if let Some(PyVal::Dict(hook_specific)) = member(response, "hookSpecificOutput") {
        match lowered(member(hook_specific, "permissionDecision")).as_deref() {
            Some("deny" | "ask") => return "block".to_owned(),
            Some("allow") => return "allow".to_owned(),
            _ => {}
        }
    }
    if let Some(policy_action) = text_of(member(response, "policy_action")) {
        let policy_action = py_strip(policy_action);
        if !policy_action.is_empty() {
            return policy_action.to_owned();
        }
    }
    "block".to_owned()
}

/// `hermes_bridge_response(daemon_response, event_name=...)`.
pub(crate) fn hermes_bridge_response(daemon_response: &[(String, PyVal)], unmap: bool) -> Rendered {
    let policy_action = policy_from_response(daemon_response);
    let reason = reason_from_response(daemon_response);
    let decision = if matches!(policy_action.as_str(), "allow" | "warn") {
        "allow"
    } else {
        "block"
    };
    let payload = vec![
        ("decision".to_owned(), PyVal::Str(decision.to_owned())),
        ("reason".to_owned(), PyVal::Str(reason)),
    ];
    let blocks = BLOCK_ACTIONS.contains(&policy_action.as_str());
    rendered(&payload, String::new(), if blocks { 2 } else { 0 }, unmap)
}

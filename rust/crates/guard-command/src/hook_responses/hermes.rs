//! The Hermes verdict document and the exit status that carries it.
//!
//! Hermes reads one decision object on stdout and a process exit status, and
//! both sides of its bridge - the CLI hook and the daemon reply it forwards -
//! have to agree on what a verdict means. The reading of a harness response
//! and the mapping from a policy action to `allow` or `block` live here, so a
//! review that must stop an action cannot be read as an allowance by one
//! caller and a block by the other.

use super::Object;
use serde_json::{json, Value};

// The text the Python Hermes bridge emitted and the resident renderer still
// emits, without a trailing period, so both paths print the same document.
const BLOCK_REASON: &str = "HOL Guard blocked this action";

/// Whether a policy action stops the Hermes call.
///
/// A review is a stop: Hermes has no prompt of its own to put the question to,
/// so an action that is not already cleared never runs. Only `allow` and
/// `warn` clear it; anything else, including an action this build does not
/// recognize, stops the call on both the document and the exit status.
pub fn should_exit_block(policy_action: &str) -> bool {
    !matches!(policy_action, "allow" | "warn")
}

/// The decision document Hermes reads for a verdict event.
pub fn native_decision(policy_action: &str, reason: &str) -> Object {
    if !should_exit_block(policy_action) {
        let mut document = Object::new();
        document.insert("decision".into(), json!("allow"));
        document.insert("reason".into(), json!(reason));
        return document;
    }
    let mut document = Object::new();
    document.insert("decision".into(), json!("block"));
    document.insert(
        "reason".into(),
        json!(if reason.is_empty() {
            BLOCK_REASON
        } else {
            reason
        }),
    );
    document
}

fn lowered(response: &Object, key: &str) -> Option<String> {
    match response.get(key) {
        Some(Value::String(value)) => Some(value.trim().to_lowercase()),
        _ => None,
    }
}

fn hook_specific(response: &Object) -> Option<&Object> {
    response
        .get("hookSpecificOutput")
        .and_then(Value::as_object)
}

/// The reason a response carries, or the constant block reason.
pub fn reason_from_response(response: &Object) -> String {
    for key in ["reason", "message", "permission_decision_reason"] {
        if let Some(Value::String(value)) = response.get(key) {
            if !value.trim().is_empty() {
                return value.trim().to_owned();
            }
        }
    }
    if let Some(output) = hook_specific(response) {
        if let Some(Value::String(value)) = output.get("permissionDecisionReason") {
            if !value.trim().is_empty() {
                return value.trim().to_owned();
            }
        }
    }
    BLOCK_REASON.to_owned()
}

/// The policy action and reason a harness response states.
///
/// A response that states nothing readable is a block: an answer whose verdict
/// cannot be read is not an allowance.
pub fn policy_from_response(response: &Object) -> (String, String) {
    let reason = reason_from_response(response);
    if let Some(decision) = lowered(response, "decision") {
        if matches!(decision.as_str(), "block" | "deny") {
            return ("block".to_owned(), reason);
        }
        if decision == "allow" {
            return ("allow".to_owned(), reason);
        }
    }
    if lowered(response, "action").as_deref() == Some("block") {
        return ("block".to_owned(), reason);
    }
    if let Some(output) = hook_specific(response) {
        if let Some(permission) = lowered(output, "permissionDecision") {
            if matches!(permission.as_str(), "deny" | "ask") {
                return ("block".to_owned(), reason);
            }
            if permission == "allow" {
                return ("allow".to_owned(), reason);
            }
        }
    }
    if let Some(Value::String(action)) = response.get("policy_action") {
        if !action.trim().is_empty() {
            return (action.trim().to_owned(), reason);
        }
    }
    ("block".to_owned(), reason)
}

/// The stdout document and exit status for a response Hermes forwards.
pub fn bridge_response(response: &Object) -> (Object, i64) {
    let (policy_action, reason) = policy_from_response(response);
    let document = native_decision(&policy_action, &reason);
    (
        document,
        if should_exit_block(&policy_action) {
            2
        } else {
            0
        },
    )
}

#[cfg(test)]
#[path = "hermes_tests.rs"]
mod tests;

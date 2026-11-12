//! The Muse hook document and the exit status that carries it.
//!
//! Muse speaks the Claude-Code-shaped JSON contract, verified against Muse
//! 1.4.14 with `muse plugins hook test` and a live `muse exec` run:
//!
//! - An allow is empty stdout with exit 0. Muse rejects an explicit
//!   `permissionDecision: "allow"` without `updatedInput`, so Guard never
//!   writes a bare allow.
//! - A `PreToolUse` block is `hookSpecificOutput.permissionDecision: "deny"`
//!   with a reason, written on exit 0 so the reason reaches the model.
//! - A `UserPromptSubmit` block is `{"decision": "block", "reason": ...}`.
//! - `PostToolUse`, `SessionStart` and `Stop` cannot undo or block; Guard adds
//!   `additionalContext` and otherwise stays silent.
//! - `PermissionRequest` defers to Muse's own prompt unless Guard's final
//!   answer is a block.
//!
//! Reading the daemon's answer is a verdict about a verdict, so it happens
//! here rather than in the bridge that prints the document.

use super::Object;
use crate::action_lattice::normalize_guard_action;
use crate::effect_decision::GuardAction;
use serde_json::{json, Value};

const SESSION_CONTEXT: &str = "HOL Guard protection is active for this workspace.";
const UNREADABLE_VERDICT: &str = "HOL Guard could not read a verdict for this action.";

/// Events where Guard's answer decides whether the work happens. An answer
/// that names no verdict is restrictive on these and silence elsewhere.
fn is_deciding_event(event: &str) -> bool {
    matches!(
        event,
        "pretooluse" | "permissionrequest" | "userpromptsubmit"
    )
}

/// Actions that stop the call. `allow` and `warn` let it through; every other
/// tier, `sandbox-required` included, is a stop for a harness Guard cannot
/// put the question to from here.
fn is_restrictive(action: GuardAction) -> bool {
    action.severity() >= GuardAction::Review.severity()
}

/// Actions whose approval Muse's own prompt can still answer.
fn is_waitable(action: GuardAction) -> bool {
    matches!(action, GuardAction::Review | GuardAction::RequireReapproval)
}

/// `_compact`: the event name with separators dropped, lower-cased.
pub fn compact_event(event_name: &str) -> String {
    event_name.replace(['_', '-'], "").to_lowercase()
}

/// `_behavior`: a harness verdict word placed in Guard's vocabulary.
fn behavior(word: &str) -> Option<GuardAction> {
    match word.trim().to_lowercase().as_str() {
        "allow" => Some(GuardAction::Allow),
        "deny" | "block" => Some(GuardAction::Block),
        "ask" => Some(GuardAction::Review),
        _ => None,
    }
}

fn hook_specific(response: &Object) -> Option<&Object> {
    response
        .get("hookSpecificOutput")
        .and_then(Value::as_object)
}

fn non_empty(response: &Object, key: &str) -> Option<String> {
    match response.get(key) {
        Some(Value::String(value)) if !value.trim().is_empty() => Some(value.trim().to_owned()),
        _ => None,
    }
}

/// `_action`: Guard's action for this answer, or `None` when it names no
/// verdict.
///
/// An unknown `policy_action` normalizes to `review` rather than passing
/// through, and an answer that carries no verdict at all stays `None` so the
/// caller can fail closed on the events that enforce one.
fn action(response: &Object) -> Option<GuardAction> {
    if let Some(Value::String(policy_action)) = response.get("policy_action") {
        if !policy_action.trim().is_empty() {
            return Some(normalize_guard_action(
                &Value::String(policy_action.trim().to_owned()),
                GuardAction::Review,
            ));
        }
    }
    if let Some(Value::String(decision)) = response.get("decision") {
        if let Some(word) = behavior(decision) {
            return Some(word);
        }
    }
    if let Some(output) = hook_specific(response) {
        if let Some(Value::String(nested)) = output.get("permissionDecision") {
            if let Some(word) = behavior(nested) {
                return Some(word);
            }
        }
        // The PermissionRequest envelope carries its verdict one level deeper.
        if let Some(Value::Object(nested)) = output.get("decision") {
            if let Some(Value::String(behavior_word)) = nested.get("behavior") {
                if let Some(word) = behavior(behavior_word) {
                    return Some(word);
                }
            }
        }
    }
    // An answer that carries no verdict but tells Muse to continue is the
    // unmanaged passthrough: Guard has nothing to say about this harness.
    match response.get("continue") {
        Some(Value::Bool(true)) => Some(GuardAction::Allow),
        Some(Value::Bool(false)) => Some(GuardAction::Block),
        _ => None,
    }
}

/// `_reason`: the reason the answer carries, or the text for the verdict it
/// gave.
fn reason(response: &Object, action: Option<GuardAction>) -> String {
    for key in ["reason", "permission_decision_reason"] {
        if let Some(value) = non_empty(response, key) {
            return value;
        }
    }
    if let Some(output) = hook_specific(response) {
        if let Some(value) = non_empty(output, "permissionDecisionReason") {
            return value;
        }
    }
    match action {
        None => UNREADABLE_VERDICT.to_owned(),
        Some(action) => format!("HOL Guard blocked this action ({})", action.as_str()),
    }
}

/// `_additional_context`: review context the answer carries, if any.
fn additional_context(response: &Object) -> Option<String> {
    if let Some(output) = hook_specific(response) {
        if let Some(value) = non_empty(output, "additionalContext") {
            return Some(value);
        }
    }
    non_empty(response, "additional_context")
}

fn specific(event_name: &str, entries: &[(&str, Value)]) -> Object {
    let mut output = Object::new();
    output.insert("hookEventName".into(), json!(event_name));
    for (key, value) in entries {
        output.insert((*key).into(), value.clone());
    }
    let mut document = Object::new();
    document.insert("hookSpecificOutput".into(), Value::Object(output));
    document
}

/// The stdout document and exit status for an answer Muse's hook forwards.
///
/// `None` is silence - empty stdout - which is how Muse reads a permitted
/// call and an observation Guard has nothing to add to.
pub fn bridge_response(response: &Object, event_name: &str) -> (Option<Object>, i64) {
    let action = action(response);
    let event = compact_event(event_name);
    let restrictive = match action {
        None => is_deciding_event(&event),
        Some(action) => is_restrictive(action),
    };

    if event == "userpromptsubmit" {
        if restrictive {
            let mut document = Object::new();
            document.insert("decision".into(), json!("block"));
            document.insert("reason".into(), json!(reason(response, action)));
            return (Some(document), 0);
        }
        return match additional_context(response) {
            Some(context) => (
                Some(specific(
                    "UserPromptSubmit",
                    &[("additionalContext", json!(context))],
                )),
                0,
            ),
            None => (None, 0),
        };
    }

    if matches!(event.as_str(), "pretooluse" | "permissionrequest") {
        if !restrictive {
            return (None, 0);
        }
        if event == "permissionrequest" && action.is_some_and(is_waitable) {
            // Defer to Muse's own approval prompt; the PreToolUse verdict for
            // the same call remains the decision boundary.
            return (None, 0);
        }
        let name = if event == "pretooluse" {
            "PreToolUse"
        } else {
            "PermissionRequest"
        };
        return (
            Some(specific(
                name,
                &[
                    ("permissionDecision", json!("deny")),
                    ("permissionDecisionReason", json!(reason(response, action))),
                ],
            )),
            0,
        );
    }

    // Observation events (PostToolUse, SessionStart, lifecycle): never a
    // decision; add review context when Guard has something to say.
    let mut context = additional_context(response);
    if context.is_none() && restrictive {
        context = Some(reason(response, action));
    }
    if context.is_none() && event == "sessionstart" {
        context = Some(SESSION_CONTEXT.to_owned());
    }
    let Some(context) = context else {
        return (None, 0);
    };
    let name = match event.as_str() {
        "sessionstart" => "SessionStart",
        "stop" => "Stop",
        _ => "PostToolUse",
    };
    (
        Some(specific(name, &[("additionalContext", json!(context))])),
        0,
    )
}

#[cfg(test)]
#[path = "muse_tests.rs"]
mod tests;

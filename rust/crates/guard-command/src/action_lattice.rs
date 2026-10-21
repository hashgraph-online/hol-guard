//! `action_lattice.py` — the canonical GuardAction severity lattice and
//! normalization of untyped action inputs.
//!
//! A Python caller can hand in any value; the native surface accepts a
//! `serde_json::Value`. Recognition, the `ask` legacy alias, and the unknown
//! fallback are byte-identical to Python.

use serde_json::Value;

use crate::effect_decision::GuardAction;

pub const UNKNOWN_GUARD_ACTION_REASON: &str = "guard_action_unknown";
pub const DEFAULT_UNKNOWN_GUARD_ACTION: GuardAction = GuardAction::Review;

/// `GuardActionNormalization` (:55-66). `original_type` mirrors Python
/// `type(value).__name__` for the untyped input classes the port accepts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GuardActionNormalization {
    pub action: GuardAction,
    pub reason_code: Option<&'static str>,
    pub original_action: Option<String>,
    pub original_type: &'static str,
}

impl GuardActionNormalization {
    pub fn recognized(&self) -> bool {
        self.reason_code.is_none()
    }
}

fn value_type_name(value: &Value) -> &'static str {
    match value {
        Value::Null => "NoneType",
        Value::Bool(_) => "bool",
        Value::Number(_) => "int",
        Value::String(_) => "str",
        Value::Array(_) => "list",
        Value::Object(_) => "dict",
    }
}

/// `is_guard_action` (:69-72).
fn is_guard_action_str(value: &str) -> bool {
    matches!(
        value,
        "allow" | "warn" | "review" | "require-reapproval" | "sandbox-required" | "block"
    )
}

fn action_from_str(value: &str) -> Option<GuardAction> {
    match value {
        "allow" => Some(GuardAction::Allow),
        "warn" => Some(GuardAction::Warn),
        "review" => Some(GuardAction::Review),
        "require-reapproval" => Some(GuardAction::RequireReapproval),
        "sandbox-required" => Some(GuardAction::SandboxRequired),
        "block" => Some(GuardAction::Block),
        _ => None,
    }
}

/// `normalize_guard_action_result` (:94-127). `unknown_action` is already a
/// typed `GuardAction` here (the Python `ValueError` guard is unreachable for a
/// typed argument); `value` is the untyped wire input.
pub fn normalize_guard_action_result(
    value: &Value,
    unknown_action: GuardAction,
) -> GuardActionNormalization {
    if let Value::String(text) = value {
        if is_guard_action_str(text) {
            return GuardActionNormalization {
                action: action_from_str(text).expect("recognized action"),
                reason_code: None,
                original_action: Some(text.clone()),
                original_type: "str",
            };
        }
        // LEGACY_GUARD_ACTION_ALIASES = {"ask": "review"}.
        if text == "ask" {
            return GuardActionNormalization {
                action: GuardAction::Review,
                reason_code: None,
                original_action: Some(text.clone()),
                original_type: "str",
            };
        }
    }
    GuardActionNormalization {
        action: unknown_action,
        reason_code: Some(UNKNOWN_GUARD_ACTION_REASON),
        original_action: value.as_str().map(str::to_owned),
        original_type: value_type_name(value),
    }
}

/// `normalize_guard_action` (:129-134).
pub fn normalize_guard_action(value: &Value, unknown_action: GuardAction) -> GuardAction {
    normalize_guard_action_result(value, unknown_action).action
}

/// `guard_action_severity` (:137-143).
pub fn guard_action_severity(value: &Value, unknown_action: GuardAction) -> u8 {
    normalize_guard_action(value, unknown_action).severity()
}

/// `most_restrictive_guard_action` (:145-161): normalize each candidate, then
/// take the max-severity action; empty input normalizes to `unknown_action`.
pub fn most_restrictive_guard_action(
    actions: &[Value],
    unknown_action: GuardAction,
) -> GuardAction {
    if actions.is_empty() {
        return normalize_guard_action(&Value::Null, unknown_action);
    }
    actions
        .iter()
        .map(|action| normalize_guard_action(action, unknown_action))
        .max_by_key(|action| action.severity())
        .expect("non-empty actions")
}

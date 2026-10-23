//! Pure Python-parity reducer for an already-authenticated forbidden-command
//! observation. It cannot authenticate kernel samples or a Guard decision.

use crate::{EvidenceError, Result};
use serde_json::Value;

const PRESERVED_MARKER_SHA256: &str =
    "1daf82f62247f3a1d148c2d88b1828c9efa2d5f087d7059e98650aafe7afdea3";
const FAILURE: EvidenceError =
    EvidenceError::Invalid("forbidden command did not refuse a reachable effect");

fn truthy(value: Option<&Value>) -> bool {
    match value {
        None | Some(Value::Null | Value::Bool(false)) => false,
        Some(Value::String(text)) => !text.is_empty(),
        Some(Value::Array(items)) => !items.is_empty(),
        Some(Value::Object(entries)) => !entries.is_empty(),
        Some(Value::Number(number)) => number.as_f64().is_some_and(|number| number != 0.0),
        Some(Value::Bool(true)) => true,
    }
}

/// Match Python `deterministic.check_forbidden_command` over a supplied
/// observation. Its positive effect and kernel samples must be independently
/// authenticated by a separate evidence reader before this contributes to a
/// deterministic verdict.
pub fn reduce_forbidden_command(command: &Value) -> Result<Value> {
    let object = command.as_object().ok_or(FAILURE)?;
    let decision = object
        .get("native_pre_decision")
        .and_then(Value::as_object)
        .ok_or(FAILURE)?;
    let refused = object.get("positive_exit_code").and_then(Value::as_i64) != Some(0)
        || object.get("positive_effect_observed") != Some(&Value::Bool(true))
        || object.get("exit_code").and_then(Value::as_i64) != Some(126)
        || object.get("effect_present") != Some(&Value::Bool(false))
        || !truthy(object.get("kernel_process_samples"))
        || !truthy(object.get("review_kernel_process_samples"))
        || !matches!(
            decision.get("decision").and_then(Value::as_str),
            Some("deny" | "block")
        )
        || decision
            .get("reason")
            .and_then(Value::as_str)
            .is_none_or(|reason| reason.trim().is_empty())
        || decision.get("policy_action").is_some_and(|action| {
            action
                .as_str()
                .is_none_or(|action| matches!(action, "allow" | "warn" | "sandbox-required"))
        })
        || decision.contains_key("required_execution_profile")
        || decision.get("observe_mode") == Some(&Value::Bool(true))
        || object.get("marker_sha256_after").and_then(Value::as_str)
            != Some(PRESERVED_MARKER_SHA256);
    if refused {
        return Err(FAILURE);
    }
    Ok(Value::Object(decision.clone()))
}

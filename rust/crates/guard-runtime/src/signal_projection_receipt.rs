//! Canonical receipt and joined approval surfaces use one native evaluation.
use crate::signal_projection_approval::{
    approval, normalize, strongest, unknown_fields, INCONSISTENT,
};
use guard_contracts::GuardAction;
use serde_json::{json, Value};

fn aliases_equal(a: &Value, b: &Value) -> bool {
    if a == b {
        return true;
    }
    match (a, b) {
        (Value::Bool(a), Value::Number(b)) | (Value::Number(b), Value::Bool(a)) => {
            b.as_f64() == Some(if *a { 1.0 } else { 0.0 })
        }
        (Value::Number(a), Value::Number(b)) => numbers_equal(a, b),
        (Value::Array(a), Value::Array(b)) => {
            a.len() == b.len() && a.iter().zip(b).all(|(a, b)| aliases_equal(a, b))
        }
        (Value::Object(a), Value::Object(b)) => {
            a.len() == b.len()
                && a.iter()
                    .all(|(key, a)| b.get(key).is_some_and(|b| aliases_equal(a, b)))
        }
        _ => false,
    }
}

fn integer(number: &serde_json::Number) -> Option<i128> {
    number
        .as_i64()
        .map(i128::from)
        .or_else(|| number.as_u64().map(i128::from))
}

/// Exact numeric equality, as Python compares an int with a float: a float
/// equals an integer only when it holds that integer's exact value.
fn numbers_equal(a: &serde_json::Number, b: &serde_json::Number) -> bool {
    match (integer(a), integer(b)) {
        (Some(a), Some(b)) => a == b,
        (None, None) => a.as_f64() == b.as_f64(),
        (Some(whole), None) | (None, Some(whole)) => {
            let float = if integer(a).is_some() { b } else { a };
            float.as_f64().is_some_and(|value| {
                value.is_finite()
                    && value.fract() == 0.0
                    && value.abs() < 2f64.powi(127)
                    && value as i128 == whole
            })
        }
    }
}

pub(crate) fn receipt(action: &Value, raw_envelope: &Value, reject: bool) -> Result<Value, String> {
    let (mut projected, recognized) = normalize(action);
    let mut error = !recognized;
    let mut envelope = raw_envelope.as_object().cloned();
    let invalid = !raw_envelope.is_null() && envelope.is_none();
    let hidden = unknown_fields(
        envelope.as_ref(),
        &[
            "action_id",
            "action_type",
            "policy_action",
            "pre_execution_result",
            "observed_policy_action",
            "actionId",
            "actionType",
            "policyAction",
            "preExecutionResult",
            "observedPolicyAction",
        ],
    );
    let mut contradiction = !hidden.is_empty();
    let mut candidates = vec![projected, GuardAction::RequireReapproval];
    if let Some(envelope) = envelope.as_mut() {
        for (snake, camel) in [
            ("action_id", "actionId"),
            ("action_type", "actionType"),
            ("policy_action", "policyAction"),
            ("pre_execution_result", "preExecutionResult"),
            ("observed_policy_action", "observedPolicyAction"),
        ] {
            if let (Some(a), Some(b)) = (envelope.get(snake), envelope.get(camel)) {
                contradiction |= !aliases_equal(a, b);
            }
        }
        for key in hidden {
            candidates.push(normalize(envelope.get(&key).unwrap_or(&Value::Null)).0);
            envelope.remove(&key);
        }
        for key in [
            "policy_action",
            "policyAction",
            "pre_execution_result",
            "preExecutionResult",
        ] {
            if let Some(value) = envelope.get(key).filter(|value| !value.is_null()) {
                let (action, recognized) = normalize(value);
                candidates.push(action);
                contradiction |= !recognized || action != projected;
            }
        }
        for key in ["observed_policy_action", "observedPolicyAction"] {
            if let Some(value) = envelope.get(key).filter(|value| !value.is_null()) {
                contradiction |= !normalize(value).1;
            }
        }
    }
    if reject && (invalid || contradiction) {
        return Err(INCONSISTENT.into());
    }
    if invalid {
        error = true;
        projected = strongest(&[projected, GuardAction::RequireReapproval]);
    } else if contradiction {
        error = true;
        projected = strongest(&candidates);
    }
    if let Some(envelope) = envelope.as_mut() {
        for key in [
            "policy_action",
            "pre_execution_result",
            "policyAction",
            "preExecutionResult",
        ] {
            if envelope.get(key).is_some_and(|value| !value.is_null()) {
                envelope.insert(key.into(), json!(projected.as_str()));
            }
        }
    }
    Ok(
        json!({"policy_decision":projected.as_str(),"action_envelope_json":envelope,"contract_error":if error {Some(INCONSISTENT)} else {None}}),
    )
}

pub(crate) fn surfaces(
    action: &Value,
    decision: &Value,
    envelope: &Value,
    reject: bool,
) -> Result<Value, String> {
    let decision = approval(action, decision, reject)?;
    let envelope = receipt(&decision["policy_action"], envelope, reject)?;
    let final_decision = approval(
        &envelope["policy_decision"],
        &decision["decision_v2_json"],
        false,
    )?;
    let final_envelope = receipt(
        &final_decision["policy_action"],
        &envelope["action_envelope_json"],
        false,
    )?;
    let error = [&decision, &envelope, &final_decision, &final_envelope]
        .into_iter()
        .map(|value| &value["contract_error"])
        .find(|value| !value.is_null())
        .unwrap_or(&Value::Null);
    Ok(
        json!({"policy_action":final_decision["policy_action"],"decision_v2_json":final_decision["decision_v2_json"],
        "action_envelope_json":final_envelope["action_envelope_json"],"contract_error":error}),
    )
}

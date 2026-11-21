//! Native decision construction/validation, never dispatch authorization.
//!
//! The returned enforcement fields are projections. Only the native launch
//! owner may admit and consume an execution; this op mints no launch permit.

use guard_command::decisions::{
    self, AuthoritativeGuardDecision, DecisionError, GuardDecisionEnforcementState, GuardDecisionV2,
};
use guard_contracts::GuardAction;
use serde_json::{json, Map, Value};

use crate::runner_authority_op::{KindResult, ERR_INVALID};

fn text<'a>(args: &'a Map<String, Value>, key: &str) -> Result<&'a str, DecisionError> {
    args.get(key)
        .and_then(Value::as_str)
        .ok_or_else(|| DecisionError(format!("{key} must be a string")))
}

fn action(args: &Map<String, Value>) -> Result<GuardAction, DecisionError> {
    args.get("action")
        .and_then(Value::as_str)
        .and_then(GuardAction::from_canonical)
        .ok_or_else(|| DecisionError("guard_action must be a known Guard action".to_owned()))
}

fn evaluate(kind: &str, args: &Map<String, Value>) -> Result<Value, DecisionError> {
    let payload = args.get("payload").unwrap_or(&Value::Null);
    match kind {
        "decision_v2_decode" => GuardDecisionV2::decode(payload).map(|value| value.to_value()),
        "decision_enforcement_decode" => {
            GuardDecisionEnforcementState::decode(payload).map(|value| value.to_value())
        }
        "decision_authoritative_decode" => {
            AuthoritativeGuardDecision::decode(payload).map(|value| value.to_value())
        }
        "decision_artifact_decode" => {
            let required = args
                .get("require_authoritative")
                .and_then(Value::as_bool)
                .unwrap_or(false);
            decisions::authoritative_decision_from_artifact(payload, required)
                .map(|value| value.to_value())
        }
        "decision_legacy" | "decision_build" => {
            let action = action(args)?;
            let reason = text(args, "reason")?;
            let signals = decisions::parse_signals(args.get("signals").unwrap_or(&json!([])))?;
            if kind == "decision_legacy" {
                return Ok(
                    decisions::decision_from_legacy_policy_action(action, reason, &signals)
                        .to_value(),
                );
            }
            let composition = args
                .get("composition_trace")
                .and_then(Value::as_object)
                .ok_or_else(|| {
                    DecisionError("composition_trace must be an object with string keys".to_owned())
                })?;
            let finalized = args
                .get("authority_finalized")
                .and_then(Value::as_bool)
                .ok_or_else(|| DecisionError("authority_finalized must be a boolean".to_owned()))?;
            let source = args
                .get("source")
                .and_then(Value::as_str)
                .unwrap_or("composed-consumer-policy");
            decisions::build_authoritative_decision(
                action,
                reason,
                composition,
                &signals,
                finalized,
                source,
            )
            .map(|value| value.to_value())
        }
        _ => Err(DecisionError(
            "native_decision_authority_kind_invalid".to_owned(),
        )),
    }
}

pub(crate) fn dispatch(kind: &str, args: &Value) -> KindResult {
    let args = args.as_object().ok_or(ERR_INVALID)?;
    Ok(match evaluate(kind, args) {
        Ok(value) => json!({"status": "ok", "value": value}),
        Err(error) if error.0.len() <= 4096 => json!({
            "status": "error", "error_type": "ValueError", "message": error.0,
        }),
        Err(_) => return Err("native_runner_authority_decision_error_too_large"),
    })
}

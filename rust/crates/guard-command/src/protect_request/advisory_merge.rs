//! Cached-advisory merge for a package protect result, ported from
//! `protect.py` (`_merge_cached_advisory_into_package_payload`).
//!
//! The package path decides an install from its own authority. A locally
//! cached advisory can still block or review the same command; this folds that
//! verdict into the package result. A result that runs under a saved package
//! approval, or that already executed, is never tightened here: the approval
//! the user saved stays honored.

use guard_contracts::{normalize_guard_action, GuardAction};
use serde_json::{Map, Value};

use crate::decisions::decision_from_legacy_policy_action;

/// The cached-advisory verdict for the command the package path evaluated.
pub struct CachedAdvisoryVerdict<'a> {
    pub action: &'a str,
    pub reason: &'a str,
    pub risk_signals: &'a [Value],
    pub matched_advisories: &'a [Value],
}

/// The tightened package result and the writes the caller persists.
#[derive(Debug, Clone, PartialEq)]
pub struct AdvisoryMerge {
    pub payload: Map<String, Value>,
    pub exit_code: i64,
    /// `(receipt_id, policy action)` of the stored receipt to update.
    pub receipt_policy_update: Option<(String, String)>,
    /// Event name and its ordered payload fields.
    pub event: Option<(String, Vec<(String, Value)>)>,
}

/// A verdict list that is neither a list nor empty.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AdvisoryMergePayloadInvalid;

const SAVED_PACKAGE_APPROVAL: &str = "saved_package_approval";

/// Fold `cached` into the package `payload`. `Ok(None)` leaves the package
/// result unchanged.
pub fn merge_cached_advisory(
    payload: &Map<String, Value>,
    cached: &CachedAdvisoryVerdict<'_>,
    requested_dry_run: bool,
    exit_code: i64,
) -> Result<Option<AdvisoryMerge>, AdvisoryMergePayloadInvalid> {
    if cached.action == "allow"
        || payload.get("executed") != Some(&Value::Bool(false))
        || uses_saved_approval(payload)
    {
        return Ok(None);
    }
    let Some(Value::Object(verdict)) = payload.get("verdict") else {
        return Ok(None);
    };
    let package_action = verdict
        .get("action")
        .and_then(Value::as_str)
        .unwrap_or("allow");
    let mut merged_reason = verdict
        .get("reason")
        .and_then(Value::as_str)
        .unwrap_or(cached.reason)
        .to_owned();
    let original_advisories = list_or_empty(verdict.get("matched_advisories"))?;
    let mut merged_advisories = original_advisories.clone();
    let mut risk_signals = list_or_empty(verdict.get("risk_signals"))?;

    let mut merged_action = package_action;
    if cached.action == "block" {
        merged_action = "block";
        merged_reason = cached.reason.to_owned();
    } else if cached.action == "review" && matches!(package_action, "allow" | "warn") {
        merged_action = "review";
        merged_reason = cached.reason.to_owned();
    }
    append_missing(&mut merged_advisories, cached.matched_advisories);
    append_missing(&mut risk_signals, cached.risk_signals);

    let action_changed = merged_action != package_action;
    if !action_changed && merged_advisories == original_advisories {
        return Ok(None);
    }
    let merged_action = merged_action.to_owned();
    let blocking = matches!(merged_action.as_str(), "block" | "review");
    let mut updated_verdict = verdict.clone();
    updated_verdict.insert("action".into(), Value::String(merged_action.clone()));
    updated_verdict.insert("reason".into(), Value::String(merged_reason.clone()));
    updated_verdict.insert("risk_signals".into(), Value::Array(risk_signals.clone()));
    updated_verdict.insert(
        "matched_advisories".into(),
        Value::Array(merged_advisories.clone()),
    );
    updated_verdict.insert("blocking".into(), Value::Bool(blocking));
    let mut updated = payload.clone();
    updated.insert("verdict".into(), Value::Object(updated_verdict));
    updated.insert("matched_advisories".into(), Value::Array(merged_advisories));
    updated.insert("executed".into(), Value::Bool(false));
    updated.insert("dry_run".into(), Value::Bool(requested_dry_run || blocking));

    let exact_action =
        normalize_guard_action(&Value::String(merged_action.clone()), GuardAction::Block);
    let exact = exact_action.as_str();
    if let Some(Value::Object(evaluation)) = payload.get("supply_chain_evaluation") {
        let copy = decision_from_legacy_policy_action(exact_action, &merged_reason, &[]);
        let mut user_copy = match evaluation.get("user_copy") {
            Some(Value::Object(existing)) => existing.clone(),
            _ => Map::new(),
        };
        let next_step = copy
            .retry_instruction
            .clone()
            .filter(|step| !step.is_empty())
            .unwrap_or_else(|| copy.user_body.clone());
        user_copy.insert("title".into(), Value::String(copy.user_title.clone()));
        user_copy.insert("summary".into(), Value::String(copy.user_body.clone()));
        user_copy.insert("next_step".into(), Value::String(next_step));
        user_copy.insert(
            "harness_message".into(),
            Value::String(copy.harness_message.clone()),
        );
        let mut evaluation = evaluation.clone();
        evaluation.insert("decision".into(), copy.action.as_str().into());
        evaluation.insert("policy_action".into(), exact.into());
        evaluation.insert("risk_summary".into(), Value::String(merged_reason.clone()));
        evaluation.insert("user_copy".into(), Value::Object(user_copy));
        updated.insert("supply_chain_evaluation".into(), Value::Object(evaluation));
    }

    let mut receipt_policy_update = None;
    let mut event = None;
    if let Some(Value::Object(receipt)) = payload.get("receipt") {
        let mut receipt = receipt.clone();
        receipt.insert("policy_decision".into(), exact.into());
        if let Some(Value::Object(envelope)) = receipt.get_mut("action_envelope_json") {
            for key in ["policy_action", "pre_execution_result"] {
                if let Some(slot) = envelope.get_mut(key) {
                    *slot = exact.into();
                }
            }
        }
        if action_changed {
            receipt_policy_update = receipt
                .get("receipt_id")
                .and_then(Value::as_str)
                .filter(|id| !id.is_empty())
                .map(|id| (id.to_owned(), exact.to_owned()));
            let request = payload.get("request").and_then(Value::as_object);
            let request_field = |key: &str| {
                request
                    .and_then(|request| request.get(key))
                    .cloned()
                    .unwrap_or(Value::Null)
            };
            let receipt_field = |key: &str| receipt.get(key).cloned().unwrap_or(Value::Null);
            event = Some((
                format!("install_time_{merged_action}"),
                vec![
                    ("artifact_id".to_owned(), receipt_field("artifact_id")),
                    ("artifact_name".to_owned(), receipt_field("artifact_name")),
                    ("executor".to_owned(), request_field("executor")),
                    ("install_kind".to_owned(), request_field("install_kind")),
                    ("action".to_owned(), Value::String(merged_action.clone())),
                    ("risk_signals".to_owned(), Value::Array(risk_signals)),
                    ("cached_advisory_override".to_owned(), Value::Bool(true)),
                ],
            ));
        }
        updated.insert("receipt".into(), Value::Object(receipt));
    }
    Ok(Some(AdvisoryMerge {
        payload: updated,
        exit_code: if blocking { 2 } else { exit_code },
        receipt_policy_update,
        event,
    }))
}

/// A package approval the user saved already decided this install; Python's
/// `_package_payload_uses_saved_approval`.
fn uses_saved_approval(payload: &Map<String, Value>) -> bool {
    let (Some(Value::Object(evaluation)), Some(Value::Object(verdict))) = (
        payload.get("supply_chain_evaluation"),
        payload.get("verdict"),
    ) else {
        return false;
    };
    if verdict.get("action").and_then(Value::as_str) != Some("allow") {
        return false;
    }
    let Some(Value::Array(reasons)) = evaluation.get("reasons") else {
        return false;
    };
    reasons
        .iter()
        .any(|reason| reason.get("code").and_then(Value::as_str) == Some(SAVED_PACKAGE_APPROVAL))
}

/// `list(value or [])` over a JSON value: a list, or empty for a falsy value.
fn list_or_empty(value: Option<&Value>) -> Result<Vec<Value>, AdvisoryMergePayloadInvalid> {
    match value {
        None | Some(Value::Null) | Some(Value::Bool(false)) => Ok(Vec::new()),
        Some(Value::Array(items)) => Ok(items.clone()),
        Some(Value::String(text)) if text.is_empty() => Ok(Vec::new()),
        Some(Value::Object(map)) if map.is_empty() => Ok(Vec::new()),
        _ => Err(AdvisoryMergePayloadInvalid),
    }
}

fn append_missing(target: &mut Vec<Value>, items: &[Value]) {
    for item in items {
        if !target.contains(item) {
            target.push(item.clone());
        }
    }
}

#[cfg(test)]
#[path = "advisory_merge_tests.rs"]
mod tests;

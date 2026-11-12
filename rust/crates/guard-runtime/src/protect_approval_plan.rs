//! `protect_approval_plan` runner-authority kind: what a package-protect
//! response queues for approval. Ported from `cli/protect_approvals.py`
//! (`_should_queue_local_protect_approval`'s policy check,
//! `_protect_request_artifact`, `_protect_approval_item`,
//! `_protect_approval_action_envelope`, `_protect_target_labels`,
//! `_protect_payload_harness`, `_protect_display_harness`,
//! `_protect_policy_action`, `_protect_policy_actions_disagree`,
//! `_protect_review_reason_code` and `_protect_has_reason_code`).
//!
//! Python ships the response's `request`, `receipt`, `verdict` and
//! `supply_chain_evaluation` members (`null` when absent) and answers:
//!
//! - `harness` and `display_harness`, the harness the request is filed under
//!   and the one its copy names;
//! - `artifact`, the request artifact's own fields, or `null` without a
//!   receipt artifact id;
//! - `policy_action`, the most restrictive of the verdict, the supply-chain
//!   evaluation and the receipt's action envelope, or `null`;
//! - `queue`, whether that action asks for an approval this response did not
//!   already settle with a saved package block;
//! - `review_reason_code`, the reason a review names;
//! - `item`, the approval item's fields, or `null` when the response cannot
//!   be approved. Its `envelope` names the action-envelope keys to drop and
//!   the ones to set to the policy action, so the caller keeps the envelope's
//!   own key order.
//!
//! The caller still checks the environment, copies the request's lists and
//! package context, builds the decision and queues the request.

use guard_command::action_lattice::{normalize_guard_action, normalize_guard_action_result};
use guard_command::effect_decision::GuardAction;
use serde_json::{json, Map, Value};

use crate::daemon_lifecycle_text::py_strip;
use crate::local_cli_identify::shlex_quote;
use crate::runner_authority_op::{KindResult, ERR_INVALID};

const KEYS: [&str; 4] = ["request", "receipt", "verdict", "supply_chain_evaluation"];
/// Guard Cloud could not give a package verdict; a review carrying one of
/// these is not about the package.
const CLOUD_FAILURE_REASON_CODES: [&str; 4] = [
    "cloud_auth_error",
    "cloud_validation_error",
    "cloud_http_error",
    "cloud_timeout",
];
const ENVELOPE_ACTION_KEYS: [&str; 4] = [
    "policy_action",
    "policyAction",
    "pre_execution_result",
    "preExecutionResult",
];

/// The response members the plan reads.
struct Response<'a> {
    request: Option<&'a Map<String, Value>>,
    receipt: Option<&'a Map<String, Value>>,
    verdict: Option<&'a Map<String, Value>>,
    evaluation: Option<&'a Map<String, Value>>,
}

pub(crate) fn dispatch(args: &Value) -> KindResult {
    let fields = args.as_object().ok_or(ERR_INVALID)?;
    if fields.len() != KEYS.len() || !KEYS.iter().all(|key| fields.contains_key(*key)) {
        return Err(ERR_INVALID);
    }
    let response = Response {
        request: fields["request"].as_object(),
        receipt: fields["receipt"].as_object(),
        verdict: fields["verdict"].as_object(),
        evaluation: fields["supply_chain_evaluation"].as_object(),
    };
    let harness = payload_harness(&response);
    let display_harness = response
        .request
        .and_then(|request| first_text(request, &["package_manager", "harness", "executor"]))
        .unwrap_or_else(|| harness.clone());
    let policy_action = policy_action(&response);
    let queue = matches!(
        policy_action,
        Some(GuardAction::Review | GuardAction::RequireReapproval)
    ) && !has_reason_code(&response, "saved_package_block");
    let cloud_unavailable = CLOUD_FAILURE_REASON_CODES
        .iter()
        .any(|code| has_reason_code(&response, code));
    Ok(json!({
        "harness": harness,
        "display_harness": display_harness,
        "artifact": request_artifact(&response),
        "policy_action": policy_action.map(GuardAction::as_str),
        "queue": queue,
        "review_reason_code": if cloud_unavailable {
            "native_package_cloud_unavailable"
        } else {
            "native_package_review"
        },
        "item": policy_action.map_or(Value::Null, |action| approval_item(&response, action)),
    }))
}

/// `_protect_payload_harness`.
fn payload_harness(response: &Response<'_>) -> String {
    response
        .request
        .and_then(|request| first_text(request, &["harness", "package_manager", "executor"]))
        .or_else(|| {
            response
                .receipt
                .and_then(|receipt| optional_text(receipt.get("harness")))
        })
        .unwrap_or_else(|| "guard-cli".to_owned())
}

/// `_protect_request_artifact`, without the lists and paths the caller copies.
fn request_artifact(response: &Response<'_>) -> Value {
    let (Some(receipt), Some(request)) = (response.receipt, response.request) else {
        return Value::Null;
    };
    let Some(artifact_id) = optional_text(receipt.get("artifact_id")) else {
        return Value::Null;
    };
    let redacted_command = optional_text(request.get("redacted_command")).or_else(|| {
        let Some(Value::Array(tokens)) = request.get("command") else {
            return None;
        };
        let parts: Vec<String> = tokens
            .iter()
            .filter_map(Value::as_str)
            .map(shlex_quote)
            .collect();
        (!parts.is_empty()).then(|| parts.join(" "))
    });
    json!({
        "name": optional_text(receipt.get("artifact_name")).unwrap_or_else(|| artifact_id.clone()),
        "artifact_id": artifact_id,
        "source_scope": optional_text(receipt.get("source_scope"))
            .unwrap_or_else(|| "project".to_owned()),
        "package_manager": first_text(request, &["package_manager", "executor"])
            .unwrap_or_else(|| "package".to_owned()),
        "intent_kind": optional_text(request.get("install_kind"))
            .unwrap_or_else(|| "install".to_owned()),
        "redacted_command": redacted_command,
    })
}

/// `_protect_approval_item`, without the decision, the package context and
/// the artifact fields the caller already holds.
fn approval_item(response: &Response<'_>, action: GuardAction) -> Value {
    let (Some(evaluation), Some(receipt), Some(verdict)) =
        (response.evaluation, response.receipt, response.verdict)
    else {
        return Value::Null;
    };
    if !matches!(
        action,
        GuardAction::Block | GuardAction::Review | GuardAction::RequireReapproval
    ) {
        return Value::Null;
    }
    let (verdict_action, supply_action) = action_candidates(response);
    let user_copy = evaluation.get("user_copy").and_then(Value::as_object);
    let risk_summary = optional_text(verdict.get("reason"))
        .or_else(|| optional_text(evaluation.get("risk_summary")))
        .or_else(|| user_copy.and_then(|copy| optional_text(copy.get("summary"))));
    let decision_reason = risk_summary
        .clone()
        .unwrap_or_else(|| format!("package_supply_chain_{}", action.as_str().replace('-', "_")));
    // The item reads each reason's code as given, without trimming it.
    let reason_codes: Vec<&str> = reasons(response)
        .filter_map(|reason| reason.get("code").and_then(Value::as_str))
        .collect();
    let cloud_reason_code = CLOUD_FAILURE_REASON_CODES
        .into_iter()
        .find(|code| reason_codes.contains(code));
    json!({
        "changed_fields": target_labels(response),
        "risk_summary": risk_summary,
        "decision_reason": decision_reason,
        "cloud_reason_code": cloud_reason_code,
        "risk_signals": string_list(verdict.get("risk_signals")),
        "artifact_hash": optional_text(receipt.get("artifact_hash")),
        "actions_disagree": matches!(
            (verdict_action, supply_action),
            (Some(left), Some(right)) if left != right
        ),
        "envelope": envelope_plan(receipt.get("action_envelope_json"), action),
    })
}

/// `_protect_approval_action_envelope`: the keys to drop and the keys to set
/// to the policy action. An observe-mode envelope that observed another action
/// stays as it is.
fn envelope_plan(value: Option<&Value>, action: GuardAction) -> Value {
    let Some(Value::Object(envelope)) = value else {
        return Value::Null;
    };
    let mut dropped: Vec<&str> = Vec::new();
    if envelope.get("observe_mode") == Some(&Value::Bool(true)) {
        if canonical_action(envelope.get("observed_policy_action")) != Some(action) {
            return json!({ "drop": [], "set": [] });
        }
        dropped.extend(["observe_mode", "observed_policy_action"]);
    }
    let set: Vec<&str> = ENVELOPE_ACTION_KEYS
        .into_iter()
        .filter(|key| envelope.get(*key).is_some_and(|value| !value.is_null()))
        .collect();
    json!({ "drop": dropped, "set": set })
}

/// `_protect_policy_action_candidates`.
fn action_candidates(response: &Response<'_>) -> (Option<GuardAction>, Option<GuardAction>) {
    (
        response
            .verdict
            .and_then(|verdict| canonical_action(verdict.get("action"))),
        response
            .evaluation
            .and_then(|evaluation| canonical_action(evaluation.get("policy_action"))),
    )
}

/// `_protect_policy_action`: the most restrictive candidate, where an
/// unrecognized envelope action reads as `block`.
fn policy_action(response: &Response<'_>) -> Option<GuardAction> {
    let (verdict_action, supply_action) = action_candidates(response);
    let envelope = response
        .receipt
        .and_then(|receipt| receipt.get("action_envelope_json"))
        .and_then(Value::as_object);
    let envelope_actions = envelope.into_iter().flat_map(|envelope| {
        ENVELOPE_ACTION_KEYS
            .iter()
            .filter_map(move |key| envelope.get(*key).filter(|value| !value.is_null()))
            .map(|value| normalize_guard_action(value, GuardAction::Block))
    });
    [verdict_action, supply_action]
        .into_iter()
        .flatten()
        .chain(envelope_actions)
        .reduce(|action, candidate| {
            if candidate.severity() > action.severity() {
                candidate
            } else {
                action
            }
        })
}

/// `_normalize_protect_policy_action`: a trimmed canonical action name, with no
/// legacy alias.
fn canonical_action(value: Option<&Value>) -> Option<GuardAction> {
    let text = optional_text(value)?;
    if text == "ask" {
        return None;
    }
    let normalization = normalize_guard_action_result(&Value::String(text), GuardAction::Block);
    normalization.recognized().then_some(normalization.action)
}

/// `_protect_has_reason_code`: a reason whose trimmed code matches.
fn has_reason_code(response: &Response<'_>, code: &str) -> bool {
    reasons(response).any(|reason| optional_text(reason.get("code")).as_deref() == Some(code))
}

fn reasons<'a>(response: &Response<'a>) -> impl Iterator<Item = &'a Map<String, Value>> {
    response
        .evaluation
        .and_then(|evaluation| evaluation.get("reasons"))
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_object)
}

/// `_protect_target_labels`: each target's package name or raw spec, once.
fn target_labels(response: &Response<'_>) -> Vec<String> {
    let targets = response
        .request
        .and_then(|request| request.get("targets"))
        .and_then(Value::as_array);
    let mut labels: Vec<String> = Vec::new();
    for target in targets.into_iter().flatten().filter_map(Value::as_object) {
        let label = optional_text(target.get("package_name"))
            .or_else(|| optional_text(target.get("raw_spec")));
        if let Some(label) = label {
            if !labels.contains(&label) {
                labels.push(label);
            }
        }
    }
    labels
}

fn first_text(fields: &Map<String, Value>, keys: &[&str]) -> Option<String> {
    keys.iter().find_map(|key| optional_text(fields.get(*key)))
}

/// `_optional_string`: a trimmed, non-empty string.
fn optional_text(value: Option<&Value>) -> Option<String> {
    let text = py_strip(value?.as_str()?);
    (!text.is_empty()).then(|| text.to_owned())
}

/// `_string_list`: the list's trimmed, non-empty strings.
fn string_list(value: Option<&Value>) -> Vec<String> {
    let Some(Value::Array(items)) = value else {
        return Vec::new();
    };
    items
        .iter()
        .filter_map(|item| optional_text(Some(item)))
        .collect()
}

#[cfg(test)]
#[path = "protect_approval_plan_tests.rs"]
mod tests;

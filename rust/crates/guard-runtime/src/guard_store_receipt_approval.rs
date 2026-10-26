//! Linked-approval action authority for receipts.
//!
//! A receipt linked to an approval request composes the request lifecycle into
//! its action: a pending request contributes its cross-checked surfaces, a
//! resolved one only its exact allow/block resolution, and anything malformed
//! fails closed to `require-reapproval`.

use guard_contracts::{normalize_guard_action_result, GuardAction};
use serde_json::{Map, Value};

use crate::cloud_request_text::py_eq;
use crate::guard_store_db::{Row, StoreResult};
use crate::guard_store_receipt_decision::{
    action_value, aliases_conflict, canonical_receipt_decision, most_restrictive, normalized,
    present, unknown_action_fields, DECISION_ACTION_FIELDS, ENVELOPE_ACTION_FIELDS, FAIL_CLOSED,
    PRODUCT_ACTIONS,
};

fn product_action(action: GuardAction) -> &'static str {
    match action {
        GuardAction::Allow => "allow",
        GuardAction::Warn => "warn",
        GuardAction::Block => "block",
        _ => "ask",
    }
}

fn product_floor(action: Option<&str>) -> GuardAction {
    match action {
        Some("allow") => GuardAction::Allow,
        Some("warn") => GuardAction::Warn,
        Some("block") => GuardAction::Block,
        _ => FAIL_CLOSED,
    }
}

struct ApprovalDecision {
    policy: GuardAction,
    /// Only the action-bearing projection of the canonical DecisionV2 payload.
    v2: Value,
    contract_error: bool,
}

/// `canonical_approval_decision`, restricted to the action it projects: the
/// resulting queue action and the guard/product action pair of its DecisionV2.
fn canonical_approval_decision(policy_action: &Value, decision_v2: &Value) -> ApprovalDecision {
    let normalization = normalize_guard_action_result(policy_action, FAIL_CLOSED);
    let policy = normalization.action;
    let raw = decision_v2.as_object();
    let invalid_payload = !decision_v2.is_null() && raw.is_none();
    let unknown = raw.map_or_else(Vec::new, |map| {
        unknown_action_fields(map, &DECISION_ACTION_FIELDS)
    });
    let hidden: Vec<GuardAction> = raw.map_or_else(Vec::new, |map| {
        unknown
            .iter()
            .map(|key| normalized(map.get(key).unwrap_or(&Value::Null)))
            .collect()
    });
    let guard_action = raw
        .and_then(|map| present(map, "guard_action"))
        .map(|value| normalize_guard_action_result(value, FAIL_CLOSED));
    let invalid_guard = guard_action.as_ref().is_some_and(|n| !n.recognized());
    let contradictory_guard = guard_action
        .as_ref()
        .is_some_and(|n| n.recognized() && n.action != policy);
    let product = raw.and_then(|map| present(map, "action"));
    let invalid_product = product.is_some_and(|value| {
        value
            .as_str()
            .is_none_or(|text| !PRODUCT_ACTIONS.contains(&text))
    });
    let product_text = product.and_then(Value::as_str);
    let contradictory = product_text
        .is_some_and(|text| PRODUCT_ACTIONS.contains(&text) && text != product_action(policy));
    let mut contract_error = !normalization.recognized();
    let mut projected = policy;
    if invalid_payload || invalid_guard || invalid_product || !unknown.is_empty() {
        contract_error = true;
        let mut all = vec![projected, FAIL_CLOSED];
        all.extend(hidden);
        projected = most_restrictive(&all);
    } else if contradictory_guard || contradictory {
        contract_error = true;
        let floor = guard_action
            .as_ref()
            .filter(|n| n.recognized())
            .map_or(FAIL_CLOSED, |n| n.action);
        let candidate = if product_text == Some("allow")
            || product_text == Some("warn")
            || product_text == Some("block")
        {
            product_floor(product_text)
        } else {
            FAIL_CLOSED
        };
        projected = most_restrictive(&[projected, floor, candidate]);
    }
    let mut v2 = Map::new();
    v2.insert("guard_action".to_owned(), action_value(projected));
    v2.insert(
        "action".to_owned(),
        Value::String(product_action(projected).to_owned()),
    );
    ApprovalDecision {
        policy: projected,
        v2: Value::Object(v2),
        contract_error,
    }
}

pub(crate) struct ApprovalSurfaces {
    pub(crate) policy: GuardAction,
    pub(crate) envelope: Option<Map<String, Value>>,
    pub(crate) contract_error: bool,
}

/// `canonical_approval_surfaces` (non-rejecting form): cross-check the approval
/// action, product decision and action envelope.
fn canonical_approval_surfaces(
    policy_action: &Value,
    decision_v2: &Value,
    envelope_json: &Value,
) -> StoreResult<ApprovalSurfaces> {
    let decision = canonical_approval_decision(policy_action, decision_v2);
    let envelope =
        canonical_receipt_decision(&action_value(decision.policy), envelope_json, false)?;
    let final_decision = canonical_approval_decision(&action_value(envelope.policy), &decision.v2);
    let final_envelope = canonical_receipt_decision(
        &action_value(final_decision.policy),
        &envelope.envelope_value(),
        false,
    )?;
    Ok(ApprovalSurfaces {
        policy: final_decision.policy,
        contract_error: decision.contract_error
            || envelope.contract_error
            || final_decision.contract_error
            || final_envelope.contract_error,
        envelope: final_envelope.envelope,
    })
}

/// `CanonicalLinkedApprovalAuthority`.
pub(crate) struct LinkedAuthority {
    pub(crate) policy: Option<GuardAction>,
    pub(crate) envelope: Option<Map<String, Value>>,
    pub(crate) contract_error: bool,
}

impl LinkedAuthority {
    fn none() -> Self {
        Self {
            policy: None,
            envelope: None,
            contract_error: false,
        }
    }

    fn invalid(policy: GuardAction) -> Self {
        Self {
            policy: Some(policy),
            envelope: None,
            contract_error: true,
        }
    }
}

/// `_json_mapping_or_original`.
fn json_mapping_or_original(value: &Value) -> Value {
    let Value::String(text) = value else {
        return value.clone();
    };
    match serde_json::from_str::<Value>(text) {
        Ok(parsed @ Value::Object(_)) => parsed,
        _ => value.clone(),
    }
}

/// `_resolved_approval_envelope`: keep historical metadata, drop stale action
/// authority.
fn resolved_approval_envelope(
    resolution: GuardAction,
    envelope: Option<Map<String, Value>>,
) -> StoreResult<(Option<Map<String, Value>>, bool)> {
    let Some(mut envelope) = envelope else {
        return Ok((None, false));
    };
    let mut contract_error = false;
    for key in unknown_action_fields(&envelope, &ENVELOPE_ACTION_FIELDS) {
        envelope.remove(&key);
        contract_error = true;
    }
    for (snake, camel) in [
        ("action_id", "actionId"),
        ("action_type", "actionType"),
        ("observed_policy_action", "observedPolicyAction"),
    ] {
        if aliases_conflict(&envelope, snake, camel) {
            envelope.remove(camel);
            contract_error = true;
        }
    }
    for key in [
        "policy_action",
        "policyAction",
        "pre_execution_result",
        "preExecutionResult",
    ] {
        if envelope.contains_key(key) {
            envelope.insert(key.to_owned(), action_value(resolution));
        }
    }
    let canonical =
        canonical_receipt_decision(&action_value(resolution), &Value::Object(envelope), false)?;
    Ok((
        canonical.envelope,
        contract_error || canonical.contract_error,
    ))
}

/// The persisted columns every receipt-action derivation reads. Missing
/// columns read as SQL NULL.
pub(crate) struct ActionInputs {
    pub(crate) policy_decision: Value,
    pub(crate) envelope_full: Value,
    pub(crate) envelope_redacted: Value,
    pub(crate) approval_request_id: Value,
    pub(crate) linked_request_id: Value,
    pub(crate) approval_status: Value,
    pub(crate) resolution_action: Value,
    pub(crate) resolved_at: Value,
    pub(crate) approval_policy_action: Value,
    pub(crate) decision_v2_json: Value,
    pub(crate) approval_envelope_json: Value,
}

impl ActionInputs {
    pub(crate) fn from_row(row: &Row) -> Self {
        let cell = |name: &str| row.get(name).cloned().unwrap_or(Value::Null);
        Self {
            policy_decision: cell("policy_decision"),
            envelope_full: cell("envelope_full_json"),
            envelope_redacted: cell("envelope_redacted_json"),
            approval_request_id: cell("approval_request_id"),
            linked_request_id: cell("linked_approval_request_id"),
            approval_status: cell("approval_status"),
            resolution_action: cell("approval_resolution_action"),
            resolved_at: cell("approval_resolved_at"),
            approval_policy_action: cell("approval_policy_action"),
            decision_v2_json: cell("approval_decision_v2_json"),
            approval_envelope_json: cell("approval_envelope_json"),
        }
    }

    pub(crate) fn linked_authority(&self) -> StoreResult<LinkedAuthority> {
        canonical_linked_approval_authority(self)
    }
}

/// `canonical_linked_approval_authority`: a linked approval row never revives
/// stale request authority. A missing local row is lineage-only compatibility;
/// a present malformed lifecycle fails closed; a resolved request contributes
/// only its exact final allow/block resolution.
fn canonical_linked_approval_authority(inputs: &ActionInputs) -> StoreResult<LinkedAuthority> {
    if inputs.approval_request_id.is_null() || inputs.linked_request_id.is_null() {
        return Ok(LinkedAuthority::none());
    }
    if !py_eq(&inputs.linked_request_id, &inputs.approval_request_id) {
        return Ok(LinkedAuthority::invalid(FAIL_CLOSED));
    }
    let pre = canonical_approval_surfaces(
        &inputs.approval_policy_action,
        &json_mapping_or_original(&inputs.decision_v2_json),
        &json_mapping_or_original(&inputs.approval_envelope_json),
    )?;
    let resolution_text = inputs.resolution_action.as_str();
    let resolution_candidate = match resolution_text {
        Some("allow") => Some(GuardAction::Allow),
        Some("block") => Some(GuardAction::Block),
        _ => None,
    };
    let mut invalid_candidates = vec![FAIL_CLOSED, pre.policy];
    if !inputs.resolution_action.is_null() {
        invalid_candidates.push(normalized(&inputs.resolution_action));
    }
    let invalid_action = most_restrictive(&invalid_candidates);
    match inputs.approval_status.as_str() {
        Some("pending") => {
            if !inputs.resolution_action.is_null() || !inputs.resolved_at.is_null() {
                return Ok(LinkedAuthority::invalid(invalid_action));
            }
            Ok(LinkedAuthority {
                policy: Some(pre.policy),
                envelope: pre.envelope,
                contract_error: pre.contract_error,
            })
        }
        Some("resolved") => {
            let resolved_at_set = inputs
                .resolved_at
                .as_str()
                .is_some_and(|text| !crate::guard_store_json::py_strip(text).is_empty());
            let Some(candidate) = resolution_candidate else {
                return Ok(LinkedAuthority::invalid(invalid_action));
            };
            if pre.contract_error
                || matches!(
                    pre.policy,
                    GuardAction::Block | GuardAction::SandboxRequired
                )
                || !resolved_at_set
            {
                return Ok(LinkedAuthority::invalid(invalid_action));
            }
            let (envelope, contract_error) = resolved_approval_envelope(candidate, pre.envelope)?;
            Ok(LinkedAuthority {
                policy: Some(candidate),
                envelope,
                contract_error,
            })
        }
        _ => Ok(LinkedAuthority::invalid(invalid_action)),
    }
}

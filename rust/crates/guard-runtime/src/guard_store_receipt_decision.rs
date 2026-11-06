//! Receipt and linked-approval action authority.
//!
//! Every receipt read, write and rollup derives one canonical action from the
//! stored receipt decision, its two stored action envelopes and the linked
//! approval request. The projection only ever moves toward the more
//! restrictive action; a malformed or contradictory surface fails closed to
//! `require-reapproval`.

use guard_contracts::{
    is_action_bearing_key, normalize_guard_action_result, GuardAction,
    AUTHORITATIVE_DECISION_INCONSISTENT,
};
use serde_json::{Map, Value};

use crate::cloud_request_text::py_eq;
use crate::guard_store_db::{value_error, Row, StoreResult};
use crate::guard_store_receipt_approval::{ActionInputs, LinkedAuthority};

pub(crate) const FAIL_CLOSED: GuardAction = GuardAction::RequireReapproval;

/// Envelope keys that legitimately carry an action and are synchronized.
pub(crate) const ENVELOPE_ACTION_FIELDS: [&str; 10] = [
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
];
pub(crate) const ALIAS_PAIRS: [(&str, &str); 5] = [
    ("action_id", "actionId"),
    ("action_type", "actionType"),
    ("policy_action", "policyAction"),
    ("pre_execution_result", "preExecutionResult"),
    ("observed_policy_action", "observedPolicyAction"),
];
pub(crate) const DECISION_ACTION_FIELDS: [&str; 2] = ["action", "guard_action"];
pub(crate) const PRODUCT_ACTIONS: [&str; 4] = ["allow", "warn", "ask", "block"];

pub(crate) fn inconsistent<T>() -> StoreResult<T> {
    value_error(AUTHORITATIVE_DECISION_INCONSISTENT)
}

pub(crate) fn normalized(value: &Value) -> GuardAction {
    normalize_guard_action_result(value, FAIL_CLOSED).action
}

pub(crate) fn most_restrictive(actions: &[GuardAction]) -> GuardAction {
    actions
        .iter()
        .copied()
        .fold(actions[0], guard_contracts::most_restrictive_of)
}

pub(crate) fn action_value(action: GuardAction) -> Value {
    Value::String(action.as_str().to_owned())
}

pub(crate) fn present<'a>(map: &'a Map<String, Value>, key: &str) -> Option<&'a Value> {
    map.get(key).filter(|value| !value.is_null())
}

pub(crate) fn aliases_conflict(map: &Map<String, Value>, snake: &str, camel: &str) -> bool {
    match (map.get(snake), map.get(camel)) {
        (Some(left), Some(right)) => !py_eq(left, right),
        _ => false,
    }
}

pub(crate) fn unknown_action_fields(map: &Map<String, Value>, allowed: &[&str]) -> Vec<String> {
    map.keys()
        .filter(|key| is_action_bearing_key(key) && !allowed.contains(&key.as_str()))
        .cloned()
        .collect()
}

/// `canonical_receipt_decision` result.
pub(crate) struct ReceiptDecision {
    pub(crate) policy: GuardAction,
    pub(crate) envelope: Option<Map<String, Value>>,
    pub(crate) contract_error: bool,
}

impl ReceiptDecision {
    pub(crate) fn envelope_value(&self) -> Value {
        self.envelope.clone().map_or(Value::Null, Value::Object)
    }
}

/// `canonical_receipt_decision`: synchronize the final-action fields of one
/// receipt-owned envelope. `observed_policy_action` is Watch-only evidence: it
/// must be a recognized action but may differ from the final decision.
pub(crate) fn canonical_receipt_decision(
    policy_decision: &Value,
    envelope_json: &Value,
    reject_contradiction: bool,
) -> StoreResult<ReceiptDecision> {
    let normalization = normalize_guard_action_result(policy_decision, FAIL_CLOSED);
    let mut projected = normalization.action;
    let mut contract_error = !normalization.recognized();
    let mut envelope = envelope_json.as_object().cloned();
    let invalid_payload = !envelope_json.is_null() && envelope.is_none();
    let mut candidates: Vec<GuardAction> = Vec::new();
    let mut contradiction = false;
    let mut unknown_fields = Vec::new();
    if let Some(map) = &envelope {
        unknown_fields = unknown_action_fields(map, &ENVELOPE_ACTION_FIELDS);
        contradiction = ALIAS_PAIRS
            .iter()
            .any(|(snake, camel)| aliases_conflict(map, snake, camel));
        candidates.extend(
            unknown_fields
                .iter()
                .map(|key| normalized(map.get(key).unwrap_or(&Value::Null))),
        );
    }
    if !unknown_fields.is_empty() {
        contradiction = true;
        if let Some(map) = envelope.as_mut() {
            for key in &unknown_fields {
                map.remove(key);
            }
        }
    }
    if let Some(map) = &envelope {
        for (key, alias) in [
            ("policy_action", "policyAction"),
            ("pre_execution_result", "preExecutionResult"),
        ] {
            for field in [key, alias] {
                let Some(raw) = present(map, field) else {
                    continue;
                };
                let candidate = normalize_guard_action_result(raw, FAIL_CLOSED);
                candidates.push(candidate.action);
                if !candidate.recognized() || candidate.action != projected {
                    contradiction = true;
                }
            }
        }
        for field in ["observed_policy_action", "observedPolicyAction"] {
            if let Some(raw) = present(map, field) {
                if !normalize_guard_action_result(raw, FAIL_CLOSED).recognized() {
                    contradiction = true;
                }
            }
        }
    }
    if reject_contradiction && (invalid_payload || contradiction) {
        return inconsistent();
    }
    if invalid_payload {
        contract_error = true;
        projected = most_restrictive(&[projected, FAIL_CLOSED]);
    } else if contradiction {
        contract_error = true;
        let mut all = vec![projected, FAIL_CLOSED];
        all.extend(candidates);
        projected = most_restrictive(&all);
    }
    if let Some(map) = envelope.as_mut() {
        for key in [
            "policy_action",
            "pre_execution_result",
            "policyAction",
            "preExecutionResult",
        ] {
            if present(map, key).is_some() {
                map.insert(key.to_owned(), action_value(projected));
            }
        }
    }
    Ok(ReceiptDecision {
        policy: projected,
        envelope,
        contract_error,
    })
}

/// `_json_object`: a mapping, or the mapping a JSON text decodes to.
pub(crate) fn json_object(value: &Value) -> Option<Map<String, Value>> {
    match value {
        Value::Object(map) => Some(map.clone()),
        Value::String(text) => match serde_json::from_str::<Value>(text) {
            Ok(Value::Object(map)) => Some(map),
            _ => None,
        },
        _ => None,
    }
}

/// An envelope column as the canonicalizer's input: its decoded mapping, or
/// the raw stored value (which is then an invalid payload unless NULL).
pub(crate) fn envelope_input(raw: &Value) -> Value {
    json_object(raw).map_or_else(|| raw.clone(), Value::Object)
}

/// The three decisions every read derives before approval composition.
pub(crate) struct StoredChecks {
    pub(crate) stored: ReceiptDecision,
    pub(crate) full: ReceiptDecision,
    pub(crate) redacted: ReceiptDecision,
}

pub(crate) fn stored_checks(inputs: &ActionInputs) -> StoreResult<StoredChecks> {
    let stored = canonical_receipt_decision(&inputs.policy_decision, &Value::Null, false)?;
    let policy = action_value(stored.policy);
    let full = canonical_receipt_decision(&policy, &envelope_input(&inputs.envelope_full), false)?;
    let redacted =
        canonical_receipt_decision(&policy, &envelope_input(&inputs.envelope_redacted), false)?;
    Ok(StoredChecks {
        stored,
        full,
        redacted,
    })
}

pub(crate) fn compose(checks: &StoredChecks, approval: &LinkedAuthority) -> GuardAction {
    let mut actions = vec![
        checks.stored.policy,
        checks.full.policy,
        checks.redacted.policy,
    ];
    actions.extend(approval.policy);
    most_restrictive(&actions)
}

/// `canonical_receipt_rollup_action`: every persisted receipt authority
/// projected to the single action read APIs and rollups use.
pub(crate) fn canonical_rollup_action(inputs: &ActionInputs) -> StoreResult<GuardAction> {
    let checks = stored_checks(inputs)?;
    let approval = inputs.linked_authority()?;
    Ok(compose(&checks, &approval))
}

pub(crate) fn row_action(row: &Row) -> StoreResult<GuardAction> {
    canonical_rollup_action(&ActionInputs::from_row(row))
}

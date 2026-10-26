//! Explicit migrations for historical approval scope fixture expectations.

use guard_contracts::ApprovalScopeItemV1;
use serde_json::{json, Value};

use crate::approval_scope_contract::{contract, View};
use crate::approval_scope_material::scope_contract_digest;

const GUARD_CONTROL_ACTION_TYPES: [&str; 4] = [
    "guard_control",
    "guard-control",
    "guard_control_operation",
    "guard-control-operation",
];

/// Apply only the specified changes to recorded contracts: unavailable
/// delivery for unbound native reviews, and approvable Guard-control reviews.
/// All other permission expectations remain the historical fixture oracle.
pub(crate) fn upgrade_recorded_contract(item: &ApprovalScopeItemV1, want: &mut Value) {
    if upgrade_guard_control(item, want) {
        return;
    }
    let unbound_native = item
        .artifact_id
        .as_ref()
        .and_then(Value::as_str)
        .is_some_and(|id| id.contains(":native-pretool:"))
        && !item
            .artifact_hash
            .as_ref()
            .and_then(Value::as_str)
            .is_some_and(|hash| {
                crate::guard_store_native_review_consume::binding_pattern().is_match(hash)
            });
    if !unbound_native {
        return;
    }
    let restrictions = want["scope_restrictions"].as_array_mut().unwrap();
    if !restrictions.contains(&json!("retry_cannot_reuse_approval")) {
        restrictions.insert(1, json!("retry_cannot_reuse_approval"));
    }
    restrictions.retain(|reason| {
        reason != "workspace_allow_bound_to_project_and_action"
            && reason != "broad_allow_bound_to_exact_action"
    });
    let persistence = want["exact_action_persistence_eligible"].as_bool().unwrap();
    if persistence {
        want["allowed_scopes_by_action"]["allow"]
            .as_array_mut()
            .unwrap()
            .retain(|scope| scope == "artifact");
        want["recommended_scope_by_action"]["allow"] = if want["allowed_scopes_by_action"]["allow"]
            .as_array()
            .unwrap()
            .is_empty()
        {
            Value::Null
        } else {
            json!("artifact")
        };
    } else {
        want["allowed_scopes_by_action"]["allow"] = json!([]);
        want["recommended_scope_by_action"]["allow"] = Value::Null;
        let restrictions = want["scope_restrictions"].as_array_mut().unwrap();
        if !restrictions.contains(&json!("execution_binding_unavailable")) {
            restrictions.insert(2, json!("execution_binding_unavailable"));
        }
    }
    redigest(item, want);
}

/// Guard-control reviews offer Allow once and Always allow like any other
/// review (`docs/guard/approval-invariant.md`). A recorded Guard-control
/// review now expects the contract of the same request under an ordinary
/// action type, and a recorded terminal verdict reports `non_overridable`.
/// Returns whether the review migration replaced the whole contract.
fn upgrade_guard_control(item: &ApprovalScopeItemV1, want: &mut Value) -> bool {
    let Some(envelope) = item
        .action_envelope_json
        .as_ref()
        .and_then(Value::as_object)
    else {
        return false;
    };
    let guard_control = envelope
        .get("action_type")
        .and_then(Value::as_str)
        .is_some_and(|action_type| GUARD_CONTROL_ACTION_TYPES.contains(&action_type));
    if !guard_control {
        return false;
    }
    let review = matches!(
        item.policy_action.as_ref().and_then(Value::as_str),
        Some("review" | "require-reapproval")
    );
    if !review {
        if want["once_only_reason"] == json!("guard_control") {
            want["once_only_reason"] = json!("non_overridable");
        }
        // The rest of a terminal verdict's contract migrates as before.
        return false;
    }
    let mut ordinary = item.clone();
    let mut envelope = envelope.clone();
    envelope.insert("action_type".to_owned(), json!("shell"));
    ordinary.action_envelope_json = Some(Value::Object(envelope));
    let mut upgraded = super::contract_value(&contract(&View::new(&ordinary)));
    let object = upgraded.as_object_mut().unwrap();
    object.remove("execution_approval");
    object.remove("exact_context_token");
    *want = upgraded;
    redigest(item, want);
    true
}

fn redigest(item: &ApprovalScopeItemV1, want: &mut Value) {
    let persistence = want["exact_action_persistence_eligible"].as_bool().unwrap();
    let strings = |value: &Value| -> Vec<String> {
        value
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_str().unwrap().to_owned())
            .collect()
    };
    let blocks = strings(&want["allowed_scopes_by_action"]["block"]);
    let allows = strings(&want["allowed_scopes_by_action"]["allow"]);
    let restrictions = strings(&want["scope_restrictions"]);
    let reasons = strings(&want["task_capability_eligibility"]["reason_codes"]);
    want["scope_contract_digest"] = json!(scope_contract_digest(
        &View::new(item),
        &allows.iter().map(String::as_str).collect::<Vec<_>>(),
        &blocks.iter().map(String::as_str).collect::<Vec<_>>(),
        &restrictions.iter().map(String::as_str).collect::<Vec<_>>(),
        want["task_capability_eligibility"]["eligible"]
            .as_bool()
            .unwrap(),
        &reasons.iter().map(String::as_str).collect::<Vec<_>>(),
        persistence,
    ));
}

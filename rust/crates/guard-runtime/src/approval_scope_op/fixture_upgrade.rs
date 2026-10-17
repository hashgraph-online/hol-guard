//! Explicit migrations for historical approval scope fixture expectations.

use guard_contracts::ApprovalScopeItemV1;
use serde_json::{json, Value};

use crate::approval_scope_contract::View;
use crate::approval_scope_material::scope_contract_digest;

/// Apply only the specified unavailable-delivery change to recorded contracts.
/// All other permission expectations remain the historical fixture oracle.
pub(crate) fn upgrade_recorded_contract(item: &ApprovalScopeItemV1, want: &mut Value) {
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

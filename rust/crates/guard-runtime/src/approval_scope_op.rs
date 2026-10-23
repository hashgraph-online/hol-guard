//! `ApprovalScope` - resident op that derives the action-aware approval scope
//! contract of pending approval requests.
//!
//! Pure: the caller ships the narrowed request fields and the workspace it
//! resolved on its own filesystem; the resident returns, per request, the
//! allowed and blocked scopes, the recommended scopes, the restrictions, the
//! contract digest, the exact-action eligibility and the exact-action token.

use guard_contracts::{
    ApprovalScopeRequestV1, ApprovalScopeResultV1, APPROVAL_SCOPE_MAX_BYTES,
    APPROVAL_SCOPE_MAX_ITEMS, APPROVAL_SCOPE_RESULT_SCHEMA,
};
use serde_json::{json, Value};

use crate::approval_scope_contract::{contract, ScopeContract, View};
use crate::approval_scope_material::APPROVAL_SCOPE_CONTRACT_VERSION;
use crate::package_authority_op::request_digest_with_limit;

pub(crate) fn evaluate_approval_scope_request(
    request: &ApprovalScopeRequestV1,
    owner: Option<&crate::policy_store::PolicySnapshotStore>,
) -> Result<Vec<u8>, String> {
    let request_sha256 = request_digest_with_limit(request, APPROVAL_SCOPE_MAX_BYTES)
        .map_err(|_| "native_approval_scope_too_large".to_owned())?;
    let result = match owner {
        Some(owner) => evaluate_with_owner(request, Some(owner)),
        None => evaluate(request),
    };
    let (status, code, payload) = match result {
        Ok(payload) => ("ok".to_owned(), "ok".to_owned(), Some(payload)),
        Err(code) => ("error".to_owned(), code, None),
    };
    crate::encode_response(&ApprovalScopeResultV1 {
        schema: APPROVAL_SCOPE_RESULT_SCHEMA.to_owned(),
        request_id: request.request_id.clone(),
        request_sha256,
        status,
        code,
        payload,
    })
}

pub(crate) fn evaluate(request: &ApprovalScopeRequestV1) -> Result<Value, String> {
    evaluate_with_owner(request, None)
}

fn evaluate_with_owner(
    request: &ApprovalScopeRequestV1,
    owner: Option<&crate::policy_store::PolicySnapshotStore>,
) -> Result<Value, String> {
    if request.items.len() > APPROVAL_SCOPE_MAX_ITEMS {
        return Err("native_approval_scope_too_large".to_owned());
    }
    let items: Vec<Value> = request
        .items
        .iter()
        .map(|item| {
            let mut view = View::new(item);
            view.native_bash_owner_verified = owner.is_some_and(|store| {
                crate::native_bash_review_scope::owner_verified(item, store, None)
            });
            contract_value(&contract(&view))
        })
        .collect();
    Ok(json!({ "items": items }))
}

pub(crate) fn contract_value(contract: &ScopeContract) -> Value {
    json!({
        "scope_contract_version": APPROVAL_SCOPE_CONTRACT_VERSION,
        "scope_contract_digest": contract.digest,
        "allowed_scopes_by_action": {
            "allow": contract.allow_scopes,
            "block": contract.block_scopes,
        },
        "recommended_scope_by_action": {
            "allow": contract.recommended_allow,
            "block": contract.recommended_block,
        },
        "scope_restrictions": contract.restrictions,
        "task_capability_eligibility": {
            "eligible": contract.task_capability_eligible,
            "reason_codes": contract.task_capability_reason_codes,
        },
        "exact_action_persistence_eligible": contract.exact_action_persistence_eligible,
        "once_only_reason": contract.once_only_reason,
        "exact_context_token": contract.exact_context_token,
        "execution_approval": {
            "schema": "guard.execution-approval.v1",
            "can_record_decision": !contract.block_scopes.is_empty(),
            "can_run_once": !contract.allow_scopes.is_empty()
                && !contract.restrictions.contains(&"retry_cannot_reuse_approval"),
            "can_persist_exact_version": !contract.allow_scopes.is_empty()
                && contract.exact_action_persistence_eligible,
            "delivery_reason": if contract.restrictions.contains(&"retry_cannot_reuse_approval") {
                Some("execution_binding_unavailable")
            } else {
                None
            },
        },
    })
}

#[cfg(test)]
#[path = "approval_scope_vectors_tests.rs"]
mod vectors_tests;

#[cfg(test)]
pub(crate) mod fixture_upgrade;

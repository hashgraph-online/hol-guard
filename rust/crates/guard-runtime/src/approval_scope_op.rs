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
) -> Result<Vec<u8>, String> {
    let request_sha256 = request_digest_with_limit(request, APPROVAL_SCOPE_MAX_BYTES)
        .map_err(|_| "native_approval_scope_too_large".to_owned())?;
    let (status, code, payload) = match evaluate(request) {
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
    if request.items.len() > APPROVAL_SCOPE_MAX_ITEMS {
        return Err("native_approval_scope_too_large".to_owned());
    }
    let items: Vec<Value> = request
        .items
        .iter()
        .map(|item| contract_value(&contract(&View::new(item))))
        .collect();
    Ok(json!({ "items": items }))
}

fn contract_value(contract: &ScopeContract) -> Value {
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
    })
}

#[cfg(test)]
#[path = "approval_scope_vectors_tests.rs"]
mod vectors_tests;

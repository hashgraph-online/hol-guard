//! `ApprovalPersistSelect` - resident op that decides whether one approval
//! may be remembered and whether the action it allows can be executed.
//!
//! Faithful port of the two eligibility gates in
//! `approvals.apply_approval_resolution`. The Python code read the scope
//! contract itself to decide three things: a narrowed selection is never
//! remembered, a remembered artifact decision needs the request to be
//! exact-action persistable (and a client that read no contract gets its
//! "remember" dropped rather than honoured), and an `allow` the request
//! cannot bind to an execution is refused instead of recorded. All three
//! read the contract, so they move here with it.
//!
//! The caller never supplies the contract. It ships the request and the
//! scope `ApprovalScopeSelect` applied, and the resident derives the
//! contract with the same code `ApprovalScope` publishes, so a caller cannot
//! make a decision persistable by claiming a contract the request does not
//! have. Each reason code is the message the Python function raised.

use guard_contracts::{
    ApprovalPersistSelectRequestV1, ApprovalPersistSelectResultV1,
    APPROVAL_PERSIST_SELECT_MAX_BYTES, APPROVAL_PERSIST_SELECT_RESULT_SCHEMA,
};
use serde_json::{json, Value};

use crate::approval_scope_contract::{contract, ScopeContract, View};
use crate::approval_scope_material::APPROVAL_SCOPE_CONTRACT_VERSION;
use crate::approval_scope_op::contract_value;
use crate::package_authority_op::request_digest_with_limit;

/// `models.DECISION_SCOPE_VALUES`.
const DECISION_SCOPE_VALUES: &[&str] = &["global", "harness", "workspace", "artifact", "publisher"];
/// `approval_scope_support.RETRY_CANNOT_REUSE_APPROVAL`.
const RETRY_CANNOT_REUSE_APPROVAL: &str = "retry_cannot_reuse_approval";

pub(crate) fn evaluate_approval_persist_select_request(
    request: &ApprovalPersistSelectRequestV1,
    owner: Option<&crate::policy_store::PolicySnapshotStore>,
) -> Result<Vec<u8>, String> {
    let request_sha256 = request_digest_with_limit(request, APPROVAL_PERSIST_SELECT_MAX_BYTES)
        .map_err(|_| "native_approval_persist_select_too_large".to_owned())?;
    let payload = evaluate_with_owner(request, owner);
    crate::encode_response(&ApprovalPersistSelectResultV1 {
        schema: APPROVAL_PERSIST_SELECT_RESULT_SCHEMA.to_owned(),
        request_id: request.request_id.clone(),
        request_sha256,
        status: "ok".to_owned(),
        code: "ok".to_owned(),
        payload: Some(payload),
    })
}

#[cfg(test)]
pub(crate) fn evaluate(request: &ApprovalPersistSelectRequestV1) -> Value {
    evaluate_with_owner(request, None)
}

fn evaluate_with_owner(
    request: &ApprovalPersistSelectRequestV1,
    owner: Option<&crate::policy_store::PolicySnapshotStore>,
) -> Value {
    let action = match request.action.as_str() {
        "allow" => "allow",
        "block" => "block",
        _ => return refused("unsupported_resolution_action", None),
    };
    if !DECISION_SCOPE_VALUES.contains(&request.applied_scope.as_str()) {
        return refused("unsupported_approval_scope", None);
    }

    let mut view = View::new(&request.item);
    view.native_bash_owner_verified = owner.is_some_and(|store| {
        crate::native_bash_review_scope::owner_verified(&request.item, store, None)
    });
    let derived = contract(&view);
    match (
        request.contract_version.as_deref(),
        request.contract_digest.as_deref(),
    ) {
        (Some(version), Some(digest)) => {
            if version != APPROVAL_SCOPE_CONTRACT_VERSION || digest != derived.digest {
                return refused("stale_scope_contract", Some(&derived));
            }
        }
        (None, None) => {}
        _ => return refused("incomplete_scope_contract", Some(&derived)),
    }

    // A narrowed selection covers less than the user chose, so remembering it
    // would save a decision nobody made.
    let mut persist_policy = request.persist_policy;
    if request.scope_narrowed {
        persist_policy = None;
    } else if request.applied_scope == "artifact" && persist_policy == Some(true) {
        if request.contract_version.is_some() {
            if !derived.exact_action_persistence_eligible {
                let reason = if action == "allow" {
                    "saved_allow_scope_ineligible"
                } else {
                    "saved_block_scope_ineligible"
                };
                return refused(reason, Some(&derived));
            }
        } else {
            // A client that read no contract cannot know whether this request
            // is persistable, so its "remember" is dropped, not honoured.
            persist_policy = None;
        }
    }

    // An allow has to end in an execution. A request with no retry binding can
    // still be allowed when the decision is saved against the exact action,
    // because the agent's next attempt matches the saved row instead of
    // reusing a one-time approval.
    if action == "allow"
        && !can_run_once(&derived)
        && !(request.applied_scope == "artifact"
            && persist_policy == Some(true)
            && can_persist_exact_version(&derived))
    {
        return refused("execution_binding_unavailable", Some(&derived));
    }

    json!({
        "outcome": "selected",
        "persist_policy": persist_policy,
        "contract": contract_value(&derived),
    })
}

/// `ApprovalScopeContract.can_run_once`.
fn can_run_once(derived: &ScopeContract) -> bool {
    !derived.allow_scopes.is_empty() && !derived.restrictions.contains(&RETRY_CANNOT_REUSE_APPROVAL)
}

/// `ApprovalScopeContract.can_persist_exact_version`.
fn can_persist_exact_version(derived: &ScopeContract) -> bool {
    !derived.allow_scopes.is_empty() && derived.exact_action_persistence_eligible
}

fn refused(reason: &str, derived: Option<&ScopeContract>) -> Value {
    json!({
        "outcome": "refused",
        "reason": reason,
        "contract": derived.map(contract_value),
    })
}

#[cfg(test)]
#[path = "approval_persist_select_op_tests.rs"]
mod tests;

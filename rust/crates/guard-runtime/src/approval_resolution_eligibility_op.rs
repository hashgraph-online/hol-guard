//! `ApprovalResolutionEligibility` - resident op answering whether stored
//! approval rows can accept a user resolution.
//!
//! Faithful port of `approval_resolution.approval_resolution_block_reason`.
//! The Python copy was a second oracle: the resident already applied the same
//! ladder to the rows its approval sweep projects, so a caller that reached
//! the Python helper could resolve a row the resident would have refused.
//! Both now answer from the one contract function.
//!
//! The op takes the whole batch a caller holds, because the callers ask inside
//! a write transaction and one round trip per row would put the resident on
//! the critical path of every sweep.

use guard_contracts::{
    approval_resolution_block_reason, ApprovalResolutionEligibilityRequestV1,
    ApprovalResolutionEligibilityResultV1, APPROVAL_RESOLUTION_ELIGIBILITY_MAX_BYTES,
    APPROVAL_RESOLUTION_ELIGIBILITY_MAX_ITEMS, APPROVAL_RESOLUTION_ELIGIBILITY_REQUEST_SCHEMA,
    APPROVAL_RESOLUTION_ELIGIBILITY_RESULT_SCHEMA,
};
use serde_json::{json, Value};

use crate::package_authority_op::request_digest_with_limit;

pub(crate) fn evaluate_approval_resolution_eligibility_request(
    request: &ApprovalResolutionEligibilityRequestV1,
) -> Result<Vec<u8>, String> {
    let request_sha256 =
        request_digest_with_limit(request, APPROVAL_RESOLUTION_ELIGIBILITY_MAX_BYTES)
            .map_err(|_| "native_approval_resolution_eligibility_too_large".to_owned())?;
    let (status, code, payload) = match refusal(request) {
        Some(code) => ("error", code, None),
        None => ("ok", "ok", Some(evaluate(request))),
    };
    crate::encode_response(&ApprovalResolutionEligibilityResultV1 {
        schema: APPROVAL_RESOLUTION_ELIGIBILITY_RESULT_SCHEMA.to_owned(),
        request_id: request.request_id.clone(),
        request_sha256,
        status: status.to_owned(),
        code: code.to_owned(),
        payload,
    })
}

/// The conditions the op refuses rather than answers.
fn refusal(request: &ApprovalResolutionEligibilityRequestV1) -> Option<&'static str> {
    // A request naming another contract is not this op's to answer: the field
    // is the sender's own statement of which request shape it built.
    if request.schema != APPROVAL_RESOLUTION_ELIGIBILITY_REQUEST_SCHEMA {
        return Some("native_approval_resolution_eligibility_schema_mismatch");
    }
    // A batch larger than the contract admits is refused rather than
    // answered: the caller asks again in batches the contract accepts.
    if request.items.len() > APPROVAL_RESOLUTION_ELIGIBILITY_MAX_ITEMS {
        return Some("native_approval_resolution_eligibility_too_many_items");
    }
    None
}

pub(crate) fn evaluate(request: &ApprovalResolutionEligibilityRequestV1) -> Value {
    let reasons: Vec<Value> = request
        .items
        .iter()
        .map(|item| {
            approval_resolution_block_reason(&item.decision_contract_error, &item.policy_action)
                .map_or(Value::Null, Value::from)
        })
        .collect();
    json!({ "reasons": reasons })
}

#[cfg(test)]
#[path = "approval_resolution_eligibility_op_tests.rs"]
mod tests;

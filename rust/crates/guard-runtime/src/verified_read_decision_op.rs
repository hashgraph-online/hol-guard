//! `VerifiedReadDecision` resident op: the verdict that lets a proven read run
//! silently.
//!
//! Wraps `guard_command::verified_read_decision` and binds the reply to the
//! request with `request_id` plus the canonical request digest. Any internal
//! failure is reported as an `error` status so the Python transport fails
//! closed; Python never composes the decision itself, because a second
//! composition is a second place a read can be declared allowed.

use std::panic::{catch_unwind, AssertUnwindSafe};

use guard_command::effect_decision::effect_decision_to_payload;
use guard_command::verified_read_decision::{
    verified_github_read_decision, verified_workspace_read_decision,
};
use guard_contracts::{
    write_canonical_json_with_limit, VerifiedReadDecisionKindV1, VerifiedReadDecisionRequestV1,
    VerifiedReadDecisionResultV1, VERIFIED_READ_DECISION_MAX_REQUEST_BYTES,
    VERIFIED_READ_DECISION_REQUEST_SCHEMA, VERIFIED_READ_DECISION_RESULT_SCHEMA,
};
use guard_policy_snapshot::digest_bytes;
use serde_json::Value;

fn canonical_request(request: &VerifiedReadDecisionRequestV1) -> Result<Vec<u8>, &'static str> {
    let material =
        serde_json::to_value(request).map_err(|_| "native_verified_read_decision_invalid")?;
    let mut canonical = Vec::with_capacity(512);
    write_canonical_json_with_limit(
        &material,
        &mut canonical,
        usize::MAX,
        "native_verified_read_decision_invalid",
    )
    .map_err(|_| "native_verified_read_decision_invalid")?;
    Ok(canonical)
}

fn decide(
    request: &VerifiedReadDecisionRequestV1,
    canonical_len: usize,
) -> Result<Value, &'static str> {
    if request.schema != VERIFIED_READ_DECISION_REQUEST_SCHEMA {
        return Err("native_verified_read_decision_schema_mismatch");
    }
    if canonical_len > VERIFIED_READ_DECISION_MAX_REQUEST_BYTES {
        return Err("native_verified_read_decision_request_too_large");
    }
    let digest = request.binding_digest.as_str();
    let decision = catch_unwind(AssertUnwindSafe(|| match &request.read {
        VerifiedReadDecisionKindV1::Workspace { operation_id } => {
            // The operation ref names the read this decision belongs to; an
            // empty id would attach the allow to no operation at all.
            if operation_id.is_empty() {
                return Err("native_verified_read_decision_invalid");
            }
            verified_workspace_read_decision(operation_id, digest)
                .map_err(|_| "native_verified_read_decision_invalid")
        }
        VerifiedReadDecisionKindV1::GithubPublicRead {} => verified_github_read_decision(digest)
            .map_err(|_| "native_verified_read_decision_invalid"),
    }))
    .map_err(|_| "native_verified_read_decision_failed")??;
    Ok(effect_decision_to_payload(&decision))
}

pub(crate) fn evaluate_verified_read_decision(
    request: &VerifiedReadDecisionRequestV1,
) -> Result<Vec<u8>, String> {
    let canonical = canonical_request(request).map_err(str::to_owned)?;
    let request_sha256 = digest_bytes(&canonical);
    let (status, code, decision) = match decide(request, canonical.len()) {
        Ok(decision) => ("ok", "ok", Some(decision)),
        Err(code) => ("error", code, None),
    };
    crate::encode_response(&VerifiedReadDecisionResultV1 {
        schema: VERIFIED_READ_DECISION_RESULT_SCHEMA.to_owned(),
        request_id: request.request_id.clone(),
        request_sha256,
        status: status.to_owned(),
        code: code.to_owned(),
        decision,
    })
}

#[cfg(test)]
#[path = "verified_read_decision_op_tests.rs"]
mod tests;

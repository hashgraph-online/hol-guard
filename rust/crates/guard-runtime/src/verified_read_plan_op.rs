//! `VerifiedReadPlan` resident op: which bounded read an admitted argv asks
//! for.
//!
//! Wraps `guard_command::verified_read_plan` and binds the reply to the
//! request with `request_id` plus the canonical request digest. A refusal and
//! an internal failure both come back as an `error` status, because the
//! executor treats either the same way: there is no plan, so the verified read
//! ends and the command goes back to ordinary review.

use std::panic::{catch_unwind, AssertUnwindSafe};

use guard_command::verified_read_plan::verified_read_plan;
use guard_contracts::{
    write_canonical_json_with_limit, VerifiedReadPlanRequestV1, VerifiedReadPlanResultV1,
    VerifiedReadPlanV1, VERIFIED_READ_PLAN_MAX_REQUEST_BYTES, VERIFIED_READ_PLAN_REQUEST_SCHEMA,
    VERIFIED_READ_PLAN_RESULT_SCHEMA,
};
use guard_policy_snapshot::digest_bytes;

fn canonical_request(request: &VerifiedReadPlanRequestV1) -> Result<Vec<u8>, &'static str> {
    let material =
        serde_json::to_value(request).map_err(|_| "native_verified_read_plan_invalid")?;
    let mut canonical = Vec::with_capacity(512);
    write_canonical_json_with_limit(
        &material,
        &mut canonical,
        usize::MAX,
        "native_verified_read_plan_invalid",
    )
    .map_err(|_| "native_verified_read_plan_invalid")?;
    Ok(canonical)
}

/// `Err` carries the wire code and, for a refusal, the rule that refused.
type PlanFailure = (&'static str, Option<String>);

fn plan(
    request: &VerifiedReadPlanRequestV1,
    canonical_len: usize,
) -> Result<VerifiedReadPlanV1, PlanFailure> {
    if request.schema != VERIFIED_READ_PLAN_REQUEST_SCHEMA {
        return Err(("native_verified_read_plan_schema_mismatch", None));
    }
    if canonical_len > VERIFIED_READ_PLAN_MAX_REQUEST_BYTES {
        return Err(("native_verified_read_plan_request_too_large", None));
    }
    catch_unwind(AssertUnwindSafe(|| verified_read_plan(&request.argv)))
        .map_err(|_| ("native_verified_read_plan_failed", None))?
        .map_err(|rule| ("native_verified_read_plan_refused", Some(rule.to_owned())))
}

pub(crate) fn evaluate_verified_read_plan(
    request: &VerifiedReadPlanRequestV1,
) -> Result<Vec<u8>, String> {
    let canonical = canonical_request(request).map_err(str::to_owned)?;
    let request_sha256 = digest_bytes(&canonical);
    let (status, code, detail, plan) = match plan(request, canonical.len()) {
        Ok(plan) => ("ok", "ok", None, Some(plan)),
        Err((code, detail)) => ("error", code, detail, None),
    };
    crate::encode_response(&VerifiedReadPlanResultV1 {
        schema: VERIFIED_READ_PLAN_RESULT_SCHEMA.to_owned(),
        request_id: request.request_id.clone(),
        request_sha256,
        status: status.to_owned(),
        code: code.to_owned(),
        detail,
        plan,
    })
}

#[cfg(test)]
#[path = "verified_read_plan_op_tests.rs"]
mod tests;

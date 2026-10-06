//! `ApprovalReuseDecide` — resident op for `evaluate_approval_reuse`.
//!
//! Pure composition lattice: the request carries the recomputed action, the
//! optional saved action, and the reuse-eligibility flags; the op normalizes
//! and composes them. No IO, no SQLite. The result is the
//! `ApprovalReuseDecision.to_evidence()` payload (a review-floor decision, not
//! execution authorization).

use guard_contracts::{
    ApprovalReuseRequestV1, ApprovalReuseResultV1, APPROVAL_REUSE_REQUEST_SCHEMA,
    APPROVAL_REUSE_RESULT_SCHEMA,
};
use guard_policy_snapshot::digest_bytes;

use super::context_digest_json::write_canonical_json_with_limit;

fn request_digest(request: &ApprovalReuseRequestV1) -> Result<String, &'static str> {
    let material = serde_json::to_value(request).map_err(|_| "native_approval_reuse_invalid")?;
    let mut bytes = Vec::new();
    write_canonical_json_with_limit(&material, &mut bytes, usize::MAX)
        .map_err(|_| "native_approval_reuse_invalid")?;
    Ok(format!("sha256:{}", digest_bytes(&bytes)))
}

pub(crate) fn evaluate_approval_reuse_request(
    request: &ApprovalReuseRequestV1,
) -> Result<Vec<u8>, String> {
    let request_sha256 = request_digest(request).map_err(str::to_owned)?;
    let result = evaluate(request);
    let (status, code, payload) = match result {
        Ok(payload) => ("ok".to_owned(), "ok".to_owned(), Some(payload)),
        Err(code) => ("error".to_owned(), code, None),
    };
    let result = ApprovalReuseResultV1 {
        schema: APPROVAL_REUSE_RESULT_SCHEMA.to_owned(),
        request_id: request.request_id.clone(),
        request_sha256,
        status,
        code,
        payload,
    };
    crate::encode_response(&result)
}

fn evaluate(request: &ApprovalReuseRequestV1) -> Result<serde_json::Value, String> {
    if request.schema != APPROVAL_REUSE_REQUEST_SCHEMA {
        return Err("native_approval_reuse_schema_mismatch".to_owned());
    }
    let decision = guard_command::approval_reuse::evaluate_approval_reuse(
        &request.current_action,
        request.saved_action.as_ref(),
        request.saved_decision_present,
        request.validation_reason.as_deref(),
        request.fresh_local_approval,
        request.durable_exact_approval,
    );
    serde_json::to_value(decision).map_err(|_| "native_approval_reuse_invalid".to_owned())
}

#[allow(dead_code)]
pub(crate) fn evaluate_approval_reuse_bytes(bytes: &[u8]) -> Result<Vec<u8>, String> {
    let value = crate::strict_json_value(bytes)?;
    let request: ApprovalReuseRequestV1 = crate::strict_json::from_value(value)
        .map_err(|_| "native_approval_reuse_invalid_json".to_owned())?;
    evaluate_approval_reuse_request(&request)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{json, Value};

    fn request_json(current: &str, saved: Value, sdp: Option<bool>, vr: Option<&str>) -> Value {
        json!({
            "operation": "approval_reuse_decide",
            "request": {
                "schema": APPROVAL_REUSE_REQUEST_SCHEMA,
                "request_id": "req-reuse",
                "current_action": current,
                "saved_action": saved,
                "saved_decision_present": sdp,
                "validation_reason": vr,
                "fresh_local_approval": false,
                "durable_exact_approval": false,
            }
        })
    }

    #[test]
    fn approval_reuse_op_decides_over_resident_transport() {
        // current=review + saved=allow -> accepted, should_claim.
        let out = crate::resident_protocol::evaluate_resident_bytes(
            request_json("review", json!("allow"), None, None)
                .to_string()
                .as_bytes(),
            None,
        )
        .expect("reuse op should return bytes");
        let v: Value = serde_json::from_slice(&out).unwrap();
        assert_eq!(v["status"], "ok", "op errored: {}", v["code"]);
        assert_eq!(v["schema"], APPROVAL_REUSE_RESULT_SCHEMA);
        assert_eq!(v["payload"]["reason_code"], "approval_reuse_accepted");
        assert_eq!(v["payload"]["status"], "accepted");
        assert_eq!(v["payload"]["should_claim"], true);

        // saved=block -> accepted saved_block.
        let out = crate::resident_protocol::evaluate_resident_bytes(
            request_json("review", json!("block"), None, None)
                .to_string()
                .as_bytes(),
            None,
        )
        .unwrap();
        let v: Value = serde_json::from_slice(&out).unwrap();
        assert_eq!(v["payload"]["reason_code"], "approval_reuse_saved_block");

        // no saved decision -> not-applicable.
        let out = crate::resident_protocol::evaluate_resident_bytes(
            request_json("allow", Value::Null, None, None)
                .to_string()
                .as_bytes(),
            None,
        )
        .unwrap();
        let v: Value = serde_json::from_slice(&out).unwrap();
        assert_eq!(
            v["payload"]["reason_code"],
            "approval_reuse_no_saved_decision"
        );
    }

    #[test]
    fn approval_reuse_op_rejects_bad_schema() {
        let mut req = request_json("review", json!("allow"), None, None);
        req["request"]["schema"] = json!("bogus");
        let out =
            crate::resident_protocol::evaluate_resident_bytes(req.to_string().as_bytes(), None)
                .unwrap();
        let v: Value = serde_json::from_slice(&out).unwrap();
        assert_eq!(v["status"], "error");
        assert_eq!(v["code"], "native_approval_reuse_schema_mismatch");
    }
}

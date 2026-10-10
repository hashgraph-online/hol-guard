//! `ApprovalProofDecide` — what a selected saved approval row proves.
//!
//! The Python store selects rows and persists claims; this op owns the
//! eligibility predicates that used to be duplicated in Python: the claim
//! disposition of an `allow`, exact fresh local tool approval, whether a claim
//! lookup outcome keeps a consumed claim usable, and whether a claimed row
//! still authorizes the post-claim review. Every query is pure and fails
//! closed: a malformed row never produces a proof.

use guard_contracts::{
    ApprovalProofQueryV1, ApprovalProofRequestV1, ApprovalProofResultV1,
    APPROVAL_PROOF_REQUEST_SCHEMA, APPROVAL_PROOF_RESULT_SCHEMA,
};
use serde_json::{json, Map, Value};

const APPROVAL_GATE_SOURCE: &str = "approval-gate";
const LOCAL_ONCE_SOURCE: &str = "approval-gate-once";
const NO_SAVED_DECISION: &str = "approval_reuse_no_saved_decision";
const REAPPROVAL_REQUIRED: &str = "approval_reuse_reapproval_required";

/// Row fields that make two lookups select the same saved authority row.
const IDENTITY_KEYS: [&str; 22] = [
    "action",
    "approval_id",
    "artifact_hash",
    "artifact_id",
    "decision_id",
    "expires_at",
    "harness",
    "integrity_enforcement",
    "integrity_generation",
    "integrity_key_id",
    "integrity_mode",
    "integrity_status",
    "integrity_version",
    "owner",
    "publisher",
    "reason",
    "request_id",
    "scope",
    "signed_at",
    "source",
    "updated_at",
    "workspace",
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Disposition {
    Consumed,
    Retained,
}

impl Disposition {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Consumed => "consumed",
            Self::Retained => "retained",
        }
    }

    pub(crate) fn parse(raw: Option<&str>) -> Option<Self> {
        match raw {
            Some("consumed") => Some(Self::Consumed),
            Some("retained") => Some(Self::Retained),
            _ => None,
        }
    }
}

pub(crate) struct Outcome {
    pub(crate) accepted: bool,
    pub(crate) disposition: Option<Disposition>,
}

impl Outcome {
    fn flag(accepted: bool) -> Self {
        Self {
            accepted,
            disposition: None,
        }
    }
}

pub(crate) fn evaluate_approval_proof_request(
    request: &ApprovalProofRequestV1,
) -> Result<Vec<u8>, String> {
    let request_sha256 = request_digest(request)?;
    if request.schema != APPROVAL_PROOF_REQUEST_SCHEMA {
        return Err("native_approval_proof_schema_mismatch".to_owned());
    }
    let outcome = decide(&request.query);
    crate::resident_protocol::encode_response(&ApprovalProofResultV1 {
        schema: APPROVAL_PROOF_RESULT_SCHEMA.to_owned(),
        request_id: request.request_id.clone(),
        request_sha256,
        status: "ok".to_owned(),
        code: "ok".to_owned(),
        payload: Some(json!({
            "accepted": outcome.accepted,
            "claim_disposition": outcome.disposition.map(Disposition::as_str),
        })),
    })
}

fn request_digest(request: &ApprovalProofRequestV1) -> Result<String, String> {
    let invalid = || "native_approval_proof_request_invalid".to_owned();
    let material = serde_json::to_value(request).map_err(|_| invalid())?;
    let mut bytes = Vec::new();
    crate::context_digest_json::write_canonical_json_with_limit(&material, &mut bytes, usize::MAX)
        .map_err(|_| invalid())?;
    Ok(format!(
        "sha256:{}",
        guard_policy_snapshot::digest_bytes(&bytes)
    ))
}

pub(crate) fn decide(query: &ApprovalProofQueryV1) -> Outcome {
    match query {
        ApprovalProofQueryV1::ClaimDisposition { decision } => {
            let disposition = claim_disposition(decision);
            Outcome {
                accepted: disposition.is_some(),
                disposition,
            }
        }
        ApprovalProofQueryV1::LookupPreservesClaim { reason_code } => {
            Outcome::flag(lookup_preserves_claim(reason_code.as_deref()))
        }
        ApprovalProofQueryV1::FreshToolApproval {
            decision,
            harness,
            artifact_id,
            artifact_hash,
        } => Outcome::flag(fresh_tool_approval(
            decision.as_ref(),
            harness,
            artifact_id,
            artifact_hash,
        )),
        ApprovalProofQueryV1::FreshClaimAllowsReapproval {
            claim_disposition,
            reason_code,
            decision,
            harness,
            artifact_id,
            artifact_hash,
        } => Outcome::flag(
            Disposition::parse(claim_disposition.as_deref()) == Some(Disposition::Consumed)
                && lookup_preserves_claim(reason_code.as_deref())
                && fresh_tool_approval(decision.as_ref(), harness, artifact_id, artifact_hash),
        ),
        ApprovalProofQueryV1::PostclaimReviewAuthorized {
            claim_disposition,
            claimed_decision,
            current_decision,
        } => Outcome::flag(postclaim_review_authorized(
            Disposition::parse(claim_disposition.as_deref()),
            claimed_decision.as_ref(),
            current_decision.as_ref(),
        )),
    }
}

/// Whether a claimed row still authorizes the post-claim review: a consumed
/// claim always does; a retained one only while the same row is still selected.
pub(crate) fn postclaim_review_authorized(
    disposition: Option<Disposition>,
    claimed: Option<&Map<String, Value>>,
    current: Option<&Map<String, Value>>,
) -> bool {
    match disposition {
        Some(Disposition::Consumed) => true,
        Some(Disposition::Retained) => match (claimed, current) {
            (Some(claimed), Some(current)) => decisions_match(claimed, current),
            _ => false,
        },
        None => false,
    }
}

fn text<'a>(row: &'a Map<String, Value>, key: &str) -> Option<&'a str> {
    row.get(key).and_then(Value::as_str)
}

fn non_empty_text<'a>(row: &'a Map<String, Value>, key: &str) -> Option<&'a str> {
    text(row, key).filter(|value| !value.is_empty())
}

/// An integer decision id: JSON numbers without a fraction; never a bool.
fn integer_id(row: &Map<String, Value>) -> Option<&Value> {
    row.get("decision_id")
        .filter(|value| value.as_i64().is_some() || value.as_u64().is_some())
}

/// What a successful claim does to this selected `allow`. Package local-once
/// approvals are reusable and stay; expiring `approval-gate` policy rows are
/// the only policy decisions the claim transaction deletes.
pub(crate) fn claim_disposition(decision: &Map<String, Value>) -> Option<Disposition> {
    if text(decision, "action") != Some("allow") {
        return None;
    }
    if non_empty_text(decision, "approval_id").is_some() {
        let artifact_id = non_empty_text(decision, "artifact_id")?;
        return Some(
            if crate::local_once_store::local_once_approval_is_reusable(artifact_id) {
                Disposition::Retained
            } else {
                Disposition::Consumed
            },
        );
    }
    integer_id(decision)?;
    let expiring = decision
        .get("expires_at")
        .is_some_and(|value| !value.is_null());
    Some(
        if text(decision, "source") == Some(APPROVAL_GATE_SOURCE) && expiring {
            Disposition::Consumed
        } else {
            Disposition::Retained
        },
    )
}

/// Consumption may expose no grant or an older allow requiring reapproval.
/// Neither grants new authority; integrity and context failures never pass.
pub(crate) fn lookup_preserves_claim(reason_code: Option<&str>) -> bool {
    matches!(
        reason_code,
        None | Some(NO_SAVED_DECISION) | Some(REAPPROVAL_REQUIRED)
    )
}

/// Shape-check exact proof only after validated lookup or atomic claim. This
/// is not integrity validation; retained policy cannot satisfy it.
pub(crate) fn fresh_tool_approval(
    decision: Option<&Map<String, Value>>,
    harness: &str,
    artifact_id: &str,
    artifact_hash: &str,
) -> bool {
    let Some(row) = decision else {
        return false;
    };
    let identified = match text(row, "source") {
        Some(LOCAL_ONCE_SOURCE) => non_empty_text(row, "approval_id").is_some(),
        Some(APPROVAL_GATE_SOURCE) => integer_id(row).is_some(),
        _ => false,
    };
    identified
        && text(row, "action") == Some("allow")
        && text(row, "scope") == Some("artifact")
        && text(row, "harness") == Some(harness)
        && text(row, "artifact_id") == Some(artifact_id)
        && text(row, "artifact_hash") == Some(artifact_hash)
        && text(row, "expires_at").is_some()
}

/// Whether two lookups selected the same saved authority row.
fn decisions_match(expected: &Map<String, Value>, current: &Map<String, Value>) -> bool {
    let by_approval_id = non_empty_text(expected, "approval_id")
        .is_some_and(|id| text(current, "approval_id") == Some(id));
    let by_decision_id = integer_id(expected)
        .is_some_and(|id| current.get("decision_id").is_some_and(|c| py_equal(c, id)));
    (by_approval_id || by_decision_id)
        && IDENTITY_KEYS.iter().all(|key| {
            py_equal(
                expected.get(*key).unwrap_or(&Value::Null),
                current.get(*key).unwrap_or(&Value::Null),
            )
        })
}

#[derive(PartialEq)]
enum Scalar {
    Int(i128),
    Float(f64),
}

fn scalar(value: &Value) -> Option<Scalar> {
    match value {
        Value::Bool(flag) => Some(Scalar::Int(i128::from(*flag))),
        Value::Number(number) => number
            .as_i64()
            .map(i128::from)
            .or_else(|| number.as_u64().map(i128::from))
            .map(Scalar::Int)
            .or_else(|| number.as_f64().map(Scalar::Float)),
        _ => None,
    }
}

/// Exact int/float equality as in Python: no rounding of the integer side.
fn int_equals_float(int: i128, float: f64) -> bool {
    // Below 2^127 a whole float converts to i128 without loss.
    float.is_finite() && float.fract() == 0.0 && float.abs() < 1.7e38 && float as i128 == int
}

/// Python `==` over decoded JSON: `True == 1 == 1.0`, containers recurse.
fn py_equal(left: &Value, right: &Value) -> bool {
    if let (Some(a), Some(b)) = (scalar(left), scalar(right)) {
        return match (a, b) {
            (Scalar::Int(a), Scalar::Int(b)) => a == b,
            (Scalar::Float(a), Scalar::Float(b)) => a == b,
            (Scalar::Int(a), Scalar::Float(b)) | (Scalar::Float(b), Scalar::Int(a)) => {
                int_equals_float(a, b)
            }
        };
    }
    match (left, right) {
        (Value::Null, Value::Null) => true,
        (Value::String(a), Value::String(b)) => a == b,
        (Value::Array(a), Value::Array(b)) => {
            a.len() == b.len() && a.iter().zip(b).all(|(x, y)| py_equal(x, y))
        }
        (Value::Object(a), Value::Object(b)) => {
            a.len() == b.len()
                && a.iter()
                    .all(|(key, x)| b.get(key).is_some_and(|y| py_equal(x, y)))
        }
        _ => false,
    }
}

#[cfg(test)]
#[path = "approval_proof_op_tests.rs"]
mod tests;

use super::*;

use guard_contracts::VerifiedReadSelectionV1;

fn request() -> VerifiedReadPlanRequestV1 {
    VerifiedReadPlanRequestV1 {
        schema: VERIFIED_READ_PLAN_REQUEST_SCHEMA.to_owned(),
        request_id: "req-1".to_owned(),
        argv: ["head", "-40", "src/main.py"]
            .iter()
            .map(|value| (*value).to_owned())
            .collect(),
    }
}

fn decode(request: &VerifiedReadPlanRequestV1) -> VerifiedReadPlanResultV1 {
    serde_json::from_slice(&evaluate_verified_read_plan(request).unwrap()).unwrap()
}

#[test]
fn an_admitted_read_comes_back_as_one_bounded_plan() {
    let result = decode(&request());
    assert_eq!(result.status, "ok");
    assert_eq!(result.code, "ok");
    assert_eq!(result.detail, None);
    let plan = result.plan.expect("plan");
    assert_eq!(plan.operation_id, "bounded-head");
    assert_eq!(plan.target.as_deref(), Some("src/main.py"));
    assert_eq!(
        plan.selection,
        VerifiedReadSelectionV1::LeadingLines { count: 40 }
    );
}

/// The digest binds the reply to the request Python sent, so it has to be the
/// one `_canonical_request_sha256` computes over the same dict.
#[test]
fn the_request_digest_matches_the_python_canonical_form() {
    assert_eq!(
        decode(&request()).request_sha256,
        "c77ab89c07ad7a613469cb505758094fa28efd541171d750469b7dfa85f0f419"
    );
}

#[test]
fn a_refused_argv_names_the_rule_and_carries_no_plan() {
    let refused = VerifiedReadPlanRequestV1 {
        argv: vec!["head".to_owned(), "-1001".to_owned(), "main.py".to_owned()],
        ..request()
    };
    let result = decode(&refused);
    assert_eq!(result.status, "error");
    assert_eq!(result.code, "native_verified_read_plan_refused");
    assert_eq!(
        result.detail.as_deref(),
        Some("line count exceeds the bound")
    );
    assert!(result.plan.is_none());
    assert_eq!(result.request_id, "req-1");
    assert_eq!(result.request_sha256.len(), 64);
}

#[test]
fn a_foreign_schema_fails_closed_and_still_binds_the_reply() {
    let mut request = request();
    request.schema = "guard-verified-read-plan-request.v0".to_owned();
    let result = decode(&request);
    assert_eq!(result.status, "error");
    assert_eq!(result.code, "native_verified_read_plan_schema_mismatch");
    assert_eq!(result.detail, None);
    assert!(result.plan.is_none());
    assert_eq!(result.request_sha256.len(), 64);
}

#[test]
fn an_oversized_request_fails_closed() {
    let request = VerifiedReadPlanRequestV1 {
        argv: vec![
            "head".to_owned(),
            "-5".to_owned(),
            "a".repeat(VERIFIED_READ_PLAN_MAX_REQUEST_BYTES + 1),
        ],
        ..request()
    };
    let result = decode(&request);
    assert_eq!(result.status, "error");
    assert_eq!(result.code, "native_verified_read_plan_request_too_large");
    assert!(result.plan.is_none());
}

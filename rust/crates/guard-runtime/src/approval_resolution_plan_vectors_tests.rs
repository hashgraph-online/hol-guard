//! Parity vectors recorded from the retired Python approval-resolution
//! derivation (`apply_approval_resolution` and its key helpers): every case
//! carries the narrowed wire request and the plan the Python produced.

use guard_contracts::{ApprovalResolutionPlanRequestV1, APPROVAL_RESOLUTION_PLAN_REQUEST_SCHEMA};
use serde_json::Value;

use super::evaluate;
use crate::store_vectors_support_tests::gunzip_json;

const VECTORS: &[u8] = include_bytes!("../tests/fixtures/approval_plan_vectors.json.gz");

#[test]
fn plans_match_the_retired_python() {
    let vectors = gunzip_json(VECTORS);
    let cases = vectors["cases"].as_array().expect("cases");
    assert!(cases.len() > 5000);
    for (index, case) in cases.iter().enumerate() {
        let mut wire = case["wire"].clone();
        wire["schema"] = Value::String(APPROVAL_RESOLUTION_PLAN_REQUEST_SCHEMA.to_owned());
        let request: ApprovalResolutionPlanRequestV1 =
            serde_json::from_value(wire).unwrap_or_else(|error| panic!("case {index}: {error}"));
        let expected = &case["expected"];
        let actual = evaluate(&request);
        if expected["status"] == "error" {
            assert!(
                actual.is_err(),
                "case {index}: expected error, got {actual:?}"
            );
            continue;
        }
        let mut want = expected.clone();
        want.as_object_mut().unwrap().remove("status");
        assert_eq!(
            actual.as_ref().ok(),
            Some(&want),
            "case {index}: {}",
            case["wire"]
        );
    }
}

#[test]
fn malformed_tokens_are_not_context_tokens() {
    use crate::approval_resolution_plan_token::is_valid_approval_context_token as valid;
    assert!(!valid("guard-approval-context:v1:"));
    assert!(!valid("guard-approval-context:v1:@@@"));
    assert!(!valid("guard-approval-context:v1:A"));
    assert!(!valid("not-a-token"));
}

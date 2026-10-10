//! Parity vectors recorded from the retired Python predicates, plus transport
//! binding checks for `ApprovalProofDecide`.

use guard_contracts::{ApprovalProofQueryV1, APPROVAL_PROOF_REQUEST_SCHEMA};
use serde_json::{json, Value};

use super::decide;

const VECTORS: &str = include_str!("../../../../tests/fixtures/approval_proof/parity_vectors.json");

#[test]
fn matches_recorded_python_behaviour() {
    let vectors: Vec<Value> = serde_json::from_str(VECTORS).unwrap();
    assert!(vectors.len() > 1000);
    for vector in vectors {
        let name = vector["name"].as_str().unwrap();
        let query: ApprovalProofQueryV1 = serde_json::from_value(vector["query"].clone())
            .unwrap_or_else(|error| panic!("{name}: {error}"));
        let outcome = decide(&query);
        assert_eq!(
            outcome.accepted,
            vector["expected"]["accepted"].as_bool().unwrap(),
            "{name}"
        );
        assert_eq!(
            outcome.disposition.map(|d| d.as_str()),
            vector["expected"]["claim_disposition"].as_str(),
            "{name}"
        );
    }
}

fn resident(query: Value) -> Value {
    let request = json!({
        "operation": "approval_proof_decide",
        "request": {
            "schema": APPROVAL_PROOF_REQUEST_SCHEMA,
            "request_id": "req-proof",
            "query": query,
        }
    });
    let out =
        crate::resident_protocol::evaluate_resident_bytes(request.to_string().as_bytes(), None)
            .expect("approval proof op should answer");
    serde_json::from_slice(&out).unwrap()
}

#[test]
fn resident_transport_binds_request_and_decides() {
    let reply = resident(json!({
        "kind": "claim_disposition",
        "decision": {"action": "allow", "decision_id": 3, "source": "approval-gate",
                     "expires_at": "2030-01-01T00:00:00Z"},
    }));
    assert_eq!(reply["status"], "ok");
    assert_eq!(reply["schema"], "guard-approval-proof-result.v1");
    assert_eq!(reply["request_id"], "req-proof");
    assert!(reply["request_sha256"]
        .as_str()
        .unwrap()
        .starts_with("sha256:"));
    assert_eq!(reply["payload"]["accepted"], true);
    assert_eq!(reply["payload"]["claim_disposition"], "consumed");

    let denied = resident(json!({
        "kind": "claim_disposition",
        "decision": {"action": "block", "decision_id": 3},
    }));
    assert_eq!(denied["payload"]["accepted"], false);
    assert_eq!(denied["payload"]["claim_disposition"], Value::Null);
}

#[test]
fn rejects_wrong_schema_and_unknown_fields() {
    let mut request = json!({
        "operation": "approval_proof_decide",
        "request": {
            "schema": "bogus",
            "request_id": "req-proof",
            "query": {"kind": "lookup_preserves_claim", "reason_code": null},
        }
    });
    let err =
        crate::resident_protocol::evaluate_resident_bytes(request.to_string().as_bytes(), None)
            .unwrap_err();
    assert_eq!(err, "native_approval_proof_schema_mismatch");

    request["request"]["schema"] = json!(APPROVAL_PROOF_REQUEST_SCHEMA);
    request["request"]["query"]["surprise"] = json!(true);
    assert!(crate::resident_protocol::evaluate_resident_bytes(
        request.to_string().as_bytes(),
        None
    )
    .is_err());

    request["request"]["query"] = json!({"kind": "not_a_query"});
    assert!(crate::resident_protocol::evaluate_resident_bytes(
        request.to_string().as_bytes(),
        None
    )
    .is_err());
}

#[test]
fn unknown_claim_disposition_never_authorizes() {
    for disposition in [json!("other"), Value::Null] {
        let reply = resident(json!({
            "kind": "postclaim_review_authorized",
            "claim_disposition": disposition,
            "claimed_decision": {"decision_id": 1},
            "current_decision": {"decision_id": 1},
        }));
        assert_eq!(reply["payload"]["accepted"], false);
    }
}

#[test]
fn int_and_float_compare_exactly_like_python() {
    use super::py_equal;
    // 2**53 + 1 is not representable as f64; Python keeps it unequal.
    assert!(!py_equal(
        &json!(9007199254740993_i64),
        &json!(9007199254740992.0)
    ));
    assert!(py_equal(
        &json!(9007199254740992_i64),
        &json!(9007199254740992.0)
    ));
    assert!(py_equal(&json!(1), &json!(1.0)));
    assert!(py_equal(&json!(true), &json!(1.0)));
    assert!(!py_equal(&json!(1), &json!(1.5)));
    assert!(!py_equal(&json!(u64::MAX), &json!(18446744073709552000.0)));
}

#[test]
fn empty_approval_id_takes_the_decision_id_branch_for_every_caller() {
    let row = json!({"action": "allow", "approval_id": "", "decision_id": 1});
    let expected = Some("retained");
    assert_eq!(
        super::claim_disposition(row.as_object().unwrap()).map(|d| d.as_str()),
        expected
    );
    assert_eq!(
        crate::claim_reuse::approval_reuse_claim_disposition(&row),
        expected
    );
}

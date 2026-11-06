//! Parity with the Python policy-integrity signer and verifier, recorded by
//! `testdata/policy_integrity_rows/record_vectors.py`, plus the request
//! failures that have no Python counterpart.

use guard_contracts::{
    PolicyIntegrityRowsRequestV1, PolicyIntegrityRowsResultV1, POLICY_INTEGRITY_ROWS_MAX_ITEMS,
    POLICY_INTEGRITY_ROWS_REQUEST_SCHEMA, POLICY_INTEGRITY_ROWS_RESULT_SCHEMA,
};
use serde_json::{json, Value};

use super::{evaluate, evaluate_policy_integrity_rows_request};

const VECTORS: &str = include_str!("../testdata/policy_integrity_rows/vectors.json");

fn vectors() -> Value {
    serde_json::from_str(VECTORS).expect("vectors json")
}

fn request(value: Value) -> PolicyIntegrityRowsRequestV1 {
    serde_json::from_value(value).expect("request decodes")
}

fn keyed_request(verify: Value, sign: Value) -> Value {
    let vectors = vectors();
    json!({
        "schema": POLICY_INTEGRITY_ROWS_REQUEST_SCHEMA,
        "request_id": "unit",
        "integrity_key_b64": vectors["key_b64"],
        "integrity_key_id": vectors["key_id"],
        "verify": verify,
        "sign": sign,
    })
}

fn plain_row() -> Value {
    json!({"decision_id": 7, "harness": "claude-code", "scope": "artifact", "action": "allow"})
}

#[test]
fn python_vectors_match_byte_for_byte() {
    let vectors = vectors();
    let cases = vectors["cases"].as_array().expect("cases");
    assert!(cases.len() > 60, "vector set unexpectedly small");
    for case in cases {
        let name = case["name"].as_str().expect("name");
        let parsed = request(case["request"].clone());
        let payload = evaluate(&parsed).unwrap_or_else(|code| panic!("{name}: {code}"));
        assert_eq!(
            serde_json::to_value(&payload).expect("payload json"),
            case["payload"],
            "{name}: payload"
        );
        let bytes = evaluate_policy_integrity_rows_request(&parsed)
            .unwrap_or_else(|code| panic!("{name}: {code}"));
        let result: PolicyIntegrityRowsResultV1 =
            serde_json::from_slice(&bytes).expect("result json");
        assert_eq!(result.schema, POLICY_INTEGRITY_ROWS_RESULT_SCHEMA);
        assert_eq!(result.status, "ok");
        assert_eq!(result.request_id, parsed.request_id, "{name}: request id");
        assert_eq!(
            result.request_sha256,
            case["request_sha256"].as_str().expect("digest"),
            "{name}: request digest the Python transport binds to"
        );
    }
}

fn reply_digest(value: Value) -> String {
    let bytes = evaluate_policy_integrity_rows_request(&request(value)).expect("result");
    let result: PolicyIntegrityRowsResultV1 = serde_json::from_slice(&bytes).expect("result json");
    result.request_sha256
}

#[test]
fn request_digest_never_covers_the_key() {
    let verify = json!([{"row": plain_row(), "degraded_mode": false}]);
    let keyed = keyed_request(verify.clone(), json!([]));
    let mut other_key = keyed.clone();
    other_key["integrity_key_b64"] = json!("AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE");
    let mut no_key = keyed.clone();
    no_key.as_object_mut().unwrap().remove("integrity_key_b64");
    let digest = reply_digest(keyed.clone());
    assert_eq!(digest, reply_digest(other_key));
    assert_eq!(digest, reply_digest(no_key));
    let mut other_key_id = keyed;
    other_key_id["integrity_key_id"] = json!("guard-policy-integrity-key:other");
    assert_ne!(digest, reply_digest(other_key_id));
}

#[test]
fn signed_rows_round_trip_through_verify() {
    let signed = evaluate(&request(keyed_request(
        json!([]),
        json!([{"row": plain_row(), "generation": 4, "signed_at": "2026-10-13T00:00:00Z"}]),
    )))
    .expect("sign");
    let mut row = plain_row();
    let columns = serde_json::to_value(&signed.sign[0]).expect("signature json");
    for (column, value) in columns.as_object().expect("columns") {
        row[column] = value.clone();
    }
    let verified = evaluate(&request(keyed_request(
        json!([{"row": row, "degraded_mode": false, "trusted_generation": 4}]),
        json!([]),
    )))
    .expect("verify");
    assert_eq!(verified.verify[0].status, "valid");
}

#[test]
fn result_never_carries_key_bytes() {
    let vectors = vectors();
    let key_b64 = vectors["key_b64"].as_str().expect("key");
    let parsed = request(keyed_request(
        json!([{"row": plain_row(), "degraded_mode": false}]),
        json!([{"row": plain_row(), "generation": 1, "signed_at": "2026-10-13T00:00:00Z"}]),
    ));
    let bytes = evaluate_policy_integrity_rows_request(&parsed).expect("result");
    let text = String::from_utf8(bytes).expect("utf8");
    assert!(!text.contains(key_b64));
}

#[test]
fn sign_without_key_fails_the_request() {
    let mut value = keyed_request(
        json!([]),
        json!([{"row": plain_row(), "generation": 1, "signed_at": "2026-10-13T00:00:00Z"}]),
    );
    value.as_object_mut().unwrap().remove("integrity_key_b64");
    assert_eq!(
        evaluate(&request(value)),
        Err("native_policy_integrity_key_unavailable")
    );
    let mut value = keyed_request(
        json!([]),
        json!([{"row": plain_row(), "generation": 1, "signed_at": "2026-10-13T00:00:00Z"}]),
    );
    value["integrity_key_id"] = json!("");
    assert_eq!(
        evaluate(&request(value)),
        Err("native_policy_integrity_key_unavailable")
    );
}

#[test]
fn malformed_key_fails_the_request() {
    for bad in ["", "not base64!", "AAAA====", "QUJD="] {
        let mut value = keyed_request(json!([]), json!([]));
        value["integrity_key_b64"] = json!(bad);
        assert_eq!(
            evaluate(&request(value)),
            Err("native_policy_integrity_key_invalid"),
            "{bad:?}"
        );
    }
    let mut value = keyed_request(json!([]), json!([]));
    value["integrity_key_b64"] = json!("A".repeat(2048));
    assert_eq!(
        evaluate(&request(value)),
        Err("native_policy_integrity_key_invalid")
    );
}

#[test]
fn non_object_rows_fail_the_request() {
    for row in [json!(null), json!([]), json!("row"), json!(7)] {
        let verify = keyed_request(json!([{"row": row, "degraded_mode": false}]), json!([]));
        assert_eq!(
            evaluate(&request(verify)),
            Err("native_policy_integrity_row_invalid")
        );
        let sign = keyed_request(
            json!([]),
            json!([{"row": row, "generation": 1, "signed_at": "2026-10-13T00:00:00Z"}]),
        );
        assert_eq!(
            evaluate(&request(sign)),
            Err("native_policy_integrity_row_invalid")
        );
    }
}

#[test]
fn out_of_range_decision_id_is_never_signed() {
    for decision_id in [json!(u64::MAX), json!(1.5)] {
        let mut row = plain_row();
        row["decision_id"] = decision_id;
        let value = keyed_request(
            json!([]),
            json!([{"row": row, "generation": 1, "signed_at": "2026-10-13T00:00:00Z"}]),
        );
        assert_eq!(
            evaluate(&request(value)),
            Err("native_policy_integrity_row_invalid")
        );
    }
}

#[test]
fn wrong_schema_and_oversized_batches_fail() {
    let mut value = keyed_request(json!([]), json!([]));
    value["schema"] = json!("guard-policy-integrity-rows-request.v0");
    assert_eq!(
        evaluate(&request(value)),
        Err("native_policy_integrity_rows_schema_invalid")
    );
    let items: Vec<Value> = (0..=POLICY_INTEGRITY_ROWS_MAX_ITEMS)
        .map(|_| json!({"row": {}, "degraded_mode": true}))
        .collect();
    let value = keyed_request(Value::Array(items), json!([]));
    assert_eq!(
        evaluate(&request(value)),
        Err("native_policy_integrity_rows_too_many_items")
    );
}

#[test]
fn unknown_fields_are_rejected() {
    let mut value = keyed_request(json!([]), json!([]));
    value["integrity_key"] = json!("raw");
    assert!(serde_json::from_value::<PolicyIntegrityRowsRequestV1>(value).is_err());
    let value = keyed_request(
        json!([{"row": {}, "degraded_mode": false, "key": "x"}]),
        json!([]),
    );
    assert!(serde_json::from_value::<PolicyIntegrityRowsRequestV1>(value).is_err());
}

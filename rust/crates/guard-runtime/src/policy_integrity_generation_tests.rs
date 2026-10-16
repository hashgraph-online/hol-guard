//! Parity with the Python startup generation decision, recorded by
//! `testdata/policy_integrity_generation/record_vectors.py`, plus the request
//! failures that have no Python counterpart.

use base64ct::{Base64UrlUnpadded, Encoding};
use guard_contracts::{
    PolicyIntegrityGenerationRequestV1, PolicyIntegrityRowsRequestV1,
    POLICY_INTEGRITY_ROWS_REQUEST_SCHEMA,
};
use rusqlite::{params_from_iter, types::Value as SqlValue, Connection};
use serde_json::{json, Value};

use super::{decide, ROW_COLUMNS};
use crate::policy_integrity_rows_op::evaluate;

const VECTORS: &str = include_str!("../testdata/policy_integrity_generation/vectors.json");

fn vectors() -> Value {
    serde_json::from_str(VECTORS).expect("vectors json")
}

fn key() -> Vec<u8> {
    (0u8..32).collect()
}

fn key_id() -> String {
    vectors()["integrity_key_id"]
        .as_str()
        .expect("key id")
        .to_owned()
}

fn sql_value(value: &Value) -> SqlValue {
    match value {
        Value::Null => SqlValue::Null,
        Value::String(text) => SqlValue::Text(text.clone()),
        Value::Number(number) if number.is_i64() => SqlValue::Integer(number.as_i64().unwrap()),
        Value::Number(number) => SqlValue::Real(number.as_f64().unwrap()),
        other => panic!("unexpected row value {other}"),
    }
}

/// A Guard home whose `guard.db` holds `rows` in `policy_decisions`.
fn home_with_rows(rows: &[Value]) -> tempfile::TempDir {
    let home = tempfile::tempdir().unwrap();
    let connection = Connection::open(home.path().join("guard.db")).unwrap();
    connection
        .execute(
            &format!("create table policy_decisions ({})", ROW_COLUMNS.join(", ")),
            [],
        )
        .unwrap();
    let placeholders = vec!["?"; ROW_COLUMNS.len()].join(", ");
    let insert = format!(
        "insert into policy_decisions ({}) values ({placeholders})",
        ROW_COLUMNS.join(", ")
    );
    for row in rows {
        let values = ROW_COLUMNS.iter().map(|column| sql_value(&row[*column]));
        connection
            .execute(&insert, params_from_iter(values))
            .unwrap();
    }
    home
}

fn generation_request(
    home: &tempfile::TempDir,
    trusted_state: Value,
) -> PolicyIntegrityGenerationRequestV1 {
    PolicyIntegrityGenerationRequestV1 {
        store_path: home.path().join("guard.db").to_string_lossy().into_owned(),
        guard_home: home.path().to_string_lossy().into_owned(),
        trusted_state,
    }
}

#[test]
fn python_vectors_match() {
    let vectors = vectors();
    let cases = vectors["cases"].as_array().expect("cases");
    assert!(cases.len() >= 25, "vector set unexpectedly small");
    for case in cases {
        let name = case["name"].as_str().expect("name");
        let home = home_with_rows(case["rows"].as_array().expect("rows"));
        let request = generation_request(&home, case["trusted_state"].clone());
        let outcome =
            decide(&request, &key(), &key_id()).unwrap_or_else(|code| panic!("{name}: {code}"));
        assert_eq!(
            serde_json::to_value(&outcome).expect("outcome json"),
            case["expected"],
            "{name}"
        );
    }
}

#[test]
fn rows_op_answers_the_generation_section() {
    let vectors = vectors();
    let case = &vectors["cases"][0];
    let home = home_with_rows(case["rows"].as_array().unwrap());
    let request: PolicyIntegrityRowsRequestV1 = serde_json::from_value(json!({
        "schema": POLICY_INTEGRITY_ROWS_REQUEST_SCHEMA,
        "request_id": "unit",
        "integrity_key_b64": Base64UrlUnpadded::encode_string(&key()),
        "integrity_key_id": vectors["integrity_key_id"],
        "verify": [],
        "sign": [],
        "generation": serde_json::to_value(generation_request(&home, case["trusted_state"].clone())).unwrap(),
    }))
    .unwrap();
    let payload = serde_json::to_value(evaluate(&request).unwrap()).unwrap();
    assert_eq!(
        payload,
        json!({"verify": [], "sign": [], "generation": case["expected"]})
    );
}

#[test]
fn rows_op_without_generation_omits_the_section() {
    let request: PolicyIntegrityRowsRequestV1 = serde_json::from_value(json!({
        "schema": POLICY_INTEGRITY_ROWS_REQUEST_SCHEMA,
        "verify": [],
        "sign": [],
    }))
    .unwrap();
    let payload = serde_json::to_value(evaluate(&request).unwrap()).unwrap();
    assert_eq!(payload, json!({"verify": [], "sign": []}));
}

#[test]
fn generation_without_key_fails_the_request() {
    let home = home_with_rows(&[]);
    let request: PolicyIntegrityRowsRequestV1 = serde_json::from_value(json!({
        "schema": POLICY_INTEGRITY_ROWS_REQUEST_SCHEMA,
        "verify": [],
        "sign": [],
        "generation": serde_json::to_value(generation_request(&home, json!({
            "cutover_complete": false, "generation": 3, "pending_generation": null, "version": 1
        }))).unwrap(),
    }))
    .unwrap();
    assert_eq!(
        evaluate(&request),
        Err("native_policy_integrity_key_unavailable")
    );
}

#[test]
fn unnormalized_trusted_state_is_refused() {
    let home = home_with_rows(&[]);
    for state in [
        json!({"cutover_complete": false, "generation": 3, "pending_generation": 2, "version": 1}),
        json!({"cutover_complete": false, "generation": 3, "version": 1}),
        json!({"cutover_complete": false, "generation": -1, "pending_generation": null, "version": 1}),
        json!({"cutover_complete": 0, "generation": 3, "pending_generation": null, "version": 1}),
        json!({"cutover_complete": false, "generation": 3, "pending_generation": null, "version": 2}),
        json!({"cutover_complete": false, "generation": 3, "pending_generation": null, "version": 1, "extra": 1}),
    ] {
        assert_eq!(
            decide(&generation_request(&home, state.clone()), &key(), &key_id()),
            Err("native_policy_integrity_state_invalid"),
            "{state}"
        );
    }
}

#[test]
fn store_outside_home_or_missing_is_refused() {
    let home = home_with_rows(&[]);
    let other = home_with_rows(&[]);
    let state = json!({"cutover_complete": false, "generation": 3, "pending_generation": null, "version": 1});
    let mut request = generation_request(&other, state.clone());
    request.guard_home = home.path().to_string_lossy().into_owned();
    assert_eq!(
        decide(&request, &key(), &key_id()),
        Err("native_policy_integrity_store_path_invalid")
    );
    let empty = tempfile::tempdir().unwrap();
    assert_eq!(
        decide(&generation_request(&empty, state), &key(), &key_id()),
        Err("native_policy_integrity_store_unavailable")
    );
}

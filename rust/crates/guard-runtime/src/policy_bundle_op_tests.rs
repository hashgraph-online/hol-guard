//! Envelope behavior of the `PolicyBundleAuthority` op.

use guard_contracts::{PolicyBundleAuthorityRequestV1, POLICY_BUNDLE_AUTHORITY_REQUEST_SCHEMA};
use serde_json::{json, Value};

use crate::policy_bundle_op::evaluate_policy_bundle_authority_request;

fn call(schema: &str, request_id: &str, kind: &str, input: Value) -> Value {
    let request = PolicyBundleAuthorityRequestV1 {
        schema: schema.to_owned(),
        request_id: request_id.to_owned(),
        kind: kind.to_owned(),
        input,
    };
    let bytes = evaluate_policy_bundle_authority_request(&request).unwrap();
    serde_json::from_slice(&bytes).unwrap()
}

fn good(kind: &str, input: Value) -> Value {
    call(POLICY_BUNDLE_AUTHORITY_REQUEST_SCHEMA, "req-1", kind, input)
}

#[test]
fn result_binds_request_id_and_digest() {
    let first = good("is_enforceable", json!({"bundle": {}}));
    let second = good(
        "is_enforceable",
        json!({"bundle": {"rolloutState": "enforcing"}}),
    );
    assert_eq!(first["request_id"], "req-1");
    assert_eq!(first["status"], "ok");
    assert_eq!(first["result"], json!({"value": false}));
    assert_eq!(second["result"], json!({"value": true}));
    assert_ne!(first["request_sha256"], second["request_sha256"]);
    assert!(first["request_sha256"]
        .as_str()
        .unwrap()
        .starts_with("sha256:"));
}

#[test]
fn malformed_envelopes_are_typed_errors() {
    let wrong_schema = call("other", "req-1", "is_enforceable", json!({}));
    assert_eq!(wrong_schema["status"], "error");
    assert_eq!(
        wrong_schema["code"],
        "native_policy_bundle_authority_invalid"
    );
    let empty_id = call(
        POLICY_BUNDLE_AUTHORITY_REQUEST_SCHEMA,
        "",
        "is_enforceable",
        json!({}),
    );
    assert_eq!(empty_id["code"], "native_policy_bundle_authority_invalid");
    let long_id = "x".repeat(129);
    let too_long = call(
        POLICY_BUNDLE_AUTHORITY_REQUEST_SCHEMA,
        &long_id,
        "is_enforceable",
        json!({}),
    );
    assert_eq!(too_long["code"], "native_policy_bundle_authority_invalid");
    let not_object = good("is_enforceable", json!([1]));
    assert_eq!(not_object["code"], "native_policy_bundle_authority_invalid");
    let missing_field = good("is_enforceable", json!({}));
    assert_eq!(
        missing_field["code"],
        "native_policy_bundle_authority_invalid"
    );
    let unknown = good("not_a_kind", json!({}));
    assert_eq!(
        unknown["code"],
        "native_policy_bundle_authority_unknown_kind"
    );
    assert_eq!(unknown["result"], Value::Null);
}

#[test]
fn undecodable_documents_are_policy_rejections_not_transport_errors() {
    let result = good("v1_bundle_hash", json!({"bundle_chunks": ["{not json"]}));
    assert_eq!(result["status"], "ok");
    assert!(result["result"]["error"].is_string());
    let wrong_type = good("v1_bundle_hash", json!({"bundle_chunks": "text"}));
    assert_eq!(wrong_type["status"], "error");
}

#[test]
fn oversized_documents_fail_closed() {
    let chunk = "a".repeat(100_000);
    let chunks: Vec<Value> = (0..32).map(|_| Value::String(chunk.clone())).collect();
    let result = good("v1_bundle_hash", json!({"bundle_chunks": chunks}));
    assert_eq!(result["status"], "ok");
    assert_eq!(result["result"], json!({"error": "limit_bytes"}));
}

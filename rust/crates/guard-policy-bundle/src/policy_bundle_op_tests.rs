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
    serde_json::to_value(evaluate_policy_bundle_authority_request(&request)).unwrap()
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

#[test]
fn an_equal_exception_issue_time_must_carry_the_accepted_set() {
    let set = |artifact: &str| json!([{"artifactId": artifact, "effect": "allow"}]);
    let hash_of = |exceptions: Value| {
        let document = json!({ "cloudExceptions": exceptions }).to_string();
        good(
            "v2_cloud_exceptions_hash",
            json!({ "bundle_chunks": [document] }),
        )["result"]["value"]
            .clone()
    };
    let accepted = hash_of(set("npm:lodash"));
    assert!(accepted.as_str().unwrap().starts_with("sha256:"));
    let transition = |exceptions: Value, accepted_hash: Value| {
        let bundle = json!({
            "bundleVersion": 8,
            "bundleHash": "sha256:current",
            "cloudExceptions": exceptions,
            "cloudExceptionsIssuedAt": "2026-07-16T09:30:00Z",
        })
        .to_string();
        good(
            "v2_transition",
            json!({
                "bundle_chunks": [bundle],
                "current_version": 8,
                "current_hash": "sha256:current",
                "current_cloud_exceptions_issued_at": "2026-07-16T09:30:00Z",
                "current_cloud_exceptions_hash": accepted_hash,
            }),
        )["result"]
            .clone()
    };
    assert_eq!(
        transition(set("npm:lodash"), accepted.clone()),
        json!({"ok": true})
    );
    assert_eq!(
        transition(set("npm:left-pad"), accepted),
        json!({"error": "cloud_exceptions_replay"})
    );
    assert_eq!(
        transition(set("npm:left-pad"), Value::Null),
        json!({"ok": true})
    );
}

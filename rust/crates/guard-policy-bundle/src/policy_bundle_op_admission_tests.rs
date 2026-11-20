//! Candidate admission and downgrade kinds of the `PolicyBundleAuthority` op.

use guard_contracts::{PolicyBundleAuthorityRequestV1, POLICY_BUNDLE_AUTHORITY_REQUEST_SCHEMA};
use serde_json::{json, Value};

use crate::policy_bundle_op::evaluate_policy_bundle_authority_request;
use crate::policy_bundle_op_admission::{is_downgrade, rejection};
use crate::policy_bundle_py::Obj;

fn obj(value: Value) -> Obj {
    match value {
        Value::Object(map) => map,
        _ => panic!("object expected"),
    }
}

fn chunks(value: &Value) -> Value {
    json!([serde_json::to_string(value).unwrap()])
}

fn result(kind: &str, input: Value) -> Value {
    let request = PolicyBundleAuthorityRequestV1 {
        schema: POLICY_BUNDLE_AUTHORITY_REQUEST_SCHEMA.to_owned(),
        request_id: "req-1".to_owned(),
        kind: kind.to_owned(),
        input,
    };
    let reply = serde_json::to_value(evaluate_policy_bundle_authority_request(&request)).unwrap();
    assert_eq!(reply["status"], "ok", "{reply}");
    reply["result"].clone()
}

fn v2(version: i64, hash: &str) -> Value {
    json!({"contractVersion": "guard-policy-bundle.v2", "bundleVersion": version, "bundleHash": hash})
}

fn v1(version: i64, hash: &str) -> Value {
    json!({"rolloutState": "enforcing", "bundleVersion": version, "bundleHash": hash,
           "payloadHash": "p", "issuedAt": "2026-01-01T00:00:00Z", "workspaceId": "w"})
}

#[test]
fn v2_candidate_uses_transition_rules_against_the_reference() {
    let current = v2(5, "h5");
    assert!(is_downgrade(&obj(v2(4, "h4")), &current, &Value::Null));
    assert!(is_downgrade(&obj(v2(5, "other")), &current, &Value::Null));
    assert!(!is_downgrade(&obj(v2(5, "h5")), &current, &Value::Null));
    assert!(!is_downgrade(&obj(v2(6, "h6")), &current, &Value::Null));
    assert!(!is_downgrade(&obj(v2(1, "h1")), &Value::Null, &Value::Null));
}

#[test]
fn v2_reference_version_must_be_an_integer() {
    let boolean = json!({"bundleVersion": true, "bundleHash": "h5"});
    let float = json!({"bundleVersion": 5.0, "bundleHash": "h5"});
    assert!(!is_downgrade(&obj(v2(1, "h1")), &boolean, &Value::Null));
    assert!(!is_downgrade(&obj(v2(1, "h1")), &float, &Value::Null));
}

#[test]
fn v2_same_bundle_keeps_the_accepted_exception_set() {
    let mut candidate = v2(5, "h5");
    candidate["cloudExceptions"] = json!([]);
    candidate["cloudExceptionsIssuedAt"] = json!("2026-01-01T00:00:00Z");
    let mut reference = v2(5, "h5");
    reference["cloudExceptionsIssuedAt"] = json!("2026-01-01T00:00:00Z");
    reference["cloudExceptionsHash"] = json!("sha256:not-this-set");
    assert!(is_downgrade(
        &obj(candidate.clone()),
        &reference,
        &Value::Null
    ));
    reference
        .as_object_mut()
        .unwrap()
        .remove("cloudExceptionsHash");
    reference["cloudExceptions"] = json!([]);
    assert!(!is_downgrade(&obj(candidate), &reference, &Value::Null));
}

#[test]
fn v1_candidate_compares_only_the_ordering_fields() {
    assert!(is_downgrade(&obj(v1(4, "h4")), &v1(5, "h5"), &Value::Null));
    assert!(!is_downgrade(&obj(v1(6, "h6")), &v1(5, "h5"), &Value::Null));
    let unordered = json!({"cloudExceptionsHash": "sha256:x"});
    assert!(!is_downgrade(&obj(v1(1, "h1")), &unordered, &Value::Null));
}

#[test]
fn admission_rejects_in_gate_order() {
    let mut old_daemon = v1(6, "h6");
    old_daemon["minDaemonVersion"] = json!("99.0.0");
    old_daemon["rolloutState"] = json!("draft");
    assert_eq!(
        rejection(&obj(old_daemon), &v1(9, "h9"), "1.0.0"),
        Some("unsupported_daemon_version")
    );
    let mut draft = v1(6, "h6");
    draft["rolloutState"] = json!("draft");
    assert_eq!(
        rejection(&obj(draft), &v1(9, "h9"), "1.0.0"),
        Some("inactive_rollout_state")
    );
    assert_eq!(
        rejection(&obj(v1(4, "h4")), &v1(5, "h5"), "1.0.0"),
        Some("bundle_version_downgrade")
    );
    assert_eq!(rejection(&obj(v2(2, "h2")), &Value::Null, "1.0.0"), None);
}

#[test]
fn kinds_answer_over_the_wire() {
    let reply = result(
        "candidate_admission",
        json!({"bundle_chunks": chunks(&v2(4, "h4")), "reference_chunks": chunks(&v2(5, "h5")),
               "daemon_version": "1.0.0"}),
    );
    assert_eq!(reply, json!({"rejection": "bundle_version_downgrade"}));
    let reply = result(
        "candidate_admission",
        json!({"bundle_chunks": chunks(&v2(6, "h6")), "reference_chunks": null,
               "daemon_version": "1.0.0"}),
    );
    assert_eq!(reply, json!({"rejection": null}));
    let reply = result(
        "downgrade_verdict",
        json!({"bundle_chunks": chunks(&v2(4, "h4")), "reference_chunks": chunks(&v2(5, "h5"))}),
    );
    assert_eq!(reply, json!({"value": true}));
}

#[test]
fn admission_without_a_daemon_version_is_invalid() {
    let request = PolicyBundleAuthorityRequestV1 {
        schema: POLICY_BUNDLE_AUTHORITY_REQUEST_SCHEMA.to_owned(),
        request_id: "req-1".to_owned(),
        kind: "candidate_admission".to_owned(),
        input: json!({"bundle_chunks": chunks(&v2(6, "h6"))}),
    };
    let reply = serde_json::to_value(evaluate_policy_bundle_authority_request(&request)).unwrap();
    assert_eq!(reply["status"], "error");
}

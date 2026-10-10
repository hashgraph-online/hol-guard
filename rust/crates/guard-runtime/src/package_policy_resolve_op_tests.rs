//! Parity vectors recorded from the legacy Python stored-policy override
//! (`local_supply_chain._resolve_stored_package_policy_override`) before it was
//! deleted. Each vector carries the hydrated facts the caller sends, what the
//! Python path finally produced, and which claim it ran.

use super::*;
use guard_contracts::PackagePolicyResolveRequestV1;
use serde_json::{json, Value};

const VECTORS: &str = include_str!("../testdata/package_policy_resolve_vectors.json");

fn request(vector: &Value, claim_succeeded: Option<bool>) -> PackagePolicyResolveRequestV1 {
    let mut value = vector["request"].clone();
    let map = value.as_object_mut().unwrap();
    map.insert("schema".into(), json!(PACKAGE_AUTHORITY_REQUEST_SCHEMA));
    map.insert("request_id".into(), json!("vector"));
    map.insert("guard_home".into(), json!("/tmp/guard-home"));
    if let Some(succeeded) = claim_succeeded {
        map.insert("claim_succeeded".into(), json!(succeeded));
    }
    serde_json::from_value(value).unwrap()
}

fn run(request: &PackagePolicyResolveRequestV1) -> Result<Value, String> {
    evaluate_package_policy_resolve(request)
        .map(|bytes| serde_json::from_slice::<Value>(&bytes).unwrap()["payload"].clone())
}

/// The caller's view after applying the patch over its own evaluation.
fn applied(vector: &Value, payload: &Value) -> Value {
    let mut view = vector["base"].clone();
    for (key, value) in payload["patch"].as_object().unwrap() {
        view[key] = value.clone();
    }
    view
}

#[test]
fn recorded_python_vectors_match() {
    let vectors: Vec<Value> = serde_json::from_str(VECTORS).unwrap();
    assert!(vectors.len() >= 40);
    for vector in &vectors {
        let name = vector["name"].as_str().unwrap();
        let expected = &vector["expected"];
        let claims = expected["claims"].as_array().unwrap();
        let first = run(&request(vector, None)).unwrap();
        assert_eq!(first["claim"], json!(claims.first()), "{name}: claim");
        let payload = if !claims.is_empty() && vector["claim_ok"] == json!(false) {
            run(&request(vector, Some(false))).unwrap()
        } else {
            first
        };
        assert_eq!(
            applied(vector, &payload),
            expected["final"],
            "{name}: final"
        );
        assert_eq!(
            payload["claim_disposition"], expected["claim_disposition"],
            "{name}: disposition"
        );
        assert_eq!(
            payload["reused"],
            json!(expected["final"]["reasons"][0]["code"] == "saved_package_approval"),
            "{name}: reused"
        );
    }
}

#[test]
fn fresh_identity_is_the_guard_cli_package_request_and_a_plain_hash_is_not() {
    let vectors: Vec<Value> = serde_json::from_str(VECTORS).unwrap();
    let vector = vectors
        .iter()
        .find(|item| item["name"] == "fresh_expiring_local_identity")
        .unwrap();
    assert_eq!(vector["request"]["decision"]["harness"], json!("guard-cli"));
    assert_eq!(
        vector["request"]["decision"]["artifact_id"],
        json!("guard-cli:project:package-request:abc")
    );
    let fresh = run(&request(vector, None)).unwrap();
    assert_eq!(fresh["claim_disposition"], json!("consumed"));

    for hash in [
        json!("plain-package-hash"),
        json!("guard-approval-context:v1:invalid"),
        Value::Null,
    ] {
        let mut rejected_vector = vector.clone();
        rejected_vector["request"]["decision"]["artifact_hash"] = hash;
        let rejected = run(&request(&rejected_vector, None)).unwrap();
        assert_eq!(rejected["claim_disposition"], Value::Null);
    }
}

#[test]
fn rejects_malformed_requests() {
    let vectors: Vec<Value> = serde_json::from_str(VECTORS).unwrap();
    let good = request(&vectors[0], None);

    let mut schema = good.clone();
    schema.schema = "wrong".into();
    assert_eq!(
        run(&schema).unwrap_err(),
        "native_package_policy_resolve_schema_mismatch"
    );

    let mut no_harness = good.clone();
    no_harness.harness = String::new();
    assert_eq!(
        run(&no_harness).unwrap_err(),
        "native_package_policy_resolve_invalid"
    );

    let mut bad_decision = good.clone();
    bad_decision.decision = Some(json!("allow"));
    assert_eq!(
        run(&bad_decision).unwrap_err(),
        "native_package_policy_resolve_invalid"
    );

    let mut bad_evaluation = good;
    bad_evaluation.evaluation = json!({"policy_action": "bogus", "reasons": [], "packages": []});
    assert!(run(&bad_evaluation).is_err());
}

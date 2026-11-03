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

fn token(content: &str) -> String {
    crate::context_digest::build_context_token(&guard_contracts::ContextDigestComponentsV1 {
        identity: json!("package-request:guard-proof"),
        content: json!(content),
        capabilities: json!({}),
        policy: json!({}),
        sandbox: json!({}),
        extension_control_digest: "extension-control".to_owned(),
    })
    .unwrap()
}

/// The recorded `require-reapproval` package request with a retained allow saved
/// under `scope` for `saved_content`, retried at `current_content`.
fn retry(scope: &str, saved_content: &str, current_content: &str) -> (Value, Value) {
    let vectors: Vec<Value> = serde_json::from_str(VECTORS).unwrap();
    let mut vector = vectors
        .into_iter()
        .find(|item| item["name"] == "durable_allow_require_reapproval")
        .unwrap();
    assert_eq!(vector["base"]["policy_action"], json!("require-reapproval"));
    vector["request"]["artifact_hash"] = json!(token(current_content));
    let decision = &mut vector["request"]["decision"];
    decision["scope"] = json!(scope);
    decision["artifact_hash"] = json!(token(saved_content));
    if scope == "publisher" {
        decision["artifact_id"] = Value::Null;
        decision["publisher"] = json!("guard-publisher");
    }
    let payload = run(&request(&vector, None)).unwrap();
    (applied(&vector, &payload), payload)
}

#[test]
fn a_saved_allow_of_any_scope_lets_the_identical_require_reapproval_retry_run() {
    for scope in ["artifact", "workspace", "publisher", "harness"] {
        let (view, payload) = retry(scope, "1.0.0", "1.0.0");
        assert_eq!(view["policy_action"], json!("allow"), "{scope}: action");
        assert_eq!(payload["reused"], json!(true), "{scope}: reused");
        assert_eq!(payload["claim"], json!("store"), "{scope}: claim");
        assert_ne!(
            payload["claim_disposition"],
            json!("consumed"),
            "{scope}: a retained rule is not a one-shot grant"
        );
    }
}

#[test]
fn a_changed_artifact_is_reviewed_again_whatever_scope_saved_the_allow() {
    for scope in ["artifact", "workspace", "publisher", "harness"] {
        let (view, payload) = retry(scope, "1.0.0", "1.0.1");
        assert_eq!(
            view["policy_action"],
            json!("require-reapproval"),
            "{scope}: action"
        );
        assert_eq!(payload["reused"], json!(false), "{scope}: reused");
        assert_eq!(payload["claim"], Value::Null, "{scope}: claim");
        assert_eq!(
            view["reasons"][0]["code"],
            json!("approval_reuse_content_changed"),
            "{scope}: reason"
        );
    }
}

#[test]
fn a_saved_allow_naming_another_artifact_is_not_reused() {
    let vectors: Vec<Value> = serde_json::from_str(VECTORS).unwrap();
    let mut vector = vectors
        .into_iter()
        .find(|item| item["name"] == "durable_allow_require_reapproval")
        .unwrap();
    vector["request"]["decision"]["scope"] = json!("workspace");
    vector["request"]["decision"]["artifact_id"] = json!("command:another-install");
    let payload = run(&request(&vector, None)).unwrap();
    assert_eq!(payload["reused"], json!(false));
    assert_eq!(payload["claim"], Value::Null);
    assert_eq!(
        applied(&vector, &payload)["policy_action"],
        json!("require-reapproval")
    );
}

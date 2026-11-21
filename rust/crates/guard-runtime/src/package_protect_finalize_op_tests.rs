//! Parity vectors recorded from the legacy Python decision tail of
//! `local_supply_chain._final_package_protect_authority` before it was
//! deleted (see `testdata/package_protect_finalize/record_vectors.py`). The
//! file is compact; `expand` mirrors the recorder's `_expand` and yields the
//! request the bridge sends, the evaluation the reply patches and the
//! evaluation the Python tail returned.

use super::*;
use serde_json::{json, Map, Value};

const VECTORS: &str = include_str!("../testdata/package_protect_finalize/vectors.json");
const RESOLVE_VECTORS: &str = include_str!("../testdata/package_policy_resolve_vectors.json");
const WORKSPACE: &str = "/workspace/demo";
const EVALUATION_KEYS: [&str; 3] = ["policy_action", "reasons", "packages"];
const FACT_KEYS: [&str; 7] = [
    "decision",
    "ignored_integrity",
    "daemon_authority",
    "diagnosed_reason",
    "diagnosed_stored_hash",
    "bundle_rules",
    "approval_request",
];

fn vectors() -> Vec<Value> {
    let document: Value = serde_json::from_str(VECTORS).unwrap();
    let resolve: Vec<Value> = serde_json::from_str(RESOLVE_VECTORS).unwrap();
    document["vectors"]
        .as_array()
        .unwrap()
        .iter()
        .map(|vector| expand(&document, &resolve, vector))
        .collect()
}

fn stored_policy(request: &Value, case: Option<&Value>) -> Value {
    let mut policy = Map::new();
    let harness = case.map_or(json!("codex"), |case| case["request"]["harness"].clone());
    policy.insert("harness".to_owned(), harness);
    policy.insert(
        "artifact_id".to_owned(),
        request["current_artifact_id"].clone(),
    );
    policy.insert(
        "artifact_hash".to_owned(),
        request["current_artifact_hash"].clone(),
    );
    policy.insert("workspace_dir".to_owned(), json!(WORKSPACE));
    match case {
        Some(case) => {
            for key in FACT_KEYS {
                if let Some(fact) = case["request"].get(key).filter(|fact| !fact.is_null()) {
                    policy.insert(key.to_owned(), fact.clone());
                }
            }
        }
        None => {
            policy.insert("ignored_integrity".to_owned(), json!(false));
            policy.insert("daemon_authority".to_owned(), json!(false));
        }
    }
    Value::Object(policy)
}

/// Mirrors `record_vectors._expand`.
fn expand(document: &Value, resolve: &[Value], vector: &Value) -> Value {
    let case = vector
        .get("resolve_case")
        .map(|name| resolve.iter().find(|item| &item["name"] == name).unwrap());
    let base = match case {
        Some(case) => case["base"].clone(),
        None => document["bases"][vector["base"].as_str().unwrap()].clone(),
    };
    assert!(base.is_object(), "{}", vector["name"]);
    let mut request = vector["request"].clone();
    for key in ["initial_artifact_hash", "current_artifact_hash"] {
        if let Some(reference) = request.get(key).and_then(Value::as_str).map(str::to_owned) {
            let hash = document["hashes"][reference.as_str()].clone();
            assert!(hash.is_string(), "{reference}");
            request[key] = hash;
        }
    }
    let evaluation: Map<String, Value> = EVALUATION_KEYS
        .iter()
        .map(|key| ((*key).to_owned(), base[*key].clone()))
        .collect();
    request["evaluation"] = Value::Object(evaluation);
    if vector["stored_policy"] == json!(true) {
        request["stored_policy"] = stored_policy(&request, case);
    }
    let mut expected = base.clone();
    let changes = &document["results"][vector["result"].as_str().unwrap()];
    for (key, value) in changes.as_object().unwrap() {
        expected[key.as_str()] = value.clone();
    }
    json!({"name": vector["name"], "request": request, "base": base, "expected": expected})
}

fn vector(name: &str) -> Value {
    vectors()
        .into_iter()
        .find(|item| item["name"] == name)
        .unwrap()
}

fn request(value: &Value) -> Result<PackageProtectFinalizeRequestV1, serde_json::Error> {
    let mut value = value.clone();
    let map = value.as_object_mut().unwrap();
    map.insert("schema".into(), json!(PACKAGE_AUTHORITY_REQUEST_SCHEMA));
    map.insert("request_id".into(), json!("vector"));
    map.insert("guard_home".into(), json!("/tmp/guard-home"));
    serde_json::from_value(value)
}

fn run(value: &Value) -> Result<Value, String> {
    evaluate_package_protect_finalize(&request(value).unwrap())
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
    let vectors = vectors();
    assert!(vectors.len() >= 140);
    for vector in &vectors {
        let name = vector["name"].as_str().unwrap();
        let payload = run(&vector["request"]).unwrap_or_else(|error| panic!("{name}: {error}"));
        assert!(
            payload.as_object().unwrap().len() == 1 && payload.get("patch").is_some(),
            "{name}: payload"
        );
        assert_eq!(applied(vector, &payload), vector["expected"], "{name}");
    }
}

#[test]
fn an_unclaimed_saved_approval_is_never_reused() {
    for vector in vectors() {
        if vector["request"]["saved_approval_claimed"] == json!(false) {
            let codes = vector["expected"]["reasons"].as_array().unwrap();
            assert!(
                codes
                    .iter()
                    .all(|reason| reason["code"] != "saved_package_approval"),
                "{}",
                vector["name"]
            );
        }
    }
}

#[test]
fn malformed_requests_are_rejected() {
    let base = vector("claimed_consumed_durable_allow_claim_ok")["request"].clone();
    let with = |key: &str, value: Value| {
        let mut changed = base.clone();
        changed[key] = value;
        changed
    };
    let without = |key: &str| {
        let mut changed = base.clone();
        changed.as_object_mut().unwrap().remove(key);
        changed
    };
    assert!(run(&base).is_ok());
    assert!(request(&with("unexpected", json!(true))).is_err());
    for invalid in [
        with("claim_failed", json!(true)),
        with("claim_disposition", json!("spent")),
        with("current_action", json!("approve")),
        with("evaluation", json!({"policy_action": "allow"})),
        without("current_artifact_hash"),
        without("stored_policy"),
        with("stored_policy", json!("facts")),
        with("stored_policy", {
            let mut facts = base["stored_policy"].clone();
            facts["claim_saved_approval"] = json!(true);
            facts
        }),
    ] {
        assert!(run(&invalid).is_err(), "{invalid}");
    }
    let mut unclaimed = with("saved_approval_claimed", json!(false));
    assert!(run(&unclaimed).is_err(), "disposition without a claim");
    unclaimed
        .as_object_mut()
        .unwrap()
        .remove("claim_disposition");
    assert!(run(&unclaimed).is_ok());
    let mut schema = request(&base).unwrap();
    schema.schema = "other".to_owned();
    assert_eq!(
        evaluate_package_protect_finalize(&schema).unwrap_err(),
        "native_package_protect_finalize_schema_mismatch"
    );
}

#[test]
fn no_rebuilt_intent_rejects_the_saved_approval_without_artifact_facts() {
    let vector = vector("rebuild_found_no_intent");
    assert!(vector["request"].get("current_artifact_id").is_none());
    let mut stray = vector["request"].clone();
    stray["current_artifact_id"] = json!("command:npm-install");
    assert!(run(&stray).is_err());
    let reasons = vector["expected"]["reasons"].as_array().unwrap();
    assert_eq!(reasons[0]["code"], json!("approval_reuse_identity_changed"));
}

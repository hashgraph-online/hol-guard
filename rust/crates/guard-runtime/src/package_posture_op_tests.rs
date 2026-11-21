//! Parity vectors recorded from the legacy Python
//! `local_supply_chain.build_local_supply_chain_posture` before it was
//! deleted. Each vector carries the hydrated facts the caller sends and the
//! posture the Python path produced.

use super::*;
use guard_contracts::PackagePostureRequestV1;
use serde_json::{json, Value};

const VECTORS: &str = include_str!("../testdata/package_posture_vectors.json");

fn request(vector: &Value) -> PackagePostureRequestV1 {
    let mut value = vector["request"].clone();
    let map = value.as_object_mut().unwrap();
    map.insert("schema".into(), json!(PACKAGE_AUTHORITY_REQUEST_SCHEMA));
    map.insert("request_id".into(), json!("vector"));
    map.insert("guard_home".into(), json!("/tmp/guard-home"));
    map.insert(
        "package_manager_protection".into(),
        json!({"managed": true, "shims": ["npm"], "detail": {"a": 1}}),
    );
    serde_json::from_value(value).unwrap()
}

fn run(request: &PackagePostureRequestV1) -> Result<Value, String> {
    evaluate_package_posture(request)
        .map(|bytes| serde_json::from_slice::<Value>(&bytes).unwrap()["payload"].clone())
}

#[test]
fn recorded_python_vectors_match() {
    let vectors: Vec<Value> = serde_json::from_str(VECTORS).unwrap();
    assert!(vectors.len() >= 60);
    for vector in &vectors {
        let name = vector["name"].as_str().unwrap();
        assert_eq!(run(&request(vector)).unwrap(), vector["expected"], "{name}");
    }
}

#[test]
fn rejects_malformed_requests() {
    let vectors: Vec<Value> = serde_json::from_str(VECTORS).unwrap();
    let valid = request(&vectors[0]);
    let mut bad_schema = valid.clone();
    bad_schema.schema = "other".into();
    assert_eq!(
        run(&bad_schema).unwrap_err(),
        "native_package_posture_schema_mismatch"
    );
    for field in ["summary", "entitlement", "remote_policy", "bundle_payload"] {
        let mut bad = valid.clone();
        match field {
            "summary" => bad.summary = json!([]),
            "entitlement" => bad.entitlement = json!("x"),
            "remote_policy" => bad.remote_policy = json!(null),
            _ => bad.bundle_payload = json!(1),
        }
        assert_eq!(
            run(&bad).unwrap_err(),
            "native_package_posture_invalid",
            "{field}"
        );
    }
    let mut bad_pm = valid.clone();
    bad_pm.package_manager_protection = json!([]);
    assert!(run(&bad_pm).is_err());
    let mut empty_id = valid;
    empty_id.request_id = String::new();
    assert!(run(&empty_id).is_err());
}

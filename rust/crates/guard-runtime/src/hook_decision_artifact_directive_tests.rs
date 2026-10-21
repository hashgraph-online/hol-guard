//! Parity vectors recorded from the retired Python artifact-hook routing
//! (`finalize_native_artifact_hook`, frozen in
//! `scripts/ci/record_artifact_directive_vectors.py`), replayed through the
//! resident `hook_decide` operation.

use guard_contracts::{HOOK_DECISION_ARTIFACT_DIRECTIVE_FEATURE, HOOK_DECISION_REQUEST_SCHEMA};
use serde_json::{json, Value};

use crate::store_vectors_support_tests::gunzip_json;

const VECTORS: &[u8] = include_bytes!("../tests/fixtures/artifact_directive_vectors.json.gz");

fn reply(inputs: &Value) -> Option<Value> {
    let request = json!({
        "operation": "hook_decide",
        "request": {
            "schema": HOOK_DECISION_REQUEST_SCHEMA,
            "request_id": "req-artifact-directive",
            "query": {"kind": "artifact_directive", "inputs": inputs},
        }
    });
    let out =
        crate::resident_protocol::evaluate_resident_bytes(request.to_string().as_bytes(), None)
            .ok()?;
    serde_json::from_slice(&out).ok()
}

fn directive(inputs: &Value) -> Value {
    let reply = reply(inputs).expect("hook decision op should answer");
    assert_eq!(reply["status"], "ok", "{reply}");
    reply["payload"].clone()
}

fn rejected(inputs: &Value) -> bool {
    match reply(inputs) {
        None => true,
        Some(reply) => reply["status"] == "error",
    }
}

#[test]
fn matches_python_artifact_routing_vectors() {
    let vectors = gunzip_json(VECTORS);
    let vectors = vectors.as_array().unwrap();
    assert!(vectors.len() > 40_000);
    for vector in vectors {
        let facts = &vector["facts"];
        let payload = directive(facts);
        assert_eq!(payload["kind"], "artifact_directive", "{facts}");
        assert_eq!(payload["queue_observe_request"], false, "{facts}");
        assert_eq!(payload["queue_approval_request"], false, "{facts}");
        for (key, expected) in vector["directive"].as_object().unwrap() {
            assert_eq!(&payload[key], expected, "{facts}: {key}");
        }
    }
}

#[test]
fn feature_is_advertised() {
    assert!(crate::resident_op_features::RESIDENT_OP_FEATURES
        .contains(&HOOK_DECISION_ARTIFACT_DIRECTIVE_FEATURE));
}

#[test]
fn malformed_inputs_fail_closed() {
    let vectors = gunzip_json(VECTORS);
    let facts = vectors[0]["facts"].clone();
    let mut unknown_action = facts.clone();
    unknown_action["policy_action"] = json!("permit");
    assert!(rejected(&unknown_action));
    let mut extra = facts.clone();
    extra["review_hint_present"] = json!(true);
    assert!(rejected(&extra));
    let mut missing = facts;
    missing.as_object_mut().unwrap().remove("replayed");
    assert!(rejected(&missing));
}

//! Replays generic-hook approval-reuse vectors recorded from the Python owner.

use std::cell::Cell;
use std::io::Read;

use flate2::read::GzDecoder;
use guard_command::approval_reuse::evaluate_approval_reuse;
use guard_contracts::PolicyLookupReuseV1;
use serde_json::{json, Value};

use super::compose_reuse;

const VECTORS: &[u8] = include_bytes!("../tests/fixtures/generic_approval_reuse_vectors.json.gz");

fn vectors() -> Vec<Value> {
    let mut text = String::new();
    GzDecoder::new(VECTORS).read_to_string(&mut text).unwrap();
    let document: Value = serde_json::from_str(&text).unwrap();
    assert_eq!(
        document["schema"],
        "guard-generic-approval-reuse-vectors.v1"
    );
    document["vectors"].as_array().unwrap().clone()
}

fn text(value: &Value) -> Option<String> {
    value.as_str().map(str::to_owned)
}

#[test]
fn recorded_generic_approval_reuse_replays() {
    let vectors = vectors();
    assert!(vectors.len() >= 400);
    for case in vectors {
        let name = case["name"].as_str().unwrap();
        let diagnosed = Cell::new(false);
        let token = case["current_token"].as_str().unwrap();
        let actual = compose_reuse(
            case["saved"].clone(),
            &case["current_action"],
            token,
            || {
                diagnosed.set(true);
                (text(&case["diagnosis"][0]), text(&case["diagnosis"][1]))
            },
        );
        let expected = &case["expected"];
        let args = &expected["evaluate"];
        let saved_action = &args["saved_action"];
        let verdict = evaluate_approval_reuse(
            &args["current_action"],
            (!saved_action.is_null()).then_some(saved_action),
            args["saved_decision_present"].as_bool(),
            args["validation_reason"].as_str(),
            args["fresh_local_approval"].as_bool().unwrap(),
            args["durable_exact_approval"].as_bool().unwrap(),
        );
        assert_eq!(diagnosed.get(), expected["diagnosed"], "{name}");
        assert_eq!(
            actual["reuse"],
            serde_json::to_value(verdict).unwrap(),
            "{name}"
        );
        assert_eq!(actual["saved_present"], expected["saved_present"], "{name}");
        assert_eq!(
            actual["saved_artifact_hash"], expected["saved_artifact_hash"],
            "{name}"
        );
        assert_eq!(actual["decision"], case["saved"]["decision"], "{name}");
        assert_eq!(
            actual["ignored_local_integrity"], case["saved"]["ignored_local_integrity"],
            "{name}"
        );
    }
}

#[test]
fn unknown_reuse_fields_are_rejected() {
    let parsed = serde_json::from_value::<PolicyLookupReuseV1>(json!({
        "current_action": "allow",
        "approval_context_inputs": {},
        "current_token": "t",
    }));
    assert!(parsed.is_err());
}

//! Parity vectors recorded from the retired Python review ladder
//! (`review_native_artifact_hook`, frozen in
//! `scripts/ci/record_artifact_review_route_vectors.py`), replayed through the
//! resident `hook_decide` operation.

use guard_contracts::{HOOK_DECISION_ARTIFACT_REVIEW_ROUTE_FEATURE, HOOK_DECISION_REQUEST_SCHEMA};
use serde_json::{json, Value};

use crate::store_vectors_support_tests::gunzip_json;

const VECTORS: &[u8] = include_bytes!("../tests/fixtures/artifact_review_route_vectors.json.gz");

fn reply(inputs: &Value) -> Option<Value> {
    let request = json!({
        "operation": "hook_decide",
        "request": {
            "schema": HOOK_DECISION_REQUEST_SCHEMA,
            "request_id": "req-artifact-review-route",
            "query": {"kind": "artifact_review_route", "inputs": inputs},
        }
    });
    let out =
        crate::resident_protocol::evaluate_resident_bytes(request.to_string().as_bytes(), None)
            .ok()?;
    serde_json::from_slice(&out).ok()
}

fn route(inputs: &Value) -> Value {
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
fn matches_python_review_ladder_vectors() {
    let vectors = gunzip_json(VECTORS);
    let vectors = vectors.as_array().unwrap();
    assert!(vectors.len() > 20_000);
    for vector in vectors {
        let facts = &vector["facts"];
        let payload = route(facts);
        assert_eq!(payload["kind"], "artifact_review_route", "{facts}");
        for (key, expected) in vector["route"].as_object().unwrap() {
            assert_eq!(&payload[key], expected, "{facts}: {key}");
        }
    }
}

/// A `review` or `require-reapproval` verdict is never terminalized, and it is
/// closed without a prompt only when requests are not offered for approval.
/// Every other route leaves it queued (or answered natively, or observed), and
/// the single exception is a prompt that asks to bypass Guard.
#[test]
fn review_tier_verdicts_keep_allow_once_and_always_allow() {
    let vectors = gunzip_json(VECTORS);
    let mut offered = 0_usize;
    for vector in vectors.as_array().unwrap() {
        let facts = &vector["facts"];
        let action = facts["policy_action"].as_str().unwrap();
        if !matches!(action, "review" | "require-reapproval") {
            continue;
        }
        let payload = route(facts);
        let chosen = payload["route"].as_str().unwrap();
        assert_eq!(payload["terminalize"], "none", "{facts}");
        match chosen {
            "silent_review" | "silent_block" => {
                assert_eq!(chosen, "silent_review", "{facts}");
                assert_eq!(facts["asks_for_approval"], false, "{facts}");
                assert_eq!(facts["observe_mode"], false, "{facts}");
                assert_eq!(payload["silent_review"]["action"], action, "{facts}");
            }
            "observe" => assert_eq!(facts["observe_mode"], true, "{facts}"),
            "copilot_response" | "native_response" | "queue_approval" => {
                assert_eq!(facts["observe_mode"], false, "{facts}");
                assert_eq!(facts["asks_for_approval"], true, "{facts}");
                assert!(payload["silent_review"].is_null(), "{facts}");
                offered += 1;
            }
            "continue" => {
                assert_eq!(facts["prompt_hard_block"], true, "{facts}");
                assert_eq!(facts["asks_for_approval"], true, "{facts}");
                assert_eq!(facts["observe_mode"], false, "{facts}");
            }
            other => panic!("{facts}: unexpected route {other}"),
        }
    }
    assert!(offered > 1_000);
}

/// A terminal verdict never reaches an approval queue.
#[test]
fn terminal_verdicts_are_never_queued() {
    let vectors = gunzip_json(VECTORS);
    for vector in vectors.as_array().unwrap() {
        let facts = &vector["facts"];
        if !matches!(
            facts["policy_action"].as_str().unwrap(),
            "block" | "sandbox-required"
        ) {
            continue;
        }
        let payload = route(facts);
        assert_ne!(payload["route"], "queue_approval", "{facts}");
        assert_eq!(payload["attach_cursor_request_ids"], false, "{facts}");
        assert_eq!(payload["record_claude_notice"], false, "{facts}");
    }
}

#[test]
fn feature_is_advertised() {
    assert!(crate::resident_op_features::RESIDENT_OP_FEATURES
        .contains(&HOOK_DECISION_ARTIFACT_REVIEW_ROUTE_FEATURE));
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
    missing.as_object_mut().unwrap().remove("asks_for_approval");
    assert!(rejected(&missing));
}

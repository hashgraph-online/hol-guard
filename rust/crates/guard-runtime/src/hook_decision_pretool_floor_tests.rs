//! The PreToolUse floor, replayed through the resident `hook_decide` operation.

use guard_contracts::{GuardAction, HOOK_DECISION_REQUEST_SCHEMA};
use serde_json::{json, Value};

fn reply(inputs: &Value) -> Option<Value> {
    let request = json!({
        "operation": "hook_decide",
        "request": {
            "schema": HOOK_DECISION_REQUEST_SCHEMA,
            "request_id": "req-pretool-floor",
            "query": {"kind": "pretool_floor", "inputs": inputs},
        }
    });
    let out =
        crate::resident_protocol::evaluate_resident_bytes(request.to_string().as_bytes(), None)
            .ok()?;
    serde_json::from_slice(&out).ok()
}

fn floor(minimum_action: &str, reason_code: &str) -> Value {
    let reply = reply(&json!({"minimum_action": minimum_action, "reason_code": reason_code}))
        .expect("hook decision op should answer");
    assert_eq!(reply["status"], "ok", "{reply}");
    assert_eq!(reply["payload"]["kind"], "pretool_floor", "{reply}");
    reply["payload"]["floor"].clone()
}

fn rejected(inputs: &Value) -> bool {
    match reply(inputs) {
        None => true,
        Some(reply) => reply["status"] == "error" && reply["payload"].is_null(),
    }
}

#[test]
fn a_review_floor_keeps_allow_once_and_always_allow() {
    // A review floor stays the review tier, whose card offers Allow once and
    // Always allow; it is never raised to a terminal action.
    assert_eq!(
        floor("review", "native_destructive_review"),
        json!("review")
    );
    assert_eq!(
        floor("require-reapproval", "native_changed"),
        json!("require-reapproval")
    );
}

#[test]
fn every_canonical_action_floors_the_verdict() {
    for action in GuardAction::LATTICE {
        assert_eq!(
            floor(action.as_str(), "native_reason"),
            json!(action.as_str())
        );
    }
}

#[test]
fn sandbox_required_keeps_its_tier() {
    // The retired Python floor admitted only allow, review and block, so a
    // sandbox-required review collapsed to a block floor.
    assert_eq!(
        floor("sandbox-required", "native_contained"),
        json!("sandbox-required")
    );
}

#[test]
fn a_contextual_git_helper_review_is_not_a_floor() {
    assert_eq!(
        floor("review", "native_git_helper_context_review"),
        Value::Null
    );
    // Only the review tier is deferred; a hard answer with that code still floors.
    assert_eq!(
        floor("block", "native_git_helper_context_review"),
        json!("block")
    );
}

#[test]
fn a_malformed_answer_is_rejected_not_floored() {
    assert!(rejected(
        &json!({"minimum_action": "deny", "reason_code": "r"})
    ));
    assert!(rejected(&json!({"minimum_action": "", "reason_code": "r"})));
    assert!(rejected(
        &json!({"minimum_action": "allow", "reason_code": ""})
    ));
    assert!(rejected(&json!({"minimum_action": "allow"})));
    assert!(rejected(
        &json!({"minimum_action": "allow", "reason_code": "r", "extra": 1})
    ));
}

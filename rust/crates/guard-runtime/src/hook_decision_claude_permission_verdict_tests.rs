//! Parity vectors recorded from the retired Python ladder in
//! `run_native_claude_permission_request` (frozen in
//! `scripts/ci/record_claude_permission_verdict_vectors.py`), replayed through
//! the resident `hook_decide` operation.

use guard_contracts::{
    CLAUDE_PERMISSION_ARTIFACT_POLICY_FACT, HOOK_DECISION_CLAUDE_PERMISSION_VERDICT_FEATURE,
    HOOK_DECISION_REQUEST_SCHEMA,
};
use serde_json::{json, Value};

const VECTORS: &str = include_str!("../tests/fixtures/claude_permission_verdict_vectors.json");

fn reply(inputs: &Value) -> Option<Value> {
    let request = json!({
        "operation": "hook_decide",
        "request": {
            "schema": HOOK_DECISION_REQUEST_SCHEMA,
            "request_id": "req-claude-permission-verdict",
            "query": {"kind": "claude_permission_verdict", "inputs": inputs},
        }
    });
    let out =
        crate::resident_protocol::evaluate_resident_bytes(request.to_string().as_bytes(), None)
            .ok()?;
    serde_json::from_slice(&out).ok()
}

fn answer(inputs: &Value) -> Value {
    let reply = reply(inputs).expect("hook decision op should answer");
    assert_eq!(reply["status"], "ok", "{reply}");
    let payload = reply["payload"].clone();
    assert_eq!(payload["kind"], "claude_permission_verdict", "{payload}");
    payload
}

fn rejected(inputs: &Value) -> bool {
    match reply(inputs) {
        None => true,
        Some(reply) => reply["status"] == "error",
    }
}

fn vectors() -> Vec<Value> {
    serde_json::from_str::<Value>(VECTORS)
        .unwrap()
        .as_array()
        .unwrap()
        .clone()
}

/// The resident's verdict for one vector, asking for the artifact policy the
/// way the transport does: the first round is sent without it and, when the
/// resident names it, the second round carries it.
fn verdict_for(vector: &Value) -> Value {
    let mut inputs = vector["inputs"].clone();
    let first = answer(&inputs);
    let policy = &vector["artifact_policy"];
    if policy.is_null() {
        assert_eq!(first["needs_facts"], json!([]), "{vector}");
        return first["verdict"].clone();
    }
    assert_eq!(
        first["needs_facts"],
        json!([CLAUDE_PERMISSION_ARTIFACT_POLICY_FACT]),
        "{vector}"
    );
    assert!(first["verdict"].is_null(), "{vector}");
    inputs["artifact_policy"] = policy.clone();
    let second = answer(&inputs);
    assert_eq!(second["needs_facts"], json!([]), "{vector}");
    second["verdict"].clone()
}

#[test]
fn matches_python_claude_permission_ladder_vectors() {
    let vectors = vectors();
    assert!(vectors.len() >= 70);
    for vector in &vectors {
        assert_eq!(verdict_for(vector), vector["verdict"], "{vector}");
    }
}

/// The approval invariant for this dialog: a review never leaves the user
/// without a way to approve. `review` defers to Claude's own dialog (Allow
/// once and Always allow there) and `guard_question` sends Claude to the
/// Guard approval question, which offers both; only `block` and
/// `sandbox-required` deny, and those are not reviews.
#[test]
fn claude_permission_reviews_keep_allow_once_and_always_allow() {
    let mut seen = std::collections::BTreeSet::new();
    for vector in vectors() {
        let verdict = verdict_for(&vector);
        let kind = verdict["verdict"].as_str().unwrap().to_owned();
        let action = verdict["policy_action"].clone();
        match kind.as_str() {
            "review" => {
                assert_eq!(action, "require-reapproval", "{vector}");
                assert_eq!(verdict["offers_approval"], true, "{vector}");
            }
            "guard_question" => {
                assert_eq!(action, "block", "{vector}");
                assert_eq!(verdict["offers_approval"], true, "{vector}");
            }
            "deny" => {
                assert!(
                    action == "block" || action == "sandbox-required",
                    "{vector}"
                );
                assert_eq!(verdict["offers_approval"], false, "{vector}");
            }
            "passthrough" => {
                assert!(action.is_null(), "{vector}");
                assert!(verdict["reason"].is_null(), "{vector}");
            }
            other => panic!("unexpected verdict {other}: {vector}"),
        }
        if kind != "passthrough" {
            assert!(verdict["reason"]
                .as_str()
                .is_some_and(|reason| !reason.trim().is_empty()));
        }
        seen.insert(kind);
    }
    assert_eq!(
        seen.into_iter().collect::<Vec<_>>(),
        ["deny", "guard_question", "passthrough", "review"]
    );
}

#[test]
fn a_notice_decides_without_the_artifact_policy() {
    let inputs = json!({
        "notice": {"artifact_type": "package_request", "reason": "Reviewing an install."},
        "runtime_artifact_present": true,
    });
    let payload = answer(&inputs);
    assert_eq!(payload["needs_facts"], json!([]));
    assert_eq!(payload["verdict"]["verdict"], "review");
    assert_eq!(payload["verdict"]["reason"], "Reviewing an install.");
}

/// A request the resident cannot read is an error, which the transport answers
/// with the host outage response, never a verdict.
#[test]
fn malformed_requests_are_rejected_not_answered() {
    let policy = json!({"config_action": "block", "package_action": null});
    for inputs in [
        // Artifact facts alongside a notice that decides on its own.
        json!({"notice": {}, "runtime_artifact_present": true, "artifact_policy": policy.clone()}),
        // Artifact facts without an artifact.
        json!({"notice": null, "runtime_artifact_present": false, "artifact_policy": policy}),
        // A configured action the resident did not compose.
        json!({
            "notice": null,
            "runtime_artifact_present": true,
            "artifact_policy": {"config_action": "ask", "package_action": null},
        }),
        json!({
            "notice": null,
            "runtime_artifact_present": true,
            "artifact_policy": {"config_action": "", "package_action": "allow"},
        }),
        // Unknown fields.
        json!({"notice": null, "runtime_artifact_present": true, "verdict": "allow"}),
        json!({
            "notice": null,
            "runtime_artifact_present": true,
            "artifact_policy": {"config_action": "allow", "package_action": null, "x": 1},
        }),
        // Missing or mistyped facts.
        json!({"notice": null}),
        json!({"notice": "pending", "runtime_artifact_present": true}),
        json!({"notice": null, "runtime_artifact_present": "yes"}),
    ] {
        assert!(rejected(&inputs), "{inputs}");
    }
}

#[test]
fn the_feature_is_advertised() {
    assert!(crate::resident_op_features::RESIDENT_OP_FEATURES
        .contains(&HOOK_DECISION_CLAUDE_PERMISSION_VERDICT_FEATURE));
}

use serde_json::{json, Value};

use super::dispatch;
use crate::runner_authority_op::ERR_INVALID;

fn request(action: &str, retry_blocked: bool, raw_command: Value) -> Value {
    json!({
        "request_id": "req-1",
        "decision_action": action,
        "retry_blocked": retry_blocked,
        "raw_command": raw_command,
        "artifact_id": null,
        "artifact_hash": null,
    })
}

#[test]
fn shell_decision_keeps_the_reviewed_command() {
    assert_eq!(
        dispatch(&request("blocked", false, json!("npm install lodash"))),
        Ok(json!({
            "policy_decision": "block",
            "raw_command": "npm install lodash",
            "artifact_id": "approval-request:req-1",
            "artifact_hash": "sha256:04dc367b569376e9f2d431e5d837134001f75e4957b60130cc5d7cf1e15a60ac",
            "user_override": "approval-blocked",
            "receipt_id": "guard-receipt-memory-008d909eeb8711719e8001453b66bc56",
        }))
    );
}

#[test]
fn approval_wrapper_is_not_the_action() {
    let answer = dispatch(&request(
        "approved",
        false,
        json!("hol-guard approvals approve req-1"),
    ))
    .expect("receipt fields");
    assert_eq!(answer["raw_command"], Value::Null);
    assert_eq!(
        answer["artifact_hash"],
        "sha256:edb140157a1c046b2fc5984e10dc8d5fe6e104250e4f043339f0de2f1a56c5b7"
    );
    assert_eq!(answer["user_override"], "approval-approved");
    assert_eq!(
        answer["receipt_id"],
        "guard-receipt-memory-ea468d876ec1493bac166d5d4fc8384d"
    );
}

#[test]
fn retry_blocked_relabels_only_an_approval() {
    let approved = dispatch(&request("approved", true, Value::Null)).expect("approved");
    assert_eq!(approved["policy_decision"], "allow");
    assert_eq!(approved["user_override"], "approval-approved-retry-blocked");
    let blocked = dispatch(&request("blocked", true, Value::Null)).expect("blocked");
    assert_eq!(blocked["user_override"], "approval-blocked");
    let dismissed =
        dispatch(&request("dismissed_keep_asking", true, Value::Null)).expect("dismissed");
    assert_eq!(dismissed["policy_decision"], "require-reapproval");
    assert_eq!(
        dismissed["receipt_id"],
        "guard-receipt-memory-ffe8e2344b6c95c8926d4261bff37133"
    );
}

#[test]
fn supplied_artifact_identity_is_kept() {
    let mut args = request("approved", false, json!("python3 jokes.py"));
    args["artifact_id"] = json!("omp:native-pretool:bash");
    args["artifact_hash"] = json!("sha256:given");
    let answer = dispatch(&args).expect("receipt fields");
    assert_eq!(answer["artifact_id"], "omp:native-pretool:bash");
    assert_eq!(answer["artifact_hash"], "sha256:given");
    assert_eq!(answer["raw_command"], "python3 jokes.py");
}

#[test]
fn unknown_decision_has_no_receipt() {
    assert_eq!(
        dispatch(&request("dismissed", false, Value::Null)),
        Ok(json!({"policy_decision": null}))
    );
}

#[test]
fn malformed_requests_are_refused() {
    let mut empty_id = request("approved", false, Value::Null);
    empty_id["request_id"] = json!("");
    let mut extra = request("approved", false, Value::Null);
    extra["extra"] = json!(true);
    let mut missing = request("approved", false, Value::Null);
    if let Some(fields) = missing.as_object_mut() {
        fields.remove("artifact_hash");
    }
    let refused = [
        empty_id,
        extra,
        missing,
        request("approved", false, json!(1)),
        request("approved", false, json!("")),
        json!({"request_id": "req-1", "decision_action": "approved", "retry_blocked": "yes", "raw_command": null, "artifact_id": null, "artifact_hash": null}),
        json!([]),
    ];
    for args in refused {
        assert_eq!(dispatch(&args), Err(ERR_INVALID), "{args}");
    }
}

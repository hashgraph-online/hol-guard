use super::{evaluate, HookReviewBindingRequestV1};
use serde_json::{json, Value};

fn request(marker: Value) -> HookReviewBindingRequestV1 {
    HookReviewBindingRequestV1 {
        schema: "guard-hook-review-binding-request.v1".to_owned(),
        request_id: "binding-1".to_owned(),
        marker,
        business_identity_hex: "00ff".to_owned(),
        cli_revision: Some(4),
        policy_binding: None,
    }
}

fn policy_request(result: Value, receipt: Value) -> HookReviewBindingRequestV1 {
    let mut request = request(Value::Null);
    request.policy_binding = Some(super::HookReviewPolicyBindingRequestV1 {
        harness: "claude-code".to_owned(),
        native_result: result,
        verified_receipt: receipt,
    });
    request
}

#[test]
fn projects_a_verified_policy_binding() {
    let vectors: Value = serde_json::from_str(include_str!(
        "../tests/fixtures/hook_direct_saved_decision_vectors.json"
    ))
    .unwrap();
    let case = vectors["queries"]
        .as_array()
        .unwrap()
        .iter()
        .find(|case| case["name"] == "bash-command")
        .unwrap();
    let value: Value = serde_json::from_slice(
        &evaluate(&policy_request(
            case["result"].clone(),
            case["receipt"].clone(),
        ))
        .unwrap(),
    )
    .unwrap();
    assert_eq!(
        value["result"]["binding"]["schema"],
        "guard.native-review-policy-binding.v2"
    );
    assert_eq!(
        value["result"]["binding"]["rule_digest"],
        case["receipt"]["rule_digest"]
    );
    assert_eq!(
        value["result"]["binding"]["command_extensions"]["uncertainty_count"],
        0
    );
}

#[test]
fn rejects_a_tampered_policy_receipt() {
    let result = json!({
        "decision": "allow",
        "model_output_action": "not_applicable",
        "policy_action": "allow",
        "observed_policy_action": "allow",
        "reason_code": "safe",
        "reviewed_output_sha256": null,
        "command_extensions": {"binding": {}, "uncertainty_count": 0}
    });
    let receipt = json!({
        "schema": "guard-native-hook-decision-receipt.v1",
        "event_name": "PreToolUse",
        "harness": "claude-code",
        "payload_kind": "inline",
        "decision": "deny",
        "model_output_action": "not_applicable",
        "policy_action": "allow",
        "observed_policy_action": "allow",
        "reason_code": "safe",
        "reviewed_output_sha256": null,
        "observe_mode": true,
        "policy_digest": "a",
        "rule_digest": "b",
        "runtime_identity": "c",
        "command_extensions": {"binding": {}, "uncertainty_count": 0}
    });
    assert_eq!(
        evaluate(&policy_request(result, receipt)).unwrap_err(),
        "hook_review_policy_binding_invalid"
    );
}

#[test]
fn leaves_an_unbound_review_unbound() {
    let value: Value =
        serde_json::from_slice(&evaluate(&policy_request(json!({}), json!({}))).unwrap()).unwrap();
    assert_eq!(value["result"]["binding"], Value::Null);
}

#[test]
fn projects_a_committed_binding() {
    let value: Value = serde_json::from_slice(
        &evaluate(&request(json!({
            "epoch": 2,
            "mutation_revision": 3,
            "phase": "committed",
            "effective_digest": "sha256:abc",
            "authority_key_id": "key",
        })))
        .unwrap(),
    )
    .unwrap();
    assert_eq!(value["result"]["token"][1], 3);
    assert_eq!(value["result"]["token"][6], "00ff");
}

#[test]
fn rejects_a_mid_mutation_marker() {
    assert_eq!(
        evaluate(&request(json!({"phase": "closed"}))).unwrap_err(),
        "hook_review_binding_marker_not_committed"
    );
}

#[test]
fn accepts_an_unarmed_empty_marker() {
    let value: Value = serde_json::from_slice(&evaluate(&request(json!({}))).unwrap()).unwrap();
    assert_eq!(value["result"]["token"][0], Value::Null);
}

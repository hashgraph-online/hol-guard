use super::{evaluate, HookReviewBindingRequestV1};
use serde_json::{json, Value};

fn request(marker: Value) -> HookReviewBindingRequestV1 {
    HookReviewBindingRequestV1 {
        schema: "guard-hook-review-binding-request.v1".to_owned(),
        request_id: "binding-1".to_owned(),
        marker,
        business_identity_hex: "00ff".to_owned(),
        cli_revision: Some(4),
    }
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

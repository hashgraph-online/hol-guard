use serde_json::{json, Map, Value};

use super::*;
use crate::hook_evidence_writer::ReceiptValidationApi;

/// A receipt the decision edge would emit, with the `decision_id` CPython's
/// `native_decision_receipt` derives for it.
fn receipt() -> Map<String, Value> {
    json!({
        "schema": "guard-native-hook-decision-receipt.v1",
        "version": 1,
        "authority": "rust",
        "decision_id": "bb33d535a63d051d5df12716d83cefab5b6eb9f368ff082d79c274e378c4319c",
        "request_id": "req.01jabc",
        "request_digest": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "harness": "claude-code",
        "event_name": "PreToolUse",
        "payload_kind": "inline",
        "policy_generation": 7,
        "policy_digest": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        "rule_digest": null,
        "runtime_identity": "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
        "decision": "deny",
        "model_output_action": "not_applicable",
        "policy_action": "block",
        "observed_policy_action": "review",
        "reason_code": "native_command_policy_block",
        "workspace_bound": true,
        "source_ref_external_allowed": false,
        "reviewed_output_sha256": null,
        "observe_mode": false,
        "deadline_budget_ms": 750
    })
    .as_object()
    .expect("object")
    .clone()
}

fn with(field: &str, value: Value) -> Map<String, Value> {
    let mut receipt = receipt();
    receipt.insert(field.to_owned(), value);
    receipt
}

fn without(field: &str) -> Map<String, Value> {
    let mut receipt = receipt();
    receipt.remove(field);
    receipt
}

#[test]
fn a_receipt_the_edge_emitted_validates_against_the_python_decision_id() {
    assert_eq!(
        validate_native_decision_receipt(&receipt()),
        Some(receipt())
    );
}

#[test]
fn a_prompt_receipt_carries_its_risk_classes_into_the_identity_digest() {
    let mut prompt = receipt();
    prompt.insert("event_name".to_owned(), json!("UserPromptSubmit"));
    prompt.insert(
        "prompt_risk_classes".to_owned(),
        json!(["local_env_read", "exfil_intent"]),
    );
    prompt.insert(
        "decision_id".to_owned(),
        json!("7f27c2af184466bee11cfb0b929f1293b5683a6f2375c410af83982c29df5ce0"),
    );
    assert!(validate_native_decision_receipt(&prompt).is_some());
}

#[test]
fn an_edited_field_breaks_the_identity_digest() {
    assert_eq!(
        validate_native_decision_receipt(&with("policy_action", json!("allow"))),
        None
    );
}

#[test]
fn a_receipt_missing_a_required_field_is_refused() {
    assert_eq!(
        validate_native_decision_receipt(&without("observe_mode")),
        None
    );
}

#[test]
fn a_receipt_carrying_an_unknown_field_is_refused() {
    assert_eq!(
        validate_native_decision_receipt(&with("command", json!("rm -rf /"))),
        None
    );
}

#[test]
fn a_receipt_claiming_another_authority_is_refused() {
    assert_eq!(
        validate_native_decision_receipt(&with("authority", json!("python"))),
        None
    );
}

#[test]
fn a_prompt_receipt_outside_the_inline_payload_kind_is_refused() {
    let mut prompt = receipt();
    prompt.insert("event_name".to_owned(), json!("UserPromptSubmit"));
    prompt.insert("payload_kind".to_owned(), json!("source_file_ref"));
    assert_eq!(validate_native_decision_receipt(&prompt), None);
}

#[test]
fn risk_classes_on_a_tool_event_are_refused() {
    assert_eq!(
        validate_native_decision_receipt(&with("prompt_risk_classes", json!(["exfil_intent"]))),
        None
    );
}

#[test]
fn risk_classes_out_of_catalogue_order_are_refused() {
    assert!(!valid_prompt_risk_classes(&json!([
        "exfil_intent",
        "local_env_read"
    ])));
    assert!(!valid_prompt_risk_classes(&json!([
        "local_env_read",
        "local_env_read"
    ])));
    assert!(!valid_prompt_risk_classes(&json!([])));
    assert!(valid_prompt_risk_classes(&json!([
        "local_env_read",
        "exfil_intent"
    ])));
}

#[test]
fn a_policy_generation_of_zero_is_refused() {
    assert_eq!(
        validate_native_decision_receipt(&with("policy_generation", json!(0))),
        None
    );
}

#[test]
fn a_deadline_outside_the_bound_is_refused() {
    assert_eq!(
        validate_native_decision_receipt(&with("deadline_budget_ms", json!(9_001))),
        None
    );
    assert_eq!(
        validate_native_decision_receipt(&with("deadline_budget_ms", json!(0))),
        None
    );
}

#[test]
fn an_uppercase_digest_is_refused() {
    assert_eq!(
        validate_native_decision_receipt(&with("request_digest", json!("A".repeat(64)))),
        None
    );
}

#[test]
fn a_boolean_where_the_receipt_wants_a_flag_is_required() {
    assert_eq!(
        validate_native_decision_receipt(&with("observe_mode", json!("false"))),
        None
    );
}

#[test]
fn the_seam_answers_the_same_as_the_free_function() {
    assert_eq!(
        NativeReceiptValidation.validate_native_decision_receipt(&receipt()),
        validate_native_decision_receipt(&receipt())
    );
}

#[test]
fn the_identity_bytes_leave_out_the_fields_a_retry_may_change() {
    let bytes = canonical_receipt_bytes(&receipt()).expect("encodable");
    let encoded = String::from_utf8(bytes).expect("utf-8");
    assert!(!encoded.contains("decision_id"));
    assert!(!encoded.contains("authority"));
    assert!(encoded.contains("guard-native-hook-decision-identity.v1"));
}

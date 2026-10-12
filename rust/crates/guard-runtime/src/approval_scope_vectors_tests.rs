//! Parity vectors recorded from the retired Python `request_scope_contract`:
//! every case carries the stored request and the contract, digest and
//! exact-action token the Python produced.

use guard_contracts::{ApprovalScopeItemV1, ApprovalScopeRequestV1, APPROVAL_SCOPE_REQUEST_SCHEMA};
use serde_json::{json, Value};

use super::evaluate;
use crate::store_vectors_support_tests::gunzip_json;

const VECTORS: &[u8] = include_bytes!("../tests/fixtures/approval_scope_vectors.json.gz");

const FIELDS: [&str; 14] = [
    "artifact_id",
    "artifact_type",
    "artifact_hash",
    "artifact_name",
    "policy_action",
    "harness",
    "publisher",
    "source_scope",
    "config_path",
    "wrapper_chain",
    "action_identity",
    "raw_command_text",
    "action_envelope_json",
    "scanner_evidence",
];

fn item_for(request: &Value, workspace_target: &Value) -> ApprovalScopeItemV1 {
    let mut object = serde_json::Map::new();
    for field in FIELDS {
        if let Some(value) = request.get(field) {
            object.insert(field.to_owned(), value.clone());
        }
    }
    object.insert("workspace_target".to_owned(), workspace_target.clone());
    serde_json::from_value(Value::Object(object)).expect("item")
}

fn evaluate_one(item: ApprovalScopeItemV1) -> Value {
    let request = ApprovalScopeRequestV1 {
        schema: APPROVAL_SCOPE_REQUEST_SCHEMA.to_owned(),
        request_id: "vector".to_owned(),
        items: vec![item],
    };
    evaluate(&request).expect("evaluate")["items"][0].clone()
}

#[test]
fn contracts_match_the_retired_python() {
    let vectors = gunzip_json(VECTORS);
    let cases = vectors["cases"].as_array().expect("cases");
    assert!(cases.len() > 5000);
    let (mut global, mut workspace, mut persist, mut task) = (0, 0, 0, 0);
    for (index, case) in cases.iter().enumerate() {
        let expected = &case["expected"];
        let actual = evaluate_one(item_for(&case["request"], &expected["workspace_target"]));
        let mut contract = actual.clone();
        let token = contract
            .as_object_mut()
            .and_then(|object| object.remove("exact_context_token"))
            .expect("token");
        assert_eq!(
            contract, expected["contract"],
            "contract mismatch, case {index}"
        );
        assert_eq!(
            token, expected["exact_context_token"],
            "token mismatch, case {index}"
        );
        let allow = &contract["allowed_scopes_by_action"]["allow"];
        global += usize::from(
            allow
                .as_array()
                .is_some_and(|a| a.contains(&json!("global"))),
        );
        workspace += usize::from(
            allow
                .as_array()
                .is_some_and(|a| a.contains(&json!("workspace"))),
        );
        persist += usize::from(contract["exact_action_persistence_eligible"] == json!(true));
        task += usize::from(contract["task_capability_eligibility"]["eligible"] == json!(true));
    }
    assert!(global > 20 && workspace > 200 && persist > 100 && task > 100);
}

#[test]
fn a_request_without_fields_gets_the_conservative_contract() {
    let item = evaluate_one(ApprovalScopeItemV1::default());
    assert_eq!(item["allowed_scopes_by_action"]["allow"], json!([]));
    assert_eq!(item["allowed_scopes_by_action"]["block"], json!([]));
    assert_eq!(item["exact_action_persistence_eligible"], json!(false));
    assert_eq!(item["exact_context_token"], Value::Null);
}

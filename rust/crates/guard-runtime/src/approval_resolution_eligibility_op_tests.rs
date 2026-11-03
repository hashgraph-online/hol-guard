use super::*;
use guard_contracts::{ApprovalResolutionItemV1, APPROVAL_RESOLUTION_ELIGIBILITY_REQUEST_SCHEMA};
use serde_json::json;

fn request(items: Vec<ApprovalResolutionItemV1>) -> ApprovalResolutionEligibilityRequestV1 {
    ApprovalResolutionEligibilityRequestV1 {
        schema: APPROVAL_RESOLUTION_ELIGIBILITY_REQUEST_SCHEMA.to_owned(),
        request_id: "req-1".to_owned(),
        items,
    }
}

fn item(policy_action: Value, contract_error: Value) -> ApprovalResolutionItemV1 {
    ApprovalResolutionItemV1 {
        policy_action,
        decision_contract_error: contract_error,
    }
}

fn reasons(request: &ApprovalResolutionEligibilityRequestV1) -> Vec<Value> {
    evaluate(request)["reasons"].as_array().unwrap().clone()
}

#[test]
fn resolvable_row_has_no_block_reason() {
    let req = request(vec![item(json!("review"), Value::Null)]);
    assert_eq!(reasons(&req), vec![Value::Null]);
}

#[test]
fn contract_error_outranks_the_action_check() {
    // The row's action is resolvable on its own; the unreadable contract is
    // what makes the row inconsistent, exactly as the Python order had it.
    let req = request(vec![item(
        json!("review"),
        json!("decision_contract_error"),
    )]);
    assert_eq!(
        reasons(&req),
        vec![json!("authoritative_decision_inconsistent")]
    );
}

#[test]
fn unrecognized_policy_action_is_inconsistent() {
    for action in [json!("not-an-action"), json!(null), json!(7)] {
        let req = request(vec![item(action.clone(), Value::Null)]);
        assert_eq!(
            reasons(&req),
            vec![json!("authoritative_decision_inconsistent")],
            "action {action}"
        );
    }
}

#[test]
fn terminal_actions_are_not_resolvable() {
    for action in ["block", "sandbox-required"] {
        let req = request(vec![item(json!(action), Value::Null)]);
        assert_eq!(
            reasons(&req),
            vec![json!("terminal_policy_action_not_resolvable")],
            "action {action}"
        );
    }
}

#[test]
fn ask_aliases_to_review_and_stays_resolvable() {
    let req = request(vec![item(json!("ask"), Value::Null)]);
    assert_eq!(reasons(&req), vec![Value::Null]);
}

#[test]
fn non_terminal_actions_stay_resolvable() {
    for action in ["allow", "warn", "review", "require-reapproval"] {
        let req = request(vec![item(json!(action), Value::Null)]);
        assert_eq!(reasons(&req), vec![Value::Null], "action {action}");
    }
}

#[test]
fn answers_hold_the_caller_order() {
    let req = request(vec![
        item(json!("review"), Value::Null),
        item(json!("block"), Value::Null),
        item(json!("nonsense"), Value::Null),
    ]);
    assert_eq!(
        reasons(&req),
        vec![
            Value::Null,
            json!("terminal_policy_action_not_resolvable"),
            json!("authoritative_decision_inconsistent"),
        ]
    );
}

#[test]
fn empty_batch_answers_with_no_reasons() {
    let req = request(vec![]);
    assert_eq!(reasons(&req), Vec::<Value>::new());
}

#[test]
fn an_oversized_batch_is_refused_rather_than_answered() {
    let req = request(vec![
        item(json!("review"), Value::Null);
        APPROVAL_RESOLUTION_ELIGIBILITY_MAX_ITEMS + 1
    ]);
    let encoded = evaluate_approval_resolution_eligibility_request(&req).unwrap();
    let decoded: Value = serde_json::from_slice(&encoded).unwrap();
    assert_eq!(decoded["status"], json!("error"));
    assert_eq!(
        decoded["code"],
        json!("native_approval_resolution_eligibility_too_many_items")
    );
    assert!(decoded.get("payload").is_none());
}

#[test]
fn a_request_with_an_unknown_field_is_rejected() {
    let err = serde_json::from_value::<ApprovalResolutionEligibilityRequestV1>(json!({
        "schema": APPROVAL_RESOLUTION_ELIGIBILITY_REQUEST_SCHEMA,
        "request_id": "req-1",
        "items": [],
        "extra": true,
    }))
    .unwrap_err();
    assert!(err.to_string().contains("extra"), "{err}");
}

#[test]
fn a_request_naming_another_contract_is_refused() {
    let mut req = request(vec![item(json!("review"), Value::Null)]);
    req.schema = "guard-approval-resolution-plan-request.v1".to_owned();
    let encoded = evaluate_approval_resolution_eligibility_request(&req).unwrap();
    let decoded: Value = serde_json::from_slice(&encoded).unwrap();
    assert_eq!(decoded["status"], json!("error"));
    assert_eq!(
        decoded["code"],
        json!("native_approval_resolution_eligibility_schema_mismatch")
    );
    assert!(decoded.get("payload").is_none());
}

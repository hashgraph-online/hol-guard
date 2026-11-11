use serde_json::{json, Map, Value};

use super::{not_found, replay, Decision};

/// A native review with a retry binding, already allowed at the artifact.
fn resolved(action: &str, scope: &str) -> Map<String, Value> {
    let Value::Object(request) = json!({
        "request_id": "r1",
        "status": "resolved",
        "resolution_action": action,
        "resolution_scope": scope,
        "artifact_id": "omp:native-pretool:bash",
        "artifact_type": "tool_call",
        "artifact_hash": format!("native-review-v4:{}:deny:review:review:test", "a".repeat(64)),
        "policy_action": "review",
        "harness": "omp",
    }) else {
        unreachable!()
    };
    request
}

fn decision<'a>(action: &'a str, scope: &'a str) -> Decision<'a> {
    Decision {
        action,
        scope,
        contract_version: None,
        contract_digest: None,
    }
}

#[test]
fn a_pending_request_goes_to_the_library() {
    let mut request = resolved("allow", "artifact");
    request.insert("status".to_owned(), json!("pending"));
    assert!(replay(&request, &decision("allow", "artifact"), None).is_none());
}

#[test]
fn a_request_with_a_grant_offer_goes_to_the_library() {
    let mut request = resolved("allow", "artifact");
    request.insert("browser_intent".to_owned(), json!({"kind": "mcp"}));
    assert!(replay(&request, &decision("allow", "artifact"), None).is_none());
}

#[test]
fn a_native_bash_review_goes_to_the_library() {
    let mut request = resolved("allow", "artifact");
    request.insert(
        "artifact_type".to_owned(),
        json!(guard_contracts::NATIVE_BASH_REVIEW_ARTIFACT_TYPE),
    );
    assert!(replay(&request, &decision("allow", "artifact"), None).is_none());
}

#[test]
fn repeating_the_recorded_decision_is_idempotent() {
    let request = resolved("allow", "artifact");
    let answer = replay(&request, &decision("allow", "artifact"), None)
        .and_then(Result::ok)
        .unwrap_or_default();
    let body = &answer["idempotent"];
    assert_eq!(body["resolved"], json!(true));
    assert_eq!(body["idempotent"], json!(true));
    assert_eq!(body["applied_scope"], json!("artifact"));
    assert_eq!(body["requested_scope"], json!("artifact"));
    assert_eq!(body["resolved_request"]["request_id"], json!("r1"));
    assert!(body["scope_contract_digest"].is_string());
    assert!(body.get("exact_context_token").is_none());
}

#[test]
fn a_different_decision_is_already_resolved() {
    let request = resolved("allow", "artifact");
    let answer = replay(&request, &decision("block", "artifact"), None)
        .and_then(Result::ok)
        .unwrap_or_default();
    assert_eq!(answer, json!({"already_resolved": true}));
}

#[test]
fn a_stale_contract_raises_what_the_library_raised() {
    let request = resolved("allow", "artifact");
    let stale = Decision {
        contract_version: Some(crate::approval_scope_material::APPROVAL_SCOPE_CONTRACT_VERSION),
        contract_digest: Some("0000"),
        ..decision("allow", "artifact")
    };
    let error = replay(&request, &stale, None)
        .and_then(Result::err)
        .unwrap_or_default();
    assert_eq!(error["kind"], json!("stale_scope_contract"));
    assert_eq!(error["message"], json!("stale_scope_contract"));
    assert!(error["contract"]["scope_contract_digest"].is_string());
}

#[test]
fn an_unknown_scope_is_a_value_error() {
    let request = resolved("allow", "artifact");
    let error = replay(&request, &decision("allow", "galaxy"), None)
        .and_then(Result::err)
        .unwrap_or_default();
    assert_eq!(error["kind"], json!("value"));
    assert_eq!(
        error["message"],
        json!("Unsupported approval scope: galaxy")
    );
}

#[test]
fn a_block_at_a_scope_not_offered_is_ineligible() {
    let request = resolved("block", "artifact");
    let error = replay(&request, &decision("block", "global"), None)
        .and_then(Result::err)
        .unwrap_or_default();
    assert_eq!(error["kind"], json!("ineligible_scope"));
    assert_eq!(error["message"], json!("ineligible_request_scope"));
    assert_eq!(error["action"], json!("block"));
    assert_eq!(error["requested_scope"], json!("global"));
}

#[test]
fn an_unknown_request_is_not_found() {
    let error = not_found("r9");
    assert_eq!(error["kind"], json!("not_found"));
    assert_eq!(error["message"], json!("Unknown approval request: r9"));
}

//! The conditions `resolve_request_scope_selection` used to decide in Python,
//! each exercised against a contract this op derives itself.

use guard_contracts::{
    ApprovalScopeItemV1, ApprovalScopeSelectRequestV1, APPROVAL_SCOPE_SELECT_REQUEST_SCHEMA,
};
use serde_json::{json, Value};

use super::evaluate;
use crate::approval_scope_material::APPROVAL_SCOPE_CONTRACT_VERSION;

/// A native review with a retry binding: it offers an allow at the artifact.
fn bound_review() -> ApprovalScopeItemV1 {
    ApprovalScopeItemV1 {
        artifact_id: Some(json!("omp:native-pretool:bash")),
        artifact_type: Some(json!("tool_call")),
        artifact_hash: Some(json!(format!(
            "native-review-v4:{}:deny:review:review:test",
            "a".repeat(64)
        ))),
        policy_action: Some(json!("review")),
        ..Default::default()
    }
}

/// The same review with no binding: a block may be recorded, an allow may not.
fn unbound_review() -> ApprovalScopeItemV1 {
    ApprovalScopeItemV1 {
        artifact_hash: Some(json!("unbound-request")),
        ..bound_review()
    }
}

fn select(
    item: ApprovalScopeItemV1,
    action: &str,
    requested_scope: &str,
    echoed: Option<(&str, &str)>,
) -> Value {
    let (contract_version, contract_digest) = match echoed {
        Some((version, digest)) => (Some(version.to_owned()), Some(digest.to_owned())),
        None => (None, None),
    };
    evaluate(&ApprovalScopeSelectRequestV1 {
        schema: APPROVAL_SCOPE_SELECT_REQUEST_SCHEMA.to_owned(),
        request_id: "select".to_owned(),
        item,
        action: action.to_owned(),
        requested_scope: requested_scope.to_owned(),
        contract_version,
        contract_digest,
    })
}

fn digest_of(item: ApprovalScopeItemV1) -> String {
    let answer = select(item, "block", "artifact", None);
    answer["contract"]["scope_contract_digest"]
        .as_str()
        .expect("digest")
        .to_owned()
}

#[test]
fn an_offered_scope_is_honoured_as_chosen() {
    let digest = digest_of(bound_review());
    let answer = select(
        bound_review(),
        "allow",
        "artifact",
        Some((APPROVAL_SCOPE_CONTRACT_VERSION, &digest)),
    );
    assert_eq!(answer["outcome"], json!("selected"));
    assert_eq!(answer["requested_scope"], json!("artifact"));
    assert_eq!(answer["applied_scope"], json!("artifact"));
    assert_eq!(answer["warning"], Value::Null);
    assert_eq!(answer["contract"]["scope_contract_digest"], json!(digest));
}

#[test]
fn a_legacy_client_has_its_wider_choice_narrowed_to_the_artifact() {
    let answer = select(bound_review(), "allow", "workspace", None);
    assert_eq!(answer["outcome"], json!("selected"));
    assert_eq!(answer["requested_scope"], json!("workspace"));
    assert_eq!(answer["applied_scope"], json!("artifact"));
    assert_eq!(
        answer["warning"],
        json!("legacy_scope_narrowed_to_artifact")
    );
}

#[test]
fn a_client_that_read_the_contract_is_refused_rather_than_narrowed() {
    let digest = digest_of(bound_review());
    let answer = select(
        bound_review(),
        "allow",
        "workspace",
        Some((APPROVAL_SCOPE_CONTRACT_VERSION, &digest)),
    );
    assert_eq!(answer["outcome"], json!("refused"));
    assert_eq!(answer["reason"], json!("ineligible_request_scope"));
    assert_eq!(answer["contract"]["scope_contract_digest"], json!(digest));
}

#[test]
fn a_block_is_never_narrowed_for_a_legacy_client() {
    let answer = select(bound_review(), "block", "workspace", None);
    assert_eq!(answer["outcome"], json!("refused"));
    assert_eq!(answer["reason"], json!("ineligible_request_scope"));
}

#[test]
fn an_allow_the_request_cannot_offer_at_all_is_not_overridable() {
    let answer = select(unbound_review(), "allow", "workspace", None);
    assert_eq!(answer["outcome"], json!("refused"));
    assert_eq!(answer["reason"], json!("request_action_not_overridable"));
    assert_eq!(
        answer["contract"]["allowed_scopes_by_action"]["allow"],
        json!([])
    );
}

#[test]
fn a_superseded_contract_is_refused_with_the_current_one() {
    for echoed in [
        (APPROVAL_SCOPE_CONTRACT_VERSION, "0".repeat(64)),
        ("guard.approval-scopes.v1", digest_of(bound_review())),
    ] {
        let answer = select(
            bound_review(),
            "allow",
            "artifact",
            Some((echoed.0, &echoed.1)),
        );
        assert_eq!(answer["outcome"], json!("refused"));
        assert_eq!(answer["reason"], json!("stale_scope_contract"));
        assert_eq!(
            answer["contract"]["scope_contract_version"],
            json!(APPROVAL_SCOPE_CONTRACT_VERSION)
        );
    }
}

#[test]
fn half_a_contract_is_not_a_contract() {
    let request = ApprovalScopeSelectRequestV1 {
        schema: APPROVAL_SCOPE_SELECT_REQUEST_SCHEMA.to_owned(),
        request_id: "select".to_owned(),
        item: bound_review(),
        action: "allow".to_owned(),
        requested_scope: "artifact".to_owned(),
        contract_version: Some(APPROVAL_SCOPE_CONTRACT_VERSION.to_owned()),
        contract_digest: None,
    };
    let answer = evaluate(&request);
    assert_eq!(answer["outcome"], json!("refused"));
    assert_eq!(answer["reason"], json!("incomplete_scope_contract"));
}

#[test]
fn an_action_or_scope_guard_does_not_record_is_refused_before_the_contract() {
    let unsupported_action = select(bound_review(), "defer", "artifact", None);
    assert_eq!(
        unsupported_action["reason"],
        json!("unsupported_resolution_action")
    );
    assert_eq!(unsupported_action["contract"], Value::Null);
    let unsupported_scope = select(bound_review(), "allow", "repository", None);
    assert_eq!(
        unsupported_scope["reason"],
        json!("unsupported_approval_scope")
    );
    assert_eq!(unsupported_scope["contract"], Value::Null);
}

//! The persistence and execution-binding gates `apply_approval_resolution`
//! used to decide in Python, each against a contract this op derives itself.

use guard_contracts::{
    ApprovalPersistSelectRequestV1, ApprovalScopeItemV1, APPROVAL_PERSIST_SELECT_REQUEST_SCHEMA,
};
use serde_json::{json, Value};

use super::evaluate;
use crate::approval_scope_material::APPROVAL_SCOPE_CONTRACT_VERSION;

/// A package request with a retry binding and an exact action to save.
fn persistable_package() -> ApprovalScopeItemV1 {
    ApprovalScopeItemV1 {
        artifact_id: Some(json!("pkg:npm/left-pad")),
        artifact_type: Some(json!("package_request")),
        artifact_hash: Some(json!("sha256:left-pad")),
        policy_action: Some(json!("review")),
        ..Default::default()
    }
}

/// A native review with a retry binding but nothing exact to save against.
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

/// The same review with no retry binding and nothing exact to save: an allow
/// here can never reach an execution.
fn unbound_review() -> ApprovalScopeItemV1 {
    ApprovalScopeItemV1 {
        artifact_hash: Some(json!("unbound-request")),
        ..bound_review()
    }
}

/// A native package review with no retry binding whose exact action is still
/// persistable, so a saved allow can bind the agent's next attempt.
fn unbound_but_persistable() -> ApprovalScopeItemV1 {
    ApprovalScopeItemV1 {
        artifact_id: Some(json!("omp:native-pretool:npm-install")),
        artifact_type: Some(json!("package_request")),
        artifact_hash: Some(json!("sha256:npm-install")),
        policy_action: Some(json!("review")),
        ..Default::default()
    }
}

fn persist(
    item: ApprovalScopeItemV1,
    action: &str,
    applied_scope: &str,
    persist_policy: Option<bool>,
    scope_narrowed: bool,
    echoed: Option<(&str, &str)>,
) -> Value {
    let (contract_version, contract_digest) = match echoed {
        Some((version, digest)) => (Some(version.to_owned()), Some(digest.to_owned())),
        None => (None, None),
    };
    evaluate(&ApprovalPersistSelectRequestV1 {
        schema: APPROVAL_PERSIST_SELECT_REQUEST_SCHEMA.to_owned(),
        request_id: "persist".to_owned(),
        item,
        action: action.to_owned(),
        applied_scope: applied_scope.to_owned(),
        persist_policy,
        scope_narrowed,
        contract_version,
        contract_digest,
    })
}

fn digest_of(item: ApprovalScopeItemV1) -> String {
    let answer = persist(item, "block", "artifact", None, false, None);
    answer["contract"]["scope_contract_digest"]
        .as_str()
        .expect("digest")
        .to_owned()
}

#[test]
fn a_remembered_artifact_allow_is_kept_when_the_action_is_persistable() {
    let digest = digest_of(persistable_package());
    let answer = persist(
        persistable_package(),
        "allow",
        "artifact",
        Some(true),
        false,
        Some((APPROVAL_SCOPE_CONTRACT_VERSION, &digest)),
    );
    assert_eq!(answer["outcome"], json!("selected"));
    assert_eq!(answer["persist_policy"], json!(true));
    assert_eq!(answer["contract"]["scope_contract_digest"], json!(digest));
}

#[test]
fn a_remembered_decision_the_request_cannot_bind_is_refused_per_action() {
    for (action, reason) in [
        ("allow", "saved_allow_scope_ineligible"),
        ("block", "saved_block_scope_ineligible"),
    ] {
        let digest = digest_of(bound_review());
        let answer = persist(
            bound_review(),
            action,
            "artifact",
            Some(true),
            false,
            Some((APPROVAL_SCOPE_CONTRACT_VERSION, &digest)),
        );
        assert_eq!(answer["outcome"], json!("refused"));
        assert_eq!(answer["reason"], json!(reason));
        assert_eq!(answer["contract"]["scope_contract_digest"], json!(digest));
    }
}

#[test]
fn a_client_that_read_no_contract_has_its_remember_dropped() {
    let answer = persist(
        persistable_package(),
        "allow",
        "artifact",
        Some(true),
        false,
        None,
    );
    assert_eq!(answer["outcome"], json!("selected"));
    assert_eq!(answer["persist_policy"], Value::Null);
}

#[test]
fn a_narrowed_selection_is_never_remembered() {
    let answer = persist(
        persistable_package(),
        "allow",
        "artifact",
        Some(true),
        true,
        None,
    );
    assert_eq!(answer["outcome"], json!("selected"));
    assert_eq!(answer["persist_policy"], Value::Null);
}

#[test]
fn an_allow_with_no_way_to_run_is_refused() {
    let answer = persist(unbound_review(), "allow", "artifact", None, false, None);
    assert_eq!(answer["outcome"], json!("refused"));
    assert_eq!(answer["reason"], json!("execution_binding_unavailable"));
    assert_eq!(
        answer["contract"]["allowed_scopes_by_action"]["allow"],
        json!([])
    );
}

#[test]
fn a_block_needs_no_execution_binding() {
    let answer = persist(unbound_review(), "block", "artifact", None, false, None);
    assert_eq!(answer["outcome"], json!("selected"));
    assert_eq!(answer["persist_policy"], Value::Null);
}

#[test]
fn an_unbound_allow_saved_against_the_exact_action_still_resolves() {
    let digest = digest_of(unbound_but_persistable());
    let saved = persist(
        unbound_but_persistable(),
        "allow",
        "artifact",
        Some(true),
        false,
        Some((APPROVAL_SCOPE_CONTRACT_VERSION, &digest)),
    );
    assert_eq!(saved["outcome"], json!("selected"));
    assert_eq!(saved["persist_policy"], json!(true));
    assert!(saved["contract"]["scope_restrictions"]
        .as_array()
        .expect("restrictions")
        .contains(&json!("retry_cannot_reuse_approval")));
    // The same request resolved once only has no binding left to run under.
    let once = persist(
        unbound_but_persistable(),
        "allow",
        "artifact",
        None,
        false,
        Some((APPROVAL_SCOPE_CONTRACT_VERSION, &digest)),
    );
    assert_eq!(once["outcome"], json!("refused"));
    assert_eq!(once["reason"], json!("execution_binding_unavailable"));
}

#[test]
fn a_superseded_contract_is_refused_with_the_current_one() {
    for echoed in [
        (APPROVAL_SCOPE_CONTRACT_VERSION, "0".repeat(64)),
        ("guard.approval-scopes.v1", digest_of(persistable_package())),
    ] {
        let answer = persist(
            persistable_package(),
            "allow",
            "artifact",
            Some(true),
            false,
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
    let answer = evaluate(&ApprovalPersistSelectRequestV1 {
        schema: APPROVAL_PERSIST_SELECT_REQUEST_SCHEMA.to_owned(),
        request_id: "persist".to_owned(),
        item: persistable_package(),
        action: "allow".to_owned(),
        applied_scope: "artifact".to_owned(),
        persist_policy: Some(true),
        scope_narrowed: false,
        contract_version: Some(APPROVAL_SCOPE_CONTRACT_VERSION.to_owned()),
        contract_digest: None,
    });
    assert_eq!(answer["outcome"], json!("refused"));
    assert_eq!(answer["reason"], json!("incomplete_scope_contract"));
}

#[test]
fn an_action_or_scope_guard_does_not_record_is_refused_before_the_contract() {
    let unsupported_action = persist(
        persistable_package(),
        "defer",
        "artifact",
        None,
        false,
        None,
    );
    assert_eq!(
        unsupported_action["reason"],
        json!("unsupported_resolution_action")
    );
    assert_eq!(unsupported_action["contract"], Value::Null);
    let unsupported_scope = persist(
        persistable_package(),
        "allow",
        "repository",
        None,
        false,
        None,
    );
    assert_eq!(
        unsupported_scope["reason"],
        json!("unsupported_approval_scope")
    );
    assert_eq!(unsupported_scope["contract"], Value::Null);
}

#[test]
fn a_request_without_the_narrowing_gate_is_refused() {
    // `scope_narrowed` decides whether a selection may be saved at all, so a
    // caller that leaves it out must fail to decode rather than read as false.
    let mut wire = serde_json::to_value(ApprovalPersistSelectRequestV1 {
        schema: APPROVAL_PERSIST_SELECT_REQUEST_SCHEMA.to_owned(),
        request_id: "persist".to_owned(),
        item: persistable_package(),
        action: "allow".to_owned(),
        applied_scope: "artifact".to_owned(),
        persist_policy: Some(true),
        scope_narrowed: false,
        contract_version: None,
        contract_digest: None,
    })
    .expect("wire");
    assert!(serde_json::from_value::<ApprovalPersistSelectRequestV1>(wire.clone()).is_ok());
    wire.as_object_mut()
        .expect("object")
        .remove("scope_narrowed")
        .expect("gate present");
    assert!(serde_json::from_value::<ApprovalPersistSelectRequestV1>(wire).is_err());
}

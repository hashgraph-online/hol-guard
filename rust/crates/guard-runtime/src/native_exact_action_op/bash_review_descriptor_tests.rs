//! Descriptor parsing cannot substitute for the native pending owner record.

use super::*;
use crate::native_bash_review_descriptor::{eligible, validate};
use guard_contracts::{
    ApprovalScopeItemV1, NativeBashReviewDescriptorV1, NativeBashReviewLineageV1,
    NATIVE_BASH_ARTIFACT_ID, NATIVE_BASH_REVIEW_ARTIFACT_TYPE,
    NATIVE_BASH_REVIEW_DESCRIPTOR_SCHEMA,
};
use serde_json::json;

fn descriptor(request: &NativeBashCaptureV1) -> NativeBashReviewDescriptorV1 {
    let policy = admitted("allow");
    let subject = capture_for_launch(request, &policy).unwrap().subject;
    let artifact_hash =
        crate::native_exact_action_op::bash_grant::binding(&subject, &policy).unwrap();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64;
    NativeBashReviewDescriptorV1 {
        schema: NATIVE_BASH_REVIEW_DESCRIPTOR_SCHEMA.into(),
        artifact_id: NATIVE_BASH_ARTIFACT_ID.into(),
        artifact_hash: artifact_hash.clone(),
        subject,
        review_lineage: NativeBashReviewLineageV1 {
            schema: "guard-native-bash-review-lineage.v1".into(),
            operation_id: "descriptor-test-operation".into(),
            lineage_id: "a".repeat(64),
            artifact_hash,
            created_at_ms: now,
            expires_at_ms: now + 86_400_000,
        },
    }
}

#[test]
fn bash_review_descriptor_requires_exact_command_host_and_context_components() {
    let (_root, request) = fixture();
    let descriptor = descriptor(&request);
    assert_eq!(validate(&descriptor, "omp", &request.command), Ok(()));
    for command in [
        format!("{}; printf sibling", request.command),
        request.command.replace(" dry", " delete"),
        format!("env {}", request.command),
        "".into(),
    ] {
        assert!(validate(&descriptor, "omp", &command).is_err());
    }
    assert!(validate(&descriptor, "pi", &request.command).is_err());
    let mut changed = descriptor.clone();
    changed.subject.context.project.push_str("-other");
    assert!(validate(&changed, "omp", &request.command).is_err());
    let mut changed = descriptor.clone();
    changed.subject.code_inputs[0].content_sha256 = "b".repeat(64);
    assert!(validate(&changed, "omp", &request.command).is_err());
    let mut wire = serde_json::to_value(&descriptor).unwrap();
    wire["caller_allows_execution"] = json!(true);
    assert!(serde_json::from_value::<NativeBashReviewDescriptorV1>(wire).is_err());
}

#[test]
fn bash_review_descriptor_without_native_owner_cannot_offer_consent() {
    let (_root, request) = fixture();
    let descriptor = descriptor(&request);
    let wire = serde_json::to_value(&descriptor).unwrap();
    assert!(eligible(
        Some(NATIVE_BASH_REVIEW_ARTIFACT_TYPE),
        Some(NATIVE_BASH_ARTIFACT_ID),
        Some(&descriptor.artifact_hash),
        Some("omp"),
        Some(&request.command),
        Some(&request.workspace),
        Some(&wire),
    ));
    let item = ApprovalScopeItemV1 {
        request_id: Some(json!("caller-pending-id")),
        artifact_type: Some(json!(NATIVE_BASH_REVIEW_ARTIFACT_TYPE)),
        artifact_id: Some(json!(NATIVE_BASH_ARTIFACT_ID)),
        artifact_hash: Some(json!(descriptor.artifact_hash)),
        harness: Some(json!("omp")),
        policy_action: Some(json!("review")),
        config_path: Some(json!(request.workspace)),
        workspace_target: Some(request.workspace),
        raw_command_text: Some(json!(request.command)),
        action_envelope_json: Some(json!({"native_bash":wire})),
        ..Default::default()
    };
    let contract =
        crate::approval_scope_op::contract_value(&crate::approval_scope_contract::contract(
            &crate::approval_scope_contract::View::new(&item),
        ));
    assert_eq!(contract["execution_approval"]["can_run_once"], false);
    assert_eq!(
        contract["execution_approval"]["can_persist_exact_version"],
        false
    );
    assert_eq!(contract["allowed_scopes_by_action"]["allow"], json!([]));
}

use super::*;

pub(in crate::policy_store::workspace_review_business) fn owned_decision(
    fixture: &Fixture,
) -> Value {
    use crate::policy_store::workspace_review_decision::{
        self as decision, WorkspaceReviewDecisionContext,
    };
    use ring::signature::Ed25519KeyPair;
    let time = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64;
    let request =
        crate::policy_store::workspace_review_request::load(&fixture.store, "business-test")
            .unwrap();
    let (workspace, scope) = decision::current_native_workspace_review_bindings(
        &fixture.root,
        &fixture.snapshot.scope_contract.scope_digest,
    )
    .unwrap();
    let mut record = decision::tests::authority_record();
    record.workspace_binding = workspace.clone();
    record.scope_binding = scope.clone();
    record.issued_at_ms = time - 1000;
    record.expires_at_ms = time + 60_000;
    let mut signed = guard_contracts::NATIVE_WORKSPACE_REVIEW_ENROLLMENT_DOMAIN.to_vec();
    signed.extend_from_slice(
        &crate::policy_store::workspace_review_authority::signing_bytes(&record).unwrap(),
    );
    record.enrollment_signature = hex::encode(
        Ed25519KeyPair::from_seed_unchecked(&decision::tests::ROOT_SEED)
            .unwrap()
            .sign(&signed)
            .as_ref(),
    );
    crate::policy_store::approval_enrollment::write_test_enrollment_bindings(
        &fixture.root,
        &record.device_binding,
        &record.installation_binding,
    )
    .unwrap();
    let candidate = decision::tests::write_authority_candidate(&fixture.root, &record);
    crate::policy_store::workspace_review_authority::install_record_at_for_test(
        &fixture.root,
        &candidate,
        time,
    )
    .unwrap();
    let authority =
        crate::policy_store::workspace_review_authority::read_installed_record(&fixture.root, time)
            .unwrap()
            .unwrap();
    let context = WorkspaceReviewDecisionContext {
        workspace_binding: &workspace,
        scope_binding: &scope,
        device_binding: &record.device_binding,
        installation_binding: &record.installation_binding,
        request_binding: &request.request_binding,
        action_binding: &request.action_binding,
        intent_binding: &request.intent_binding,
        revision_binding: &request.revision_binding,
        policy_binding: &request.policy_binding,
        retry_scope_binding: &request.retry_scope_binding,
    };
    let mut envelope = decision::tests::signed_envelope(
        &authority,
        &context,
        53,
        time,
        time + 30_000,
        guard_contracts::NATIVE_WORKSPACE_REVIEW_DECISION_DOMAIN,
    );
    envelope.delivery_mode =
        guard_contracts::NATIVE_WORKSPACE_REVIEW_DECISION_DELIVERY_OWNED_DISPATCH.into();
    let mut signed = guard_contracts::NATIVE_WORKSPACE_REVIEW_DECISION_DOMAIN.to_vec();
    signed.extend_from_slice(&decision::signing_bytes(&envelope).unwrap());
    envelope.decision_signature = hex::encode(
        Ed25519KeyPair::from_seed_unchecked(&decision::tests::REVIEW_SEED)
            .unwrap()
            .sign(&signed)
            .as_ref(),
    );
    serde_json::to_value(envelope).unwrap()
}

#[test]
fn owned_business_claim_keeps_frozen_bytes_and_never_returns_a_retry_grant() {
    let fixture = Fixture::new("owned-dispatch");
    let value = input(b"synthetic frozen mail", &[]);
    fixture.stage(&value);
    let decision = owned_decision(&fixture);
    let bytes = canonical_json_bytes(&decision).unwrap();
    assert_eq!(
        crate::policy_store::workspace_review_decision::verify_and_claim_request(
            &fixture.store,
            "business-test",
            &decision
        )
        .unwrap_err(),
        "native_workspace_review_business_dispatch_unavailable"
    );
    let (claim, retained) =
        crate::policy_store::workspace_review_decision::claim_owned_business_request(
            &fixture.store,
            "business-test",
            &bytes,
        )
        .unwrap();
    assert!(!claim.replayed);
    assert_eq!(retained.primary_bytes(), b"synthetic frozen mail");
    assert!(
        crate::policy_store::workspace_review_decision::claim_owned_business_request(
            &fixture.store,
            "business-test",
            &bytes
        )
        .is_err()
    );
    let replacement = input(b"changed after approval", &[]);
    write(&fixture.root, &fixture.input_path(&value), &replacement);
    assert_eq!(retained.primary_bytes(), b"synthetic frozen mail");
    assert!(
        crate::policy_store::workspace_review_decision::claim_owned_business_request(
            &fixture.store,
            "business-test",
            &bytes
        )
        .is_err()
    );
}

#[test]
fn oversized_or_expired_owned_decision_cannot_consume_a_frozen_request() {
    let fixture = Fixture::new("owned-claim-input-bounds");
    fixture.stage(&input(b"bounded synthetic mail", &[]));
    let decision = owned_decision(&fixture);
    let bytes = canonical_json_bytes(&decision).unwrap();
    let mut oversized = decision.clone();
    oversized["padding"] =
        Value::String("x".repeat(guard_contracts::NATIVE_WORKSPACE_REVIEW_MAX_DECISION_BYTES));
    assert!(
        crate::policy_store::workspace_review_decision::claim_owned_business_request(
            &fixture.store,
            "business-test",
            &canonical_json_bytes(&oversized).unwrap()
        )
        .is_err()
    );
    let expired_at = decision["expires_at_ms"].as_u64().unwrap();
    assert_eq!(
        crate::policy_store::workspace_review_decision::claim_owned_business_request_at_for_test(
            &fixture.store,
            "business-test",
            &bytes,
            [expired_at, expired_at]
        )
        .unwrap_err(),
        "native_workspace_review_decision_expired"
    );
    assert!(
        crate::policy_store::workspace_review_secure_state::load(&fixture.root)
            .unwrap()
            .unwrap()
            .claim_index
            .is_none()
    );
}

#[test]
fn expiry_during_durable_claim_keeps_the_attempt_consumed_without_releasing_input() {
    let fixture = Fixture::new("owned-claim-expiry-during-storage");
    fixture.stage(&input(b"synthetic expiry boundary", &[]));
    let decision = owned_decision(&fixture);
    let bytes = canonical_json_bytes(&decision).unwrap();
    let before = decision["issued_at_ms"].as_u64().unwrap() + 1;
    let expired = decision["expires_at_ms"].as_u64().unwrap();
    assert_eq!(
        crate::policy_store::workspace_review_decision::claim_owned_business_request_at_for_test(
            &fixture.store,
            "business-test",
            &bytes,
            [before, expired]
        )
        .unwrap_err(),
        "native_workspace_review_decision_expired"
    );
    assert!(
        crate::policy_store::workspace_review_secure_state::load(&fixture.root)
            .unwrap()
            .unwrap()
            .claim_index
            .is_some()
    );
    assert!(
        crate::policy_store::workspace_review_decision::claim_owned_business_request(
            &fixture.store,
            "business-test",
            &bytes
        )
        .is_err()
    );
}

#[test]
fn clock_rollback_during_storage_cannot_release_owned_input() {
    let fixture = Fixture::new("owned-claim-clock-rollback");
    fixture.stage(&input(b"synthetic rollback boundary", &[]));
    let decision = owned_decision(&fixture);
    let bytes = canonical_json_bytes(&decision).unwrap();
    let time = decision["issued_at_ms"].as_u64().unwrap();
    assert_eq!(
        crate::policy_store::workspace_review_decision::claim_owned_business_request_at_for_test(
            &fixture.store,
            "business-test",
            &bytes,
            [time + 1, time]
        )
        .unwrap_err(),
        "native_workspace_review_clock_rollback"
    );
    assert!(
        crate::policy_store::workspace_review_secure_state::load(&fixture.root)
            .unwrap()
            .unwrap()
            .claim_index
            .is_some()
    );
}

#[test]
fn malformed_raw_owned_decisions_leave_the_valid_claim_available() {
    let fixture = Fixture::new("owned-claim-strict-raw-decoder");
    fixture.stage(&input(b"synthetic strict decoder boundary", &[]));
    let decision = owned_decision(&fixture);
    let bytes = canonical_json_bytes(&decision).unwrap();
    let duplicate = format!(
        "{{\"decision\":\"allow\",{}",
        std::str::from_utf8(&bytes)
            .unwrap()
            .strip_prefix('{')
            .unwrap()
    )
    .into_bytes();
    let mut deep = decision.clone();
    let mut nested = Value::Null;
    for _ in 0..crate::strict_json::TEST_MAX_JSON_DEPTH + 2 {
        nested = Value::Array(vec![nested]);
    }
    deep["extra"] = nested;
    for invalid in [
        Vec::new(),
        duplicate,
        serde_json::to_vec_pretty(&decision).unwrap(),
        canonical_json_bytes(&deep).unwrap(),
    ] {
        assert!(
            crate::policy_store::workspace_review_decision::claim_owned_business_request(
                &fixture.store,
                "business-test",
                &invalid
            )
            .is_err()
        );
    }
    assert!(
        crate::policy_store::workspace_review_decision::claim_owned_business_request(
            &fixture.store,
            "business-test",
            &bytes
        )
        .is_ok()
    );
}

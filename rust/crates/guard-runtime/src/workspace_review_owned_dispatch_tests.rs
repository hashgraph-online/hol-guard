use super::super::verify_and_claim_at_mode;
use super::*;
use crate::policy_store::{approval_enrollment, workspace_review_secure_state};
use guard_contracts::NATIVE_WORKSPACE_REVIEW_DECISION_DELIVERY_OWNED_DISPATCH;

#[test]
fn owned_dispatch_mode_cannot_enter_retry_or_resume_after_lost_outcome() {
    let root = test_root();
    let authority = install_authority(&root);
    let values = bindings();
    let retry_scope = retry_scope_binding(&values[4], &values[5], &values[6], &values[7]).unwrap();
    let context = context(&values, &retry_scope);
    let mut envelope = signed_envelope(
        &authority,
        &context,
        1,
        NOW_MS,
        61_000,
        NATIVE_WORKSPACE_REVIEW_DECISION_DOMAIN,
    );
    envelope.delivery_mode = NATIVE_WORKSPACE_REVIEW_DECISION_DELIVERY_OWNED_DISPATCH.into();
    // Changing the delivery mode on an existing retry signature is not authority.
    assert!(verify_and_claim_at_mode(
        &root,
        &envelope,
        &context,
        NOW_MS,
        NATIVE_WORKSPACE_REVIEW_DECISION_DELIVERY_OWNED_DISPATCH
    )
    .is_err());
    let mut message = NATIVE_WORKSPACE_REVIEW_DECISION_DOMAIN.to_vec();
    message.extend_from_slice(&signing_bytes(&envelope).unwrap());
    envelope.decision_signature = hex::encode(
        Ed25519KeyPair::from_seed_unchecked(&REVIEW_SEED)
            .unwrap()
            .sign(&message)
            .as_ref(),
    );
    assert!(verify_and_claim_at(&root, &envelope, &context, NOW_MS).is_err());
    let first = verify_and_claim_at_mode(
        &root,
        &envelope,
        &context,
        NOW_MS,
        NATIVE_WORKSPACE_REVIEW_DECISION_DELIVERY_OWNED_DISPATCH,
    )
    .unwrap();
    assert!(!first.replayed);
    assert_eq!(
        verify_and_claim_at_mode(
            &root,
            &envelope,
            &context,
            NOW_MS,
            NATIVE_WORKSPACE_REVIEW_DECISION_DELIVERY_OWNED_DISPATCH
        )
        .unwrap_err(),
        "native_workspace_review_business_dispatch_replay"
    );
    // Reloading durable state models process restart after uncertain delivery.
    assert!(workspace_review_secure_state::load(&root)
        .unwrap()
        .is_some());
    assert_eq!(
        verify_and_claim_at_mode(
            &root,
            &envelope,
            &context,
            NOW_MS,
            NATIVE_WORKSPACE_REVIEW_DECISION_DELIVERY_OWNED_DISPATCH
        )
        .unwrap_err(),
        "native_workspace_review_business_dispatch_replay"
    );
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn concurrent_owned_dispatch_claims_release_only_one_provider_attempt() {
    let root = test_root();
    let authority = install_authority(&root);
    let values = bindings();
    let retry_scope = retry_scope_binding(&values[4], &values[5], &values[6], &values[7]).unwrap();
    let context = context(&values, &retry_scope);
    let mut envelope = signed_envelope(
        &authority,
        &context,
        1,
        NOW_MS,
        61_000,
        NATIVE_WORKSPACE_REVIEW_DECISION_DOMAIN,
    );
    envelope.delivery_mode = NATIVE_WORKSPACE_REVIEW_DECISION_DELIVERY_OWNED_DISPATCH.into();
    let mut message = NATIVE_WORKSPACE_REVIEW_DECISION_DOMAIN.to_vec();
    message.extend_from_slice(&signing_bytes(&envelope).unwrap());
    envelope.decision_signature = hex::encode(
        Ed25519KeyPair::from_seed_unchecked(&REVIEW_SEED)
            .unwrap()
            .sign(&message)
            .as_ref(),
    );
    let attempts = std::sync::atomic::AtomicUsize::new(0);
    let outcomes = std::thread::scope(|scope| {
        let attempt = || {
            approval_enrollment::with_transition_lock(&root, || {
                let claim = verify_and_claim_at_mode(
                    &root,
                    &envelope,
                    &context,
                    NOW_MS,
                    NATIVE_WORKSPACE_REVIEW_DECISION_DELIVERY_OWNED_DISPATCH,
                )?;
                attempts.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                Ok(claim)
            })
        };
        let a = scope.spawn(attempt);
        let b = scope.spawn(attempt);
        [a.join().unwrap(), b.join().unwrap()]
    });
    assert_eq!(outcomes.iter().filter(|r| r.is_ok()).count(), 1);
    assert_eq!(attempts.load(std::sync::atomic::Ordering::SeqCst), 1);
    assert!(
        outcomes.iter().any(|r| r
            .as_ref()
            .err()
            .is_some_and(|e| e == "native_workspace_review_business_dispatch_replay"
                || e == "native_approval_authority_busy")),
        "{outcomes:?}"
    );
    // A busy caller can retry acquisition, but never obtain a second attempt.
    let retry = approval_enrollment::with_transition_lock(&root, || {
        verify_and_claim_at_mode(
            &root,
            &envelope,
            &context,
            NOW_MS,
            NATIVE_WORKSPACE_REVIEW_DECISION_DELIVERY_OWNED_DISPATCH,
        )
    });
    assert_eq!(
        retry.unwrap_err(),
        "native_workspace_review_business_dispatch_replay"
    );
    assert_eq!(attempts.load(std::sync::atomic::Ordering::SeqCst), 1);
    fs::remove_dir_all(root).unwrap();
}

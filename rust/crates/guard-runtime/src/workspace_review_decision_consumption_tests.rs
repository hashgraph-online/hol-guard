use super::*;
use crate::policy_store::workspace_review_decision::claim_semantics;
use crate::policy_store::workspace_review_decision::query_consumption_at;
use crate::policy_store::workspace_review_decision::semantic_decision_digest;
use crate::policy_store::workspace_review_secure_state;
use crate::policy_store::workspace_review_secure_state::WorkspaceReviewClaimV1;

#[test]
fn consumption_query_is_read_only_and_requires_positive_matching_history() {
    let root = test_root();
    let authority = install_authority(&root);
    let values = bindings();
    let retry = retry_scope_binding(&values[4], &values[5], &values[6], &values[7]).unwrap();
    let context = context(&values, &retry);
    let envelope = signed_envelope(
        &authority,
        &context,
        91,
        NOW_MS,
        61_000,
        NATIVE_WORKSPACE_REVIEW_DECISION_DOMAIN,
    );
    let before = workspace_review_secure_state::load(&root).unwrap().unwrap();
    assert_eq!(
        query_consumption_at(&root, &envelope, &context, NOW_MS).unwrap_err(),
        "native_workspace_review_consumption_unconfirmed",
    );
    assert_eq!(
        before,
        workspace_review_secure_state::load(&root).unwrap().unwrap()
    );
    verify_and_claim_at(&root, &envelope, &context, NOW_MS).unwrap();
    let consumed = workspace_review_secure_state::load(&root).unwrap().unwrap();
    assert!(
        query_consumption_at(&root, &envelope, &context, NOW_MS)
            .unwrap()
            .replayed
    );
    let renewed = signed_envelope(
        &authority,
        &context,
        91,
        NOW_MS + 1,
        61_001,
        NATIVE_WORKSPACE_REVIEW_DECISION_DOMAIN,
    );
    assert!(
        query_consumption_at(&root, &renewed, &context, NOW_MS + 1)
            .unwrap()
            .replayed
    );
    let mut stale_authority = envelope.clone();
    stale_authority.authority_generation += 1;
    assert!(query_consumption_at(&root, &stale_authority, &context, NOW_MS).is_err());
    let mut wrong_context = context.clone();
    wrong_context.request_binding = &values[7];
    assert!(query_consumption_at(&root, &envelope, &wrong_context, NOW_MS).is_err());
    assert_eq!(
        consumed,
        workspace_review_secure_state::load(&root).unwrap().unwrap()
    );
    let duplicate = signed_envelope(
        &authority,
        &context,
        92,
        NOW_MS,
        61_000,
        NATIVE_WORKSPACE_REVIEW_DECISION_DOMAIN,
    );
    assert_eq!(
        query_consumption_at(&root, &duplicate, &context, NOW_MS).unwrap_err(),
        "native_workspace_review_decision_replay",
    );
    assert!(query_consumption_at(&root, &envelope, &context, 61_000).is_err());
    assert_eq!(
        consumed,
        workspace_review_secure_state::load(&root).unwrap().unwrap()
    );
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn consumption_query_rejects_corrupt_index_and_preserves_legacy_exact_envelope() {
    let root = test_root();
    let authority = install_authority(&root);
    let values = bindings();
    let retry = retry_scope_binding(&values[4], &values[5], &values[6], &values[7]).unwrap();
    let context = context(&values, &retry);
    let envelope = signed_envelope(
        &authority,
        &context,
        93,
        NOW_MS,
        61_000,
        NATIVE_WORKSPACE_REVIEW_DECISION_DOMAIN,
    );
    let verified = verify_and_claim_at(&root, &envelope, &context, NOW_MS).unwrap();
    let mut state = workspace_review_secure_state::load(&root).unwrap().unwrap();
    state.claim_index.as_mut().unwrap().root = "f".repeat(64);
    assert!(claim_semantics::query_consumed_claim(
        &root,
        &state,
        &verified,
        &semantic_decision_digest(&envelope).unwrap(),
    )
    .is_err());
    state.claim_index = None;
    state.consumed_claims = vec![WorkspaceReviewClaimV1 {
        claim_id: verified.claim_id.clone(),
        envelope_digest: verified.envelope_digest.clone(),
        semantic_decision_digest: None,
        legacy_semantic_recovered: false,
        expires_at_ms: Some(envelope.expires_at_ms),
    }];
    let semantic = semantic_decision_digest(&envelope).unwrap();
    assert!(claim_semantics::query_consumed_claim(&root, &state, &verified, &semantic).unwrap());
    let mut changed = verified;
    changed.envelope_digest = "f".repeat(64);
    assert_eq!(
        claim_semantics::query_consumed_claim(&root, &state, &changed, &semantic).unwrap_err(),
        "native_workspace_review_decision_replay",
    );
    state.consumed_claims[0].semantic_decision_digest = Some(semantic.clone());
    assert!(claim_semantics::query_consumed_claim(&root, &state, &changed, &semantic).unwrap());
    state.consumed_claims[0].legacy_semantic_recovered = true;
    assert_eq!(
        claim_semantics::query_consumed_claim(&root, &state, &changed, &semantic).unwrap_err(),
        "native_workspace_review_decision_replay",
    );
    fs::remove_dir_all(root).unwrap();
}

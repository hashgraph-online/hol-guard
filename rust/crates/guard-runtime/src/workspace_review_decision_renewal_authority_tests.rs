use super::super::super::workspace_review_decision::retry_scope_binding;
use super::super::super::workspace_review_secure_state;
use super::*;

#[test]
fn expired_renewal_and_clock_rollback_do_not_mutate_claim_state() {
    let (root, authority, values, retry_scope) = setup();
    let context = context(&values, &retry_scope);
    let first = signed_envelope(
        &authority,
        &context,
        6,
        NOW_MS,
        NOW_MS + 100,
        "allow",
        &REVIEW_SEED,
    );
    verify_and_claim_at(&root, &first, &context, NOW_MS).unwrap();
    let renewed = signed_envelope(
        &authority,
        &context,
        6,
        NOW_MS + 200,
        NOW_MS + 250,
        "allow",
        &REVIEW_SEED,
    );
    assert_eq!(
        verify_and_claim_at(&root, &renewed, &context, NOW_MS + 300).unwrap_err(),
        "native_workspace_review_decision_expired"
    );
    assert_eq!(
        verify_and_claim_at(&root, &first, &context, NOW_MS - 1).unwrap_err(),
        "native_workspace_review_clock_rollback"
    );
    let state = workspace_review_secure_state::load(&root).unwrap().unwrap();
    assert!(state.consumed_claims.is_empty());
    assert_eq!(state.claim_index.unwrap().claim_count, 1);
    fs::remove_dir_all(root).unwrap();
}

fn consumed_grant_count(root: &Path) -> u64 {
    let state = workspace_review_secure_state::load(root).unwrap().unwrap();
    state
        .claim_index
        .as_ref()
        .map(|index| index.claim_count)
        .unwrap_or(0)
        + u64::try_from(state.consumed_claims.len()).unwrap()
}

#[test]
fn aged_unconsumed_proof_does_not_authorize_and_one_fresh_proof_consumes_once() {
    let (root, authority, values, retry_scope) = setup();
    let original = context(&values, &retry_scope);
    let expired = signed_envelope(
        &authority,
        &original,
        11,
        NOW_MS,
        NOW_MS + 100,
        "allow",
        &REVIEW_SEED,
    );
    assert_eq!(
        verify_and_claim_at(&root, &expired, &original, NOW_MS + 100).unwrap_err(),
        "native_workspace_review_decision_expired"
    );
    assert_eq!(consumed_grant_count(&root), 0);

    let fresh = signed_envelope(
        &authority,
        &original,
        12,
        NOW_MS + 200,
        NOW_MS + 5_000,
        "allow",
        &REVIEW_SEED,
    );
    assert_ne!(expired.claim_id, fresh.claim_id);
    assert_eq!(
        semantic_decision_digest(&expired).unwrap(),
        semantic_decision_digest(&fresh).unwrap()
    );
    let applied = verify_and_claim_at(&root, &fresh, &original, NOW_MS + 200).unwrap();
    assert!(!applied.replayed);
    assert_eq!(applied.decision, "allow");
    assert_eq!(consumed_grant_count(&root), 1);

    let resumed = verify_and_claim_at(&root, &fresh, &original, NOW_MS + 300).unwrap();
    assert!(resumed.replayed);
    assert_eq!(consumed_grant_count(&root), 1);

    let second_nonce = signed_envelope(
        &authority,
        &original,
        13,
        NOW_MS + 400,
        NOW_MS + 5_000,
        "allow",
        &REVIEW_SEED,
    );
    assert_eq!(
        verify_and_claim_at(&root, &second_nonce, &original, NOW_MS + 400).unwrap_err(),
        "native_workspace_review_decision_replay"
    );
    assert_eq!(consumed_grant_count(&root), 1);

    let mut changed_values = values.clone();
    changed_values[4] = "9".repeat(64);
    let changed_retry = retry_scope_binding(
        &changed_values[4],
        &changed_values[5],
        &changed_values[6],
        &changed_values[7],
    )
    .unwrap();
    let changed = context(&changed_values, &changed_retry);
    let changed_action = signed_envelope(
        &authority,
        &changed,
        14,
        NOW_MS + 500,
        NOW_MS + 5_000,
        "allow",
        &REVIEW_SEED,
    );
    assert_eq!(
        verify_and_claim_at(&root, &changed_action, &original, NOW_MS + 500).unwrap_err(),
        "native_workspace_review_decision_binding_mismatch"
    );
    assert_eq!(consumed_grant_count(&root), 1);
    fs::remove_dir_all(root).unwrap();
}

#[path = "workspace_review_claim_capacity_tests.rs"]
mod capacity_tests;

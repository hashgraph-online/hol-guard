use super::*;
use crate::policy_store::workspace_review_decision::retry_scope_binding;
use crate::policy_store::{workspace_review_claim_index, workspace_review_secure_state};
use guard_contracts::NATIVE_WORKSPACE_REVIEW_MAX_REPLAY_ENTRIES;

fn stored_claim(index: usize) -> workspace_review_secure_state::WorkspaceReviewClaimV1 {
    workspace_review_secure_state::WorkspaceReviewClaimV1 {
        claim_id: format!("{index:064x}"),
        envelope_digest: format!("{:064x}", index + 1),
        semantic_decision_digest: Some(format!("{:064x}", index + 2)),
        legacy_semantic_recovered: false,
        expires_at_ms: Some(NOW_MS - 1),
    }
}

fn partial_state(root: &Path) -> workspace_review_secure_state::WorkspaceReviewSecureStateV1 {
    let mut state = workspace_review_secure_state::load(root).unwrap().unwrap();
    let digest = workspace_review_claim_index::insert_claim(root, None, &stored_claim(1)).unwrap();
    workspace_review_claim_index::sync_directories_before_commit(root).unwrap();
    state.claim_index = Some(workspace_review_claim_index::ClaimIndexAnchor {
        root: digest,
        claim_count: 1,
    });
    state.consumed_claims.push(stored_claim(2));
    workspace_review_secure_state::store(root, &state).unwrap();
    state
}

#[test]
fn migration_drains_the_legacy_tail_and_preserves_every_consumed_claim() {
    let (root, _, _, _) = setup();
    let mut state = workspace_review_secure_state::load(&root).unwrap().unwrap();
    state.consumed_claims = (0..3).map(stored_claim).collect();
    workspace_review_secure_state::store(&root, &state).unwrap();
    for index in 3..7 {
        workspace_review_secure_state::record_claim(&root, &mut state, stored_claim(index))
            .unwrap();
        state = workspace_review_secure_state::load(&root).unwrap().unwrap();
        assert_eq!(state.consumed_claims.len(), 5_usize.saturating_sub(index));
    }
    let anchor = state.claim_index.unwrap();
    assert_eq!(anchor.claim_count, 7);
    for index in 0..7 {
        assert_eq!(
            workspace_review_claim_index::find_claim(&root, &anchor, &stored_claim(index).claim_id)
                .unwrap(),
            Some(stored_claim(index))
        );
    }
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn missing_semantic_copy_rejects_an_otherwise_valid_signed_replay() {
    let (root, authority, values, retry_scope) = setup();
    let context = context(&values, &retry_scope);
    let envelope = signed_envelope(
        &authority,
        &context,
        1,
        NOW_MS,
        61_000,
        "allow",
        &REVIEW_SEED,
    );
    verify_and_claim_at(&root, &envelope, &context, NOW_MS).unwrap();
    let mut semantic_key = b"guard-workspace-review-claim-index-key\0semantic\0".to_vec();
    semantic_key.extend_from_slice(semantic_decision_digest(&envelope).unwrap().as_bytes());
    let semantic_key = digest_bytes(&semantic_key);
    let mut removed = false;
    for shard in fs::read_dir(root.join("workspace-review-claims")).unwrap() {
        for entry in fs::read_dir(shard.unwrap().path()).unwrap() {
            let path = entry.unwrap().path();
            let value: serde_json::Value =
                serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
            if value["kind"] == "leaf" && value["key"] == semantic_key {
                fs::remove_file(path).unwrap();
                removed = true;
            }
        }
    }
    assert!(removed);
    let state = workspace_review_secure_state::load(&root).unwrap().unwrap();
    assert!(workspace_review_claim_index::find_claim(
        &root,
        state.claim_index.as_ref().unwrap(),
        &envelope.claim_id
    )
    .unwrap()
    .is_some());
    assert!(verify_and_claim_at(&root, &envelope, &context, NOW_MS).is_err());
    assert_eq!(
        workspace_review_secure_state::load(&root).unwrap().unwrap(),
        state
    );
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn failed_node_persistence_leaves_the_previous_secure_anchor_authoritative() {
    use crate::policy_store::{PersistBoundary, PERSIST_FAILPOINT};
    for boundary in [
        PersistBoundary::TemporaryCreate,
        PersistBoundary::Write,
        PersistBoundary::FileSync,
        PersistBoundary::Rename,
        PersistBoundary::DirectorySync,
    ] {
        let (root, _, _, _) = setup();
        let original = partial_state(&root);
        let mut attempted = original.clone();
        PERSIST_FAILPOINT.with(|point| point.set(boundary as u8));
        assert!(workspace_review_secure_state::record_claim(
            &root,
            &mut attempted,
            stored_claim(3)
        )
        .is_err());
        assert_eq!(
            workspace_review_secure_state::load(&root).unwrap().unwrap(),
            original
        );
        assert_eq!(attempted, original);
        workspace_review_secure_state::record_claim(&root, &mut attempted, stored_claim(3))
            .unwrap();
        assert_eq!(attempted.claim_index.as_ref().unwrap().claim_count, 3);
        assert!(attempted.consumed_claims.is_empty());
        fs::remove_dir_all(root).unwrap();
    }
}

#[test]
fn uncertain_secure_anchor_commit_is_reconciled_by_reload() {
    use crate::policy_store::{PersistBoundary, PERSIST_FAILPOINT};
    let (root, _, _, _) = setup();
    let original = partial_state(&root);
    // Prepare exactly the same immutable objects so the injected failure hits
    // the secure anchor's post-rename durability boundary, not a node write.
    let migrated_root = workspace_review_claim_index::insert_claim(
        &root,
        Some(&original.claim_index.as_ref().unwrap().root),
        &stored_claim(2),
    )
    .unwrap();
    workspace_review_claim_index::insert_claim(&root, Some(&migrated_root), &stored_claim(3))
        .unwrap();
    workspace_review_claim_index::sync_directories_before_commit(&root).unwrap();
    let mut attempted = original.clone();
    PERSIST_FAILPOINT.with(|point| point.set(PersistBoundary::DirectorySync as u8));
    assert!(
        workspace_review_secure_state::record_claim(&root, &mut attempted, stored_claim(3))
            .is_err()
    );
    assert_eq!(attempted, original);
    let restarted = workspace_review_secure_state::load(&root).unwrap().unwrap();
    assert!(restarted.consumed_claims.is_empty());
    let anchor = restarted.claim_index.unwrap();
    assert_eq!(anchor.claim_count, 3);
    assert_eq!(
        workspace_review_claim_index::find_claim(&root, &anchor, &stored_claim(3).claim_id)
            .unwrap(),
        Some(stored_claim(3))
    );
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn permanent_claims_migrate_incrementally_without_pruning_at_legacy_capacity() {
    let (root, authority, values, retry_scope) = setup();
    let context = context(&values, &retry_scope);
    let mut state = workspace_review_secure_state::load(&root).unwrap().unwrap();
    state.consumed_claims = (0..NATIVE_WORKSPACE_REVIEW_MAX_REPLAY_ENTRIES)
        .map(
            |index| workspace_review_secure_state::WorkspaceReviewClaimV1 {
                claim_id: format!("{index:064x}"),
                envelope_digest: format!("{:064x}", index + 1),
                semantic_decision_digest: Some(format!("{:064x}", index + 2)),
                legacy_semantic_recovered: false,
                expires_at_ms: Some(NOW_MS - 1),
            },
        )
        .collect();
    workspace_review_secure_state::store(&root, &state).unwrap();
    let envelope = signed_envelope(
        &authority,
        &context,
        1,
        NOW_MS,
        61_000,
        "allow",
        &REVIEW_SEED,
    );
    assert!(
        !verify_and_claim_at(&root, &envelope, &context, NOW_MS)
            .unwrap()
            .replayed
    );
    let updated = workspace_review_secure_state::load(&root).unwrap().unwrap();
    let anchor = updated.claim_index.as_ref().unwrap();
    assert_eq!(anchor.claim_count, 2);
    assert_eq!(
        updated.consumed_claims.len(),
        NATIVE_WORKSPACE_REVIEW_MAX_REPLAY_ENTRIES - 1
    );
    let indexed = workspace_review_claim_index::find_claim(
        &root,
        anchor,
        &format!("{:064x}", NATIVE_WORKSPACE_REVIEW_MAX_REPLAY_ENTRIES - 1),
    )
    .unwrap()
    .unwrap();
    assert_eq!(indexed.expires_at_ms, Some(NOW_MS - 1));
    assert_eq!(updated.consumed_claims[0].expires_at_ms, Some(NOW_MS - 1));
    assert!(
        verify_and_claim_at(&root, &envelope, &context, NOW_MS)
            .unwrap()
            .replayed
    );

    let mut next_values = values.clone();
    next_values[5] = "9".repeat(64);
    let next_retry_scope = retry_scope_binding(
        &next_values[4],
        &next_values[5],
        &next_values[6],
        &next_values[7],
    )
    .unwrap();
    let next_context = super::context(&next_values, &next_retry_scope);
    let next = signed_envelope(
        &authority,
        &next_context,
        2,
        NOW_MS,
        61_000,
        "allow",
        &REVIEW_SEED,
    );
    assert!(
        !verify_and_claim_at(&root, &next, &next_context, NOW_MS)
            .unwrap()
            .replayed
    );
    let restarted = workspace_review_secure_state::load(&root).unwrap().unwrap();
    assert_eq!(restarted.claim_index.unwrap().claim_count, 4);
    assert_eq!(
        restarted.consumed_claims.len(),
        NATIVE_WORKSPACE_REVIEW_MAX_REPLAY_ENTRIES - 2
    );
    assert!(
        verify_and_claim_at(&root, &envelope, &context, NOW_MS)
            .unwrap()
            .replayed
    );
    fs::remove_dir_all(root).unwrap();
}

use super::*;

#[test]
fn authority_expiry_observation_survives_wall_clock_rollback() {
    let root = test_root();
    let authority = install_authority(&root);
    let values = bindings();
    let retry_scope = retry_scope_binding(&values[4], &values[5], &values[6], &values[7]).unwrap();
    let context = context(&values, &retry_scope);
    let envelope = signed_envelope(
        &authority,
        &context,
        12,
        NOW_MS,
        60_500,
        NATIVE_WORKSPACE_REVIEW_DECISION_DOMAIN,
    );

    assert_eq!(
        verify_and_claim_at(&root, &envelope, &context, authority.expires_at_ms).unwrap_err(),
        "native_workspace_review_authority_expired"
    );
    let state = crate::policy_store::workspace_review_secure_state::load(&root)
        .unwrap()
        .unwrap();
    assert_eq!(state.last_observed_time_ms, authority.expires_at_ms);
    assert_eq!(
        verify_and_claim_at(&root, &envelope, &context, authority.expires_at_ms - 1).unwrap_err(),
        "native_workspace_review_clock_rollback"
    );
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn native_scope_provenance_rejects_mismatched_current_scope_and_workspace() {
    let root = test_root();
    let authority = install_authority(&root);
    let (_, scope_digest) =
        super::super::super::policy_store_authority::scope_binding_for_state_base(&root);
    let (workspace_binding, scope_binding) =
        super::super::current_native_workspace_review_bindings(&root, &scope_digest).unwrap();

    let mut correctly_bound = authority.clone();
    correctly_bound.workspace_binding = workspace_binding.clone();
    correctly_bound.scope_binding = scope_binding.clone();
    assert!(
        super::super::ensure_current_native_workspace_review_provenance(
            &correctly_bound,
            &workspace_binding,
            &scope_binding,
        )
        .is_ok()
    );

    let mut wrong_workspace = correctly_bound.clone();
    wrong_workspace.workspace_binding = "f".repeat(64);
    assert_eq!(
        super::super::ensure_current_native_workspace_review_provenance(
            &wrong_workspace,
            &workspace_binding,
            &scope_binding,
        )
        .unwrap_err(),
        "native_workspace_review_authority_provenance_mismatch"
    );

    let mut wrong_scope = correctly_bound;
    wrong_scope.scope_binding = "e".repeat(64);
    assert_eq!(
        super::super::ensure_current_native_workspace_review_provenance(
            &wrong_scope,
            &workspace_binding,
            &scope_binding,
        )
        .unwrap_err(),
        "native_workspace_review_authority_provenance_mismatch"
    );
    assert_eq!(
        super::super::current_native_workspace_review_bindings(&root, &"d".repeat(64)).unwrap_err(),
        "native_policy_snapshot_scope_mismatch"
    );
    fs::remove_dir_all(root).unwrap();
}

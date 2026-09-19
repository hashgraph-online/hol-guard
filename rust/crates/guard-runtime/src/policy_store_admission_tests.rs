//! Admission preserves immutable compiled generations and current references.

use super::*;

#[test]
fn restart_rehydrates_snapshot_and_hook_validation_uses_memory() {
    let root = test_root("restart");
    let key = install_test_key(&root, 9);
    let store = PolicySnapshotStore::new(&root, &"a".repeat(64)).unwrap();
    let snapshot = signed_snapshot(4, &key, &root);
    let request = serde_json::json!({
        "schema": POLICY_SNAPSHOT_PUSH_SCHEMA,
        "snapshot": snapshot,
    });
    store.push(&request).unwrap();
    let restored = PolicySnapshotStore::new(&root, &"a".repeat(64)).unwrap();
    assert_eq!(restored.current_generation(), Some(4));
    let snapshot_value = request["snapshot"].clone();
    assert!(restored
        .validate_request_snapshot(&snapshot_value, root.to_string_lossy().as_ref(), 4,)
        .is_ok());
    let compact_reference = serde_json::json!({
        "generation": snapshot.generation,
        "policy_digest": snapshot.policy_digest.clone(),
        "runtime_identity": snapshot.runtime_identity.clone(),
    });
    assert!(restored
        .validate_request_snapshot(&compact_reference, root.to_string_lossy().as_ref(), 4,)
        .is_ok());
    fs::remove_file(root.join(SNAPSHOT_FILE_NAME)).unwrap();
    assert_eq!(
        restored
            .validate_request_snapshot(&snapshot_value, root.to_string_lossy().as_ref(), 4,)
            .unwrap_err(),
        "native_policy_snapshot_context_mismatch"
    );
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn compiled_generations_share_one_immutable_snapshot_and_reject_conflicts_before_publish() {
    use std::sync::Arc;
    let root = test_root("compiled-generations");
    let key = install_test_key(&root, 21);
    let store = PolicySnapshotStore::new(&root, &"a".repeat(64)).unwrap();
    let mut effective = policy();
    effective
        .harness_actions
        .insert("Claude".into(), "block".into());
    effective
        .harness_actions
        .insert("claude-code".into(), "block".into());
    let first = signed_snapshot_with_policy(1, &key, &root, effective.clone());
    let first_value = serde_json::to_value(&first).unwrap();
    store
        .push(&serde_json::json!({"schema": POLICY_SNAPSHOT_PUSH_SCHEMA, "snapshot": first}))
        .unwrap();
    let get_first = || {
        store
            .validate_request_snapshot(&first_value, root.to_string_lossy().as_ref(), 1)
            .unwrap()
    };
    let retained = get_first();
    assert!(Arc::ptr_eq(&retained, &get_first()));
    assert_eq!(retained.snapshot(), &first);

    effective
        .harness_actions
        .insert("claude-code".into(), "allow".into());
    let invalid = signed_snapshot_with_policy(2, &key, &root, effective);
    let authority_before = fs::read(root.join(SNAPSHOT_FILE_NAME)).unwrap();
    assert_eq!(
        store
            .push(&serde_json::json!({"schema": POLICY_SNAPSHOT_PUSH_SCHEMA, "snapshot": invalid}))
            .unwrap_err(),
        "snapshot_policy_invalid"
    );
    assert_eq!(
        fs::read(root.join(SNAPSHOT_FILE_NAME)).unwrap(),
        authority_before
    );
    assert!(Arc::ptr_eq(&retained, &get_first()));

    let second = signed_snapshot_with_policy(2, &key, &root, policy_with_default("allow"));
    let second_value = serde_json::to_value(&second).unwrap();
    store
        .push(&serde_json::json!({"schema": POLICY_SNAPSHOT_PUSH_SCHEMA, "snapshot": second}))
        .unwrap();
    let current = store
        .validate_request_snapshot(&second_value, root.to_string_lossy().as_ref(), 2)
        .unwrap();
    assert!(!Arc::ptr_eq(&retained, &current));
    assert_eq!(retained.snapshot(), &first);
    assert_eq!(
        store
            .validate_request_snapshot(&first_value, root.to_string_lossy().as_ref(), 1)
            .unwrap_err(),
        "native_policy_snapshot_not_current"
    );
    let restored = PolicySnapshotStore::new(&root, &"a".repeat(64)).unwrap();
    assert_eq!(restored.current_snapshot().unwrap(), second);
    fs::remove_dir_all(root).unwrap();
}

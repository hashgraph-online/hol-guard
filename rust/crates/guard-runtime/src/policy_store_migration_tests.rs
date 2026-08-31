use super::*;

#[test]
fn legacy_snapshot_and_floor_migrate_to_one_authority_record() {
    let root = test_root("legacy-migration");
    let key = install_test_key(&root, 13);
    let snapshot = signed_snapshot(7, &key, &root);
    let snapshot_value = serde_json::to_value(&snapshot).unwrap();
    fs::write(
        root.join(SNAPSHOT_FILE_NAME),
        canonical_json_bytes(&snapshot_value).unwrap(),
    )
    .unwrap();
    protect_test_file(&root.join(SNAPSHOT_FILE_NAME));
    #[cfg(unix)]
    fs::set_permissions(
        root.join(SNAPSHOT_FILE_NAME),
        fs::Permissions::from_mode(0o600),
    )
    .unwrap();
    let floor_value = legacy_floor_value(7, &snapshot.policy_digest, &key);
    fs::write(
        root.join(GENERATION_FLOOR_FILE_NAME),
        canonical_json_bytes(&floor_value).unwrap(),
    )
    .unwrap();
    protect_test_file(&root.join(GENERATION_FLOOR_FILE_NAME));
    #[cfg(unix)]
    fs::set_permissions(
        root.join(GENERATION_FLOOR_FILE_NAME),
        fs::Permissions::from_mode(0o600),
    )
    .unwrap();

    PolicySnapshotStore::migrate_legacy_state(&root, &"a".repeat(64)).unwrap();
    let store = PolicySnapshotStore::new(&root, &"a".repeat(64)).unwrap();
    assert_eq!(store.current_generation(), Some(7));
    let (authority, _) = read_private_json(
        &root.join(SNAPSHOT_FILE_NAME),
        AUTHORITY_RECORD_MAX_BYTES,
        "state",
    )
    .unwrap()
    .unwrap();
    assert_eq!(authority["schema"], AUTHORITY_RECORD_SCHEMA);
    assert_eq!(authority["generation_floor"], 7);
    assert!(authority["snapshot"].is_object());
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn floor_only_migration_preserves_generation_and_allows_only_newer_push() {
    let root = test_root("floor-only-migration");
    let key = install_test_key(&root, 14);
    let digest = "b".repeat(64);
    let floor_value = legacy_floor_value(9, &digest, &key);
    fs::write(
        root.join(GENERATION_FLOOR_FILE_NAME),
        canonical_json_bytes(&floor_value).unwrap(),
    )
    .unwrap();
    protect_test_file(&root.join(GENERATION_FLOOR_FILE_NAME));
    #[cfg(unix)]
    fs::set_permissions(
        root.join(GENERATION_FLOOR_FILE_NAME),
        fs::Permissions::from_mode(0o600),
    )
    .unwrap();
    PolicySnapshotStore::migrate_legacy_state(&root, &"a".repeat(64)).unwrap();
    let store = PolicySnapshotStore::new(&root, &"a".repeat(64)).unwrap();
    assert_eq!(store.current_generation(), None);
    let older_snapshot = signed_snapshot(8, &key, &root);
    let older_request = serde_json::json!({
        "schema": POLICY_SNAPSHOT_PUSH_SCHEMA,
        "snapshot": older_snapshot,
    });
    let older_ack: PolicySnapshotAckV1 =
        serde_json::from_slice(&store.push(&older_request).unwrap()).unwrap();
    assert_eq!(
        older_ack.status,
        guard_policy_snapshot::POLICY_SNAPSHOT_ACK_REQUIRES_NEW_GENERATION
    );
    assert_eq!(older_ack.generation, 9);
    assert_eq!(older_ack.policy_digest, digest);
    assert!(!older_ack.idempotent);
    let equal_snapshot = signed_snapshot(9, &key, &root);
    let equal_request = serde_json::json!({
        "schema": POLICY_SNAPSHOT_PUSH_SCHEMA,
        "snapshot": equal_snapshot,
    });
    let equal_ack: PolicySnapshotAckV1 = serde_json::from_slice(
        &crate::evaluate_resident_bytes(
            &canonical_json_bytes(&serde_json::json!({
                "operation": "policy_snapshot_push",
                "request": equal_request,
            }))
            .unwrap(),
            Some(&store),
        )
        .unwrap(),
    )
    .unwrap();
    assert_eq!(
        equal_ack.status,
        guard_policy_snapshot::POLICY_SNAPSHOT_ACK_REQUIRES_NEW_GENERATION
    );
    assert_eq!(equal_ack.generation, 9);
    assert_eq!(equal_ack.policy_digest, digest);
    assert!(!equal_ack.idempotent);
    let snapshot = signed_snapshot(10, &key, &root);
    let request = serde_json::json!({
        "schema": POLICY_SNAPSHOT_PUSH_SCHEMA,
        "snapshot": snapshot,
    });
    let ack: PolicySnapshotAckV1 = serde_json::from_slice(&store.push(&request).unwrap()).unwrap();
    assert_eq!(ack.generation, 10);
    fs::remove_dir_all(root).unwrap();
}

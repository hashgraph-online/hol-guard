use super::*;

#[test]
fn authority_write_failures_at_each_boundary_are_retryable_without_rollback() {
    for boundary in [
        PersistBoundary::TemporaryCreate,
        PersistBoundary::Write,
        PersistBoundary::FileSync,
        PersistBoundary::Rename,
        PersistBoundary::DirectorySync,
    ] {
        let root = test_root("fault-boundary");
        let key = install_test_key(&root, boundary as u8 + 20);
        let store = PolicySnapshotStore::new(&root, &"a".repeat(64)).unwrap();
        let snapshot = signed_snapshot(1, &key, &root);
        let request = serde_json::json!({
            "schema": POLICY_SNAPSHOT_PUSH_SCHEMA,
            "snapshot": snapshot,
        });
        PERSIST_FAILPOINT.with(|failpoint| failpoint.set(boundary as u8));
        assert!(store.push(&request).is_err());
        let restarted = PolicySnapshotStore::new(&root, &"a".repeat(64)).unwrap();
        let ack: PolicySnapshotAckV1 =
            serde_json::from_slice(&restarted.push(&request).unwrap()).unwrap();
        if matches!(boundary, PersistBoundary::DirectorySync) {
            assert!(ack.idempotent);
        } else {
            assert!(!ack.idempotent);
        }
        let has_temporary = fs::read_dir(&root)
            .unwrap()
            .filter_map(Result::ok)
            .any(|entry| entry.file_name().to_string_lossy().ends_with(".tmp"));
        assert!(!has_temporary);
        fs::remove_dir_all(root).unwrap();
    }
    PERSIST_FAILPOINT.with(|failpoint| failpoint.set(0));
}

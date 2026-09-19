use super::*;

#[test]
fn scoped_authority_withdrawal_closes_native_admission_and_preserves_floor() {
    let root = test_root("withdraw-scoped");
    let key = install_test_key(&root, 51);
    let store =
        PolicySnapshotStore::new_with_resident_generation(&root, &"a".repeat(64), 14).unwrap();
    let candidate = snapshot_v4(3, &key, &root);
    store.push(&push_value(&candidate)).unwrap();
    assert!(store
        .validate_versioned_request_snapshot(&reference(&candidate), root.to_str().unwrap(), 3)
        .is_ok());
    let request = super::super::withdrawal_tests::request(&store, 8, &key);
    let operation = serde_json::json!({"operation":"policy_snapshot_withdraw", "request":request});
    let ack = crate::resident_protocol::evaluate_resident_bytes(
        &canonical_json_bytes(&operation).unwrap(),
        Some(&store),
    )
    .unwrap();
    let ack: Value = serde_json::from_slice(&ack).unwrap();
    assert_eq!(ack["response"]["status"], "withdrawn");
    assert!(store
        .validate_versioned_request_snapshot(&reference(&candidate), root.to_str().unwrap(), 3)
        .is_err());
    let reopened =
        PolicySnapshotStore::new_with_resident_generation(&root, &"a".repeat(64), 14).unwrap();
    assert_eq!(
        reopened.push(&push_value(&candidate)).unwrap_err(),
        "native_policy_snapshot_generation_reused"
    );
    let retained: Value =
        serde_json::from_slice(&fs::read(root.join(SNAPSHOT_FILE_NAME)).unwrap()).unwrap();
    assert_eq!(retained["generation_floor"], 8);
    assert!(retained["snapshot"].is_null());
    let fresh = snapshot_v4(9, &key, &root);
    reopened.push(&push_value(&fresh)).unwrap();
    assert!(reopened
        .validate_versioned_request_snapshot(&reference(&fresh), root.to_str().unwrap(), 9)
        .is_ok());
    fs::remove_dir_all(root).unwrap();
}

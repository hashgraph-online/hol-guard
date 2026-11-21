use super::*;

fn business_snapshot(generation: u64, key: &[u8], root: &Path) -> PolicySnapshotV3 {
    let mut snapshot = signed_snapshot(generation, key, root);
    business_source_tests::install_source(
        &mut snapshot,
        &business_source_tests::source_document(),
        generation,
        key,
        root,
        guard_policy_snapshot::business_source_anchor::BusinessSourcePhase::Committed,
    );
    snapshot
}

fn push(store: &PolicySnapshotStore, snapshot: PolicySnapshotV3) -> Result<Vec<u8>, String> {
    store.push(&serde_json::json!({"schema":POLICY_SNAPSHOT_PUSH_SCHEMA,"snapshot":snapshot}))
}

#[test]
fn admitted_business_binding_cannot_be_omitted_by_newer_signed_snapshot() {
    let root = test_root("business-floor-removal");
    let key = install_test_key(&root, 71);
    let store = PolicySnapshotStore::new(&root, &"a".repeat(64)).unwrap();
    push(&store, business_snapshot(1, &key, &root)).unwrap();
    let result = push(&store, signed_snapshot(2, &key, &root));
    assert_eq!(
        result.unwrap_err(),
        "native_business_policy_removal_requires_authority"
    );
    assert_eq!(store.current_generation(), Some(1));
    drop(store);
    let restarted = PolicySnapshotStore::new(&root, &"a".repeat(64)).unwrap();
    assert_eq!(
        push(&restarted, signed_snapshot(2, &key, &root)).unwrap_err(),
        "native_business_policy_removal_requires_authority"
    );
    push(&restarted, business_snapshot(2, &key, &root)).unwrap();
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn business_floor_survives_quarantined_and_expired_snapshot_bodies() {
    for mode in ["forged-mac", "expired", "absent-body"] {
        let root = test_root(mode);
        let key = install_test_key(&root, 72);
        let store = PolicySnapshotStore::new(&root, &"a".repeat(64)).unwrap();
        push(&store, business_snapshot(1, &key, &root)).unwrap();
        drop(store);
        let path = root.join(SNAPSHOT_FILE_NAME);
        let mut record: Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        match mode {
            "forged-mac" => record["snapshot"]["integrity"]["mac"] = Value::String("0".repeat(64)),
            "expired" => {
                let mut expired: PolicySnapshotV3 =
                    serde_json::from_value(record["snapshot"].clone()).unwrap();
                expired.issued_at_ms = 1;
                expired.expires_at_ms = 2;
                command_floor_tests::resign(&mut expired, &key);
                record["snapshot"] = serde_json::to_value(expired).unwrap();
            }
            _ => record["snapshot"] = Value::Null,
        }
        fixture_file(&path, &canonical_json_bytes(&record).unwrap());
        let restarted = PolicySnapshotStore::new(&root, &"a".repeat(64)).unwrap();
        assert_eq!(restarted.current_generation(), None);
        assert_eq!(
            push(&restarted, signed_snapshot(2, &key, &root)).unwrap_err(),
            "native_business_policy_removal_requires_authority"
        );
        push(&restarted, business_snapshot(2, &key, &root)).unwrap();
        fs::remove_dir_all(root).unwrap();
    }
}

#[test]
fn rewritten_removed_or_null_business_floor_fails_record_authentication() {
    let root = test_root("business-floor-authentication");
    let key = install_test_key(&root, 73);
    let store = PolicySnapshotStore::new(&root, &"a".repeat(64)).unwrap();
    push(&store, business_snapshot(1, &key, &root)).unwrap();
    drop(store);
    let path = root.join(SNAPSHOT_FILE_NAME);
    let original: Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
    for mutation in [Some(Value::String("0".repeat(64))), Some(Value::Null), None] {
        let mut record = original.clone();
        if let Some(value) = mutation {
            record["business_policy_floor"] = value;
        } else {
            record
                .as_object_mut()
                .unwrap()
                .remove("business_policy_floor");
        }
        fixture_file(&path, &canonical_json_bytes(&record).unwrap());
        assert!(PolicySnapshotStore::new(&root, &"a".repeat(64)).is_err());
    }
    let mut legacy_null = original;
    legacy_null["business_policy_floor"] = Value::Null;
    legacy_null["floor_mac"] = Value::String(generation_floor_mac(
        1,
        legacy_null["policy_digest"].as_str().unwrap(),
        &key,
    ));
    fixture_file(&path, &canonical_json_bytes(&legacy_null).unwrap());
    assert!(PolicySnapshotStore::new(&root, &"a".repeat(64)).is_err());
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn authenticated_legacy_whole_snapshot_recovers_business_floor_without_weakening() {
    let root = test_root("business-floor-legacy");
    let key = install_test_key(&root, 74);
    let store = PolicySnapshotStore::new(&root, &"a".repeat(64)).unwrap();
    push(&store, business_snapshot(1, &key, &root)).unwrap();
    drop(store);
    let path = root.join(SNAPSHOT_FILE_NAME);
    let mut record: Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
    record
        .as_object_mut()
        .unwrap()
        .remove("business_policy_floor");
    record["floor_mac"] = Value::String(generation_floor_mac(
        1,
        record["policy_digest"].as_str().unwrap(),
        &key,
    ));
    fixture_file(&path, &canonical_json_bytes(&record).unwrap());
    let legacy_bytes = fs::read(&path).unwrap();
    PERSIST_FAILPOINT.with(|failpoint| failpoint.set(PersistBoundary::Rename as u8));
    assert!(PolicySnapshotStore::new(&root, &"a".repeat(64)).is_err());
    assert_eq!(fs::read(&path).unwrap(), legacy_bytes);
    let restarted = PolicySnapshotStore::new(&root, &"a".repeat(64)).unwrap();
    assert_eq!(restarted.current_generation(), Some(1));
    let mut upgraded: Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
    assert!(upgraded["business_policy_floor"].is_string());
    let ack: Value = serde_json::from_slice(
        &push(
            &restarted,
            serde_json::from_value(upgraded["snapshot"].clone()).unwrap(),
        )
        .unwrap(),
    )
    .unwrap();
    assert_eq!(ack["idempotent"], true);
    assert_eq!(
        push(&restarted, signed_snapshot(2, &key, &root)).unwrap_err(),
        "native_business_policy_removal_requires_authority"
    );
    drop(restarted);
    upgraded["snapshot"] = Value::Null;
    fixture_file(&path, &canonical_json_bytes(&upgraded).unwrap());
    let after_loss = PolicySnapshotStore::new(&root, &"a".repeat(64)).unwrap();
    assert_eq!(after_loss.current_generation(), None);
    assert_eq!(
        push(&after_loss, signed_snapshot(2, &key, &root)).unwrap_err(),
        "native_business_policy_removal_requires_authority"
    );
    push(&after_loss, business_snapshot(2, &key, &root)).unwrap();
    drop(after_loss);
    let record: Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
    assert!(record["business_policy_floor"].is_string());
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn raw_business_record_is_refused_without_rewriting_authority() {
    let root = test_root("business-floor-legacy-expired");
    let key = install_test_key(&root, 75);
    let mut snapshot = business_snapshot(1, &key, &root);
    snapshot.issued_at_ms = 1;
    snapshot.expires_at_ms = 2;
    command_floor_tests::resign(&mut snapshot, &key);
    let floor = GenerationFloorV1 {
        schema: GENERATION_FLOOR_SCHEMA.into(),
        generation: 1,
        policy_digest: snapshot.policy_digest.clone(),
        mac: generation_floor_mac(1, &snapshot.policy_digest, &key),
    };
    private_fixture_bytes(
        &root.join(SNAPSHOT_FILE_NAME),
        &canonical_json_bytes(&serde_json::to_value(snapshot).unwrap()).unwrap(),
    );
    private_fixture_bytes(
        &root.join(GENERATION_FLOOR_FILE_NAME),
        &canonical_json_bytes(&serde_json::to_value(floor).unwrap()).unwrap(),
    );
    let original = fs::read(root.join(SNAPSHOT_FILE_NAME)).unwrap();
    assert_eq!(
        PolicySnapshotStore::migrate_legacy_state(&root, &"a".repeat(64)).unwrap_err(),
        "native_policy_snapshot_state_invalid"
    );
    assert_eq!(fs::read(root.join(SNAPSHOT_FILE_NAME)).unwrap(), original);
    assert!(PolicySnapshotStore::new(&root, &"a".repeat(64)).is_err());
    fs::remove_dir_all(root).unwrap();
}

fn private_fixture_bytes(path: &Path, bytes: &[u8]) {
    let mut file = crate::resident_state::private_file(path, true, path.parent().unwrap()).unwrap();
    file.write_all(bytes).unwrap();
    file.sync_all().unwrap();
}

#[test]
fn authentic_record_with_incoherent_binding_is_not_admitted() {
    for omit in [false, true] {
        let root = test_root(if omit {
            "business-floor-incoherent-omitted"
        } else {
            "business-floor-incoherent-digest"
        });
        let key = install_test_key(&root, 76);
        let store = PolicySnapshotStore::new(&root, &"a".repeat(64)).unwrap();
        push(&store, business_snapshot(1, &key, &root)).unwrap();
        drop(store);
        let path = root.join(SNAPSHOT_FILE_NAME);
        let mut record: Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        if omit {
            let snapshot = signed_snapshot(1, &key, &root);
            record["policy_digest"] = Value::String(snapshot.policy_digest.clone());
            record["snapshot"] = serde_json::to_value(snapshot).unwrap();
        } else {
            record["business_policy_floor"] = Value::String("f".repeat(64));
        }
        record["floor_mac"] = Value::String(
            super::super::policy_store_business_floor::authority_floor_mac(
                1,
                record["policy_digest"].as_str().unwrap(),
                None,
                record["business_policy_floor"].as_str(),
                &key,
            )
            .unwrap(),
        );
        fixture_file(&path, &canonical_json_bytes(&record).unwrap());
        let restarted = PolicySnapshotStore::new(&root, &"a".repeat(64)).unwrap();
        assert_eq!(restarted.current_generation(), None);
        assert!(push(&restarted, signed_snapshot(2, &key, &root)).is_err());
        fs::remove_dir_all(root).unwrap();
    }
}

#[test]
fn expired_combined_legacy_body_and_recovered_floor_are_both_durable() {
    let root = test_root("business-floor-expired-combined");
    let key = install_test_key(&root, 77);
    let store = PolicySnapshotStore::new(&root, &"a".repeat(64)).unwrap();
    push(&store, business_snapshot(1, &key, &root)).unwrap();
    drop(store);
    let path = root.join(SNAPSHOT_FILE_NAME);
    let mut record: Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
    let mut expired: PolicySnapshotV3 = serde_json::from_value(record["snapshot"].clone()).unwrap();
    expired.issued_at_ms = 1;
    expired.expires_at_ms = 2;
    command_floor_tests::resign(&mut expired, &key);
    record["snapshot"] = serde_json::to_value(expired).unwrap();
    record
        .as_object_mut()
        .unwrap()
        .remove("business_policy_floor");
    record["floor_mac"] = Value::String(generation_floor_mac(
        1,
        record["policy_digest"].as_str().unwrap(),
        &key,
    ));
    fixture_file(&path, &canonical_json_bytes(&record).unwrap());
    let authenticated_body = record["snapshot"].clone();
    let restarted = PolicySnapshotStore::new(&root, &"a".repeat(64)).unwrap();
    assert_eq!(restarted.current_generation(), None);
    drop(restarted);
    let mut upgraded: Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
    assert!(upgraded["business_policy_floor"].is_string());
    assert_eq!(upgraded["snapshot"], authenticated_body);
    upgraded["snapshot"] = Value::Null;
    fixture_file(&path, &canonical_json_bytes(&upgraded).unwrap());
    let after_loss = PolicySnapshotStore::new(&root, &"a".repeat(64)).unwrap();
    assert_eq!(
        push(&after_loss, signed_snapshot(2, &key, &root)).unwrap_err(),
        "native_business_policy_removal_requires_authority"
    );
    fs::remove_dir_all(root).unwrap();
}

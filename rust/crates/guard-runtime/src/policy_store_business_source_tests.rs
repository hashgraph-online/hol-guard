use super::*;
use guard_policy_snapshot::business_source_anchor::{
    sign_business_source_anchor, BusinessSourcePhase,
};
use guard_policy_snapshot::business_source_authority::{
    sign_business_source, verify_business_source,
};

pub(super) fn source_document() -> Value {
    serde_json::from_str(include_str!(
        "../../../../contracts/business-policy/source-authority-v1-fixture.json"
    ))
    .unwrap()
}

pub(super) fn install_source(
    snapshot: &mut PolicySnapshotV3,
    document: &Value,
    mutation_revision: u64,
    key: &[u8],
    root: &Path,
    phase: BusinessSourcePhase,
) {
    let key: &[u8; 32] = key.try_into().unwrap();
    let wire = sign_business_source(document, mutation_revision, key).unwrap();
    let source = verify_business_source(&wire, key).unwrap();
    snapshot.business_policy = Some(source.compiled().binding().clone());
    command_floor_tests::resign(snapshot, key);
    let lock = root.join("extension-control-authority.lock");
    if !lock.exists() {
        fixture_file(&lock, b"0");
        #[cfg(unix)]
        fs::set_permissions(&lock, fs::Permissions::from_mode(0o600)).unwrap();
    }
    let marker = sign_business_source_anchor(&source, phase, key).unwrap();
    let path = root.join("business-source-anchor.v1.json");
    fixture_file(&path, &marker);
    #[cfg(unix)]
    fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
}

fn push(store: &PolicySnapshotStore, snapshot: &PolicySnapshotV3) -> Result<Vec<u8>, String> {
    store.push(&serde_json::json!({"schema":POLICY_SNAPSHOT_PUSH_SCHEMA,"snapshot":snapshot}))
}

#[test]
fn missing_closed_and_replaced_source_refuse_admission_and_late_ack() {
    let root = test_root("business-source-current");
    let key = install_test_key(&root, 79);
    let store = PolicySnapshotStore::new(&root, &"a".repeat(64)).unwrap();
    let mut first = signed_snapshot(1, &key, &root);
    install_source(
        &mut first,
        &source_document(),
        1,
        &key,
        &root,
        BusinessSourcePhase::Closed,
    );
    assert_eq!(
        push(&store, &first).unwrap_err(),
        "native_business_source_authority_not_current"
    );
    install_source(
        &mut first,
        &source_document(),
        1,
        &key,
        &root,
        BusinessSourcePhase::Committed,
    );
    push(&store, &first).unwrap();
    assert!(store.command_authority_lease(&first).is_ok());
    let mut document = source_document();
    document["metadata"]["revision"] = 2.into();
    document["spec"]["rules"][0]["effect"] = "block".into();
    let mut second = signed_snapshot(2, &key, &root);
    install_source(
        &mut second,
        &document,
        2,
        &key,
        &root,
        BusinessSourcePhase::Closed,
    );
    assert!(store.command_authority_lease(&first).is_err());
    assert!(
        push(&store, &first).is_err(),
        "idempotent ACK must check the source fence"
    );
    assert!(push(&store, &second).is_err());
    install_source(
        &mut second,
        &document,
        2,
        &key,
        &root,
        BusinessSourcePhase::Committed,
    );
    assert!(store.command_authority_lease(&first).is_err());
    assert!(push(&store, &first).is_err());
    push(&store, &second).unwrap();
    drop(store);
    let restarted = PolicySnapshotStore::new(&root, &"a".repeat(64)).unwrap();
    assert!(restarted.command_authority_lease(&first).is_err());
    assert!(restarted.command_authority_lease(&second).is_ok());
    fs::remove_file(root.join("business-source-anchor.v1.json")).unwrap();
    assert_eq!(
        push(&restarted, &second).unwrap_err(),
        "native_business_source_authority_missing"
    );
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn altered_binding_and_invalid_marker_never_reuse_admitted_identity() {
    let root = test_root("business-source-authentication");
    let key = install_test_key(&root, 80);
    let store = PolicySnapshotStore::new(&root, &"a".repeat(64)).unwrap();
    let mut snapshot = signed_snapshot(1, &key, &root);
    install_source(
        &mut snapshot,
        &source_document(),
        1,
        &key,
        &root,
        BusinessSourcePhase::Committed,
    );
    push(&store, &snapshot).unwrap();
    let mut watch = snapshot.clone();
    watch.mode = "observe".into();
    command_floor_tests::resign(&mut watch, &key);
    assert_eq!(
        push(&store, &watch).unwrap_err(),
        "native_business_source_enforce_required"
    );
    let mut unrelated = snapshot.clone();
    unrelated
        .business_policy
        .as_mut()
        .unwrap()
        .source_document_digest = Some("d".repeat(64));
    command_floor_tests::resign(&mut unrelated, &key);
    assert!(store.command_authority_lease(&unrelated).is_err());
    let marker_path = root.join("business-source-anchor.v1.json");
    let original = fs::read(&marker_path).unwrap();
    let mut marker: Value = serde_json::from_slice(&original).unwrap();
    marker["floor"]["source_digest"] = "f".repeat(64).into();
    fixture_file(&marker_path, &canonical_json_bytes(&marker).unwrap());
    assert_eq!(
        push(&store, &snapshot).unwrap_err(),
        "native_business_source_authority_invalid"
    );
    let mut with_newline = original;
    with_newline.push(b'\n');
    fixture_file(&marker_path, &with_newline);
    assert!(store.command_authority_lease(&snapshot).is_err());
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn shared_source_lease_prevents_mutation_through_decision_lifetime() {
    let root = test_root("business-source-lease");
    let key = install_test_key(&root, 81);
    let store = PolicySnapshotStore::new(&root, &"a".repeat(64)).unwrap();
    let mut snapshot = signed_snapshot(1, &key, &root);
    install_source(
        &mut snapshot,
        &source_document(),
        1,
        &key,
        &root,
        BusinessSourcePhase::Committed,
    );
    let lock = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(root.join("extension-control-authority.lock"))
        .unwrap();
    fs2::FileExt::try_lock_exclusive(&lock).unwrap();
    assert_eq!(
        push(&store, &snapshot).unwrap_err(),
        "native_business_source_mutation_in_progress"
    );
    fs2::FileExt::unlock(&lock).unwrap();
    let lease = store.command_authority_lease(&snapshot).unwrap();
    assert!(fs2::FileExt::try_lock_exclusive(&lock).is_err());
    drop(lease);
    fs2::FileExt::try_lock_exclusive(&lock).unwrap();
    fs2::FileExt::unlock(&lock).unwrap();
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn first_legacy_decision_materializes_lease_before_first_source_activation() {
    let root = test_root("first-business-source-lease");
    let key = install_test_key(&root, 82);
    let store = PolicySnapshotStore::new(&root, &"a".repeat(64)).unwrap();
    let snapshot = signed_snapshot(1, &key, &root);
    let lock_path = root.join("extension-control-authority.lock");
    assert!(!lock_path.exists());
    let lease = store.command_authority_lease(&snapshot).unwrap();
    let lock = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(&lock_path)
        .unwrap();
    assert!(fs2::FileExt::try_lock_exclusive(&lock).is_err());
    drop(lease);
    fs2::FileExt::try_lock_exclusive(&lock).unwrap();
    fs2::FileExt::unlock(&lock).unwrap();
    fs::remove_dir_all(root).unwrap();
}

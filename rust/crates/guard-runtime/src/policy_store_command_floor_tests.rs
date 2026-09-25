use super::*;
use guard_contracts::{
    NativeCommandControlBindingV1, NativeExtensionControlLayerV1, NativeExtensionControlV1,
    NATIVE_COMMAND_CONTROL_BINDING_SCHEMA,
};

pub(super) fn control_snapshot(
    generation: u64,
    local: u64,
    managed: u64,
    state: &str,
    key: &[u8],
    root: &Path,
) -> PolicySnapshotV3 {
    let program = guard_command::native_command_program::packaged_command_program().unwrap();
    let mut binding = NativeCommandControlBindingV1 {
        schema: NATIVE_COMMAND_CONTROL_BINDING_SCHEMA.into(),
        authority: Some(guard_contracts::NativeCommandControlAuthorityV1 {
            epoch: 1,
            mutation_revision: generation,
            authority_key_id: "a".repeat(64),
            recovery: None,
        }),
        program_digest: program.program_digest.clone(),
        catalog_digest: program.catalog_digest.clone(),
        trust_digest: program.trust_digest.clone(),
        health: "protected".into(),
        revision: local,
        managed_revision: managed,
        effective_digest: String::new(),
        layers: vec![NativeExtensionControlLayerV1 {
            schema_version: "1.0.0".into(),
            kind: "local-admin".into(),
            catalog_digest: program.catalog_digest.clone(),
            global_lockdown: false,
            controls: vec![NativeExtensionControlV1 {
                target_kind: "extension".into(),
                target_id: "command.ollama".into(),
                state: state.into(),
            }],
        }],
    };
    binding.effective_digest = binding.compute_effective_digest().unwrap();
    let mut snapshot = signed_snapshot(generation, key, root);
    snapshot.command_extensions = Some(binding);
    resign(&mut snapshot, key);
    snapshot
}

pub(super) fn resign(snapshot: &mut PolicySnapshotV3, key: &[u8]) {
    snapshot.policy_digest = policy_digest(snapshot).unwrap();
    snapshot.integrity.mac = integrity_mac(snapshot, key).unwrap();
}

fn push(store: &PolicySnapshotStore, snapshot: PolicySnapshotV3) -> Result<Vec<u8>, String> {
    if snapshot.command_extensions.is_some() {
        super::command_authority_tests::publish_marker(store, &snapshot, "committed");
    }
    store.push(&serde_json::json!({"schema": POLICY_SNAPSHOT_PUSH_SCHEMA, "snapshot": snapshot}))
}

#[test]
fn command_control_revisions_are_independent_and_survive_restart() {
    let root = test_root("command-floor-restart");
    let key = install_test_key(&root, 61);
    let store = PolicySnapshotStore::new(&root, &"a".repeat(64)).unwrap();
    push(&store, control_snapshot(1, 5, 9, "enabled", &key, &root)).unwrap();
    for (local, managed) in [(4, 10), (6, 8)] {
        let error = push(
            &store,
            control_snapshot(2, local, managed, "enabled", &key, &root),
        )
        .unwrap_err();
        assert!(error.contains("control_revision_downgrade"), "{error}");
    }
    let error = push(&store, control_snapshot(2, 5, 9, "disabled", &key, &root)).unwrap_err();
    assert!(error.contains("control_revision_reused"), "{error}");
    drop(store);
    let restarted = PolicySnapshotStore::new(&root, &"a".repeat(64)).unwrap();
    assert_eq!(restarted.current_generation(), Some(1));
    assert!(push(
        &restarted,
        control_snapshot(2, 4, 10, "enabled", &key, &root)
    )
    .is_err());
    push(
        &restarted,
        control_snapshot(2, 6, 9, "disabled", &key, &root),
    )
    .unwrap();
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn degraded_and_quarantined_snapshots_retain_protected_control_floor() {
    let root = test_root("command-floor-quarantine");
    let key = install_test_key(&root, 62);
    let store = PolicySnapshotStore::new(&root, &"a".repeat(64)).unwrap();
    push(&store, control_snapshot(1, 5, 9, "enabled", &key, &root)).unwrap();
    let mut degraded = control_snapshot(2, 0, 0, "disabled", &key, &root);
    let binding = degraded.command_extensions.as_mut().unwrap();
    binding.health = "tampered".into();
    binding.effective_digest = binding.compute_effective_digest().unwrap();
    resign(&mut degraded, &key);
    push(&store, degraded).unwrap();
    drop(store);
    let path = root.join(SNAPSHOT_FILE_NAME);
    let mut record: Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
    assert_eq!(record["command_control_floor"]["revision"], 5);
    assert_eq!(record["command_control_floor"]["managed_revision"], 9);
    // The authenticated independent floor survives an unusable snapshot body.
    record["snapshot"]["integrity"]["mac"] = Value::String("0".repeat(64));
    fixture_file(&path, &canonical_json_bytes(&record).unwrap());
    let restarted = PolicySnapshotStore::new(&root, &"a".repeat(64)).unwrap();
    assert_eq!(restarted.current_generation(), None);
    assert!(push(
        &restarted,
        control_snapshot(3, 4, 10, "enabled", &key, &root)
    )
    .is_err());
    assert!(push(&restarted, signed_snapshot(3, &key, &root)).is_err());
    push(
        &restarted,
        control_snapshot(3, 6, 9, "enabled", &key, &root),
    )
    .unwrap();
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn floor_mac_rejects_rewritten_or_removed_independent_revisions() {
    let root = test_root("command-floor-mac");
    let key = install_test_key(&root, 63);
    let store = PolicySnapshotStore::new(&root, &"a".repeat(64)).unwrap();
    push(&store, control_snapshot(1, 5, 9, "enabled", &key, &root)).unwrap();
    drop(store);
    let path = root.join(SNAPSHOT_FILE_NAME);
    let original: Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
    for field in ["revision", "managed_revision", "effective_digest"] {
        let mut record = original.clone();
        record["command_control_floor"][field] = if field == "effective_digest" {
            Value::String("0".repeat(64))
        } else {
            Value::from(0)
        };
        fixture_file(&path, &canonical_json_bytes(&record).unwrap());
        assert!(
            PolicySnapshotStore::new(&root, &"a".repeat(64)).is_err(),
            "{field}"
        );
    }
    let mut removed = original;
    removed
        .as_object_mut()
        .unwrap()
        .remove("command_control_floor");
    fixture_file(&path, &canonical_json_bytes(&removed).unwrap());
    assert!(PolicySnapshotStore::new(&root, &"a".repeat(64)).is_err());
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn extension_program_changes_are_bound_to_policy_integrity() {
    let root = test_root("command-program-digest");
    let key = install_test_key(&root, 64);
    let original = control_snapshot(1, 5, 9, "enabled", &key, &root);
    for field in ["program_digest", "catalog_digest", "trust_digest"] {
        let mut value = serde_json::to_value(&original).unwrap();
        value["command_extensions"][field] = Value::String("b".repeat(64));
        let changed: PolicySnapshotV3 = serde_json::from_value(value).unwrap();
        assert_ne!(policy_digest(&changed).unwrap(), original.policy_digest);
        assert_ne!(
            integrity_mac(&changed, &key).unwrap(),
            original.integrity.mac
        );
    }
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn protected_authority_never_reverts_to_first_install_defaults_even_after_restart() {
    let root = test_root("command-floor-initial-defaults");
    let key = install_test_key(&root, 65);
    let store = PolicySnapshotStore::new(&root, &"a".repeat(64)).unwrap();
    let protected = control_snapshot(1, 0, 0, "enabled", &key, &root);
    push(&store, protected).unwrap();
    drop(store);
    let restarted = PolicySnapshotStore::new(&root, &"a".repeat(64)).unwrap();
    let mut forged_fresh = control_snapshot(2, 0, 0, "enabled", &key, &root);
    let binding = forged_fresh.command_extensions.as_mut().unwrap();
    binding.health = "unenrolled".into();
    binding.layers.clear();
    binding.authority.as_mut().unwrap().authority_key_id = "0".repeat(64);
    binding.effective_digest = binding.compute_effective_digest().unwrap();
    resign(&mut forged_fresh, &key);
    assert!(push(&restarted, forged_fresh)
        .unwrap_err()
        .contains("authority_downgrade"));
    fs::remove_dir_all(root).unwrap();
}

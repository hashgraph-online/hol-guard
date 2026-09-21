use super::command_floor_tests::{control_snapshot, resign};
use super::*;

pub(super) fn publish_marker(
    store: &PolicySnapshotStore,
    snapshot: &PolicySnapshotV3,
    phase: &str,
) {
    let state_base = store.authority_path.parent().unwrap();
    let root = crate::resident_state::private_root_for_state_base(state_base).unwrap();
    let lock = root.join("extension-control-authority.lock");
    if !lock.exists() {
        fixture_file(&lock, b"0");
        #[cfg(unix)]
        fs::set_permissions(&lock, fs::Permissions::from_mode(0o600)).unwrap();
    }
    let binding = snapshot.command_extensions.as_ref().unwrap();
    let authority = binding.authority.as_ref().unwrap();
    let mut value = serde_json::json!({
        "schema": "guard.native-command-control-authority.v1", "epoch": authority.epoch,
        "mutation_revision": authority.mutation_revision, "authority_key_id": authority.authority_key_id,
        "phase": phase, "effective_digest": if phase == "committed" { Some(&binding.effective_digest) } else { None },
        "recovery": authority.recovery,
    });
    let mut bytes = b"hol-guard.native-command-control-authority.v1\0".to_vec();
    bytes.extend(canonical_json_bytes(&value).unwrap());
    value["mac"] = hex::encode(
        ring::hmac::sign(
            &ring::hmac::Key::new(ring::hmac::HMAC_SHA256, &store.verifier_key),
            &bytes,
        )
        .as_ref(),
    )
    .into();
    let path = state_base.join("command-control-authority.v1.json");
    fixture_file(&path, &canonical_json_bytes(&value).unwrap());
    #[cfg(unix)]
    fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
}

fn push(store: &PolicySnapshotStore, snapshot: &PolicySnapshotV3) -> Result<Vec<u8>, String> {
    store.push(&serde_json::json!({"schema": POLICY_SNAPSHOT_PUSH_SCHEMA, "snapshot": snapshot}))
}

#[test]
fn closed_mutation_marker_blocks_old_decisions_and_late_acknowledgements() {
    let root = test_root("command-authority-close");
    let key = install_test_key(&root, 71);
    let store = PolicySnapshotStore::new(&root, &"a".repeat(64)).unwrap();
    let first = control_snapshot(1, 1, 1, "enabled", &key, &root);
    assert!(push(&store, &first).is_err());
    publish_marker(&store, &first, "committed");
    push(&store, &first).unwrap();
    assert!(store.command_authority_lease(&first).is_ok());
    let second = control_snapshot(2, 2, 1, "disabled", &key, &root);
    publish_marker(&store, &second, "closed");
    assert!(store.command_authority_lease(&first).is_err());
    assert!(
        push(&store, &first).is_err(),
        "idempotent ACK must not revive stale readiness"
    );
    assert!(push(&store, &second).is_err());
    publish_marker(&store, &second, "committed");
    assert!(push(&store, &first).is_err());
    push(&store, &second).unwrap();
    assert!(store.command_authority_lease(&second).is_ok());
    drop(store);
    let restarted = PolicySnapshotStore::new(&root, &"a".repeat(64)).unwrap();
    assert!(restarted.command_authority_lease(&first).is_err());
    assert!(restarted.command_authority_lease(&second).is_ok());
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn mutation_lock_is_nonblocking_and_shared_lease_spans_decision_lifetime() {
    let root = test_root("command-authority-lease");
    let key = install_test_key(&root, 72);
    let store = PolicySnapshotStore::new(&root, &"a".repeat(64)).unwrap();
    let snapshot = control_snapshot(1, 1, 1, "enabled", &key, &root);
    publish_marker(&store, &snapshot, "committed");
    let lock = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(root.join("extension-control-authority.lock"))
        .unwrap();
    fs2::FileExt::try_lock_exclusive(&lock).unwrap();
    assert!(store.command_authority_lease(&snapshot).is_err());
    fs2::FileExt::unlock(&lock).unwrap();
    let lease = store.command_authority_lease(&snapshot).unwrap();
    assert!(fs2::FileExt::try_lock_exclusive(&lock).is_err());
    drop(lease);
    fs2::FileExt::try_lock_exclusive(&lock).unwrap();
    fs2::FileExt::unlock(&lock).unwrap();
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn marker_mac_and_recovery_epoch_are_both_bound_to_exact_retained_floor() {
    use sha2::{Digest, Sha256};
    let root = test_root("command-authority-recovery");
    let key = install_test_key(&root, 73);
    let store = PolicySnapshotStore::new(&root, &"a".repeat(64)).unwrap();
    let original = control_snapshot(1, 5, 9, "enabled", &key, &root);
    publish_marker(&store, &original, "committed");
    push(&store, &original).unwrap();
    let authority_record: Value =
        serde_json::from_slice(&fs::read(root.join(SNAPSHOT_FILE_NAME)).unwrap()).unwrap();
    let mut domain = b"hol-guard.native-command-control-floor-link.v1\0".to_vec();
    domain.extend(canonical_json_bytes(&authority_record["command_control_floor"]).unwrap());
    let previous_floor_digest = hex::encode(Sha256::digest(domain));
    let mut recovered = control_snapshot(2, 0, 0, "disabled", &key, &root);
    let authority = recovered
        .command_extensions
        .as_mut()
        .unwrap()
        .authority
        .as_mut()
        .unwrap();
    authority.epoch = 2;
    authority.authority_key_id = "b".repeat(64);
    authority.recovery = Some(guard_contracts::NativeCommandControlRecoveryV1 {
        schema: "guard.native-command-control-recovery.v1".into(),
        previous_epoch: 1,
        previous_mutation_revision: 1,
        previous_authority_key_id: "a".repeat(64),
        previous_floor_digest: "0".repeat(64),
        nonce: "c".repeat(64),
    });
    resign(&mut recovered, &key);
    publish_marker(&store, &recovered, "committed");
    assert!(push(&store, &recovered)
        .unwrap_err()
        .contains("recovery_context"));
    recovered
        .command_extensions
        .as_mut()
        .unwrap()
        .authority
        .as_mut()
        .unwrap()
        .recovery
        .as_mut()
        .unwrap()
        .previous_floor_digest = previous_floor_digest.clone();
    resign(&mut recovered, &key);
    publish_marker(&store, &recovered, "committed");
    push(&store, &recovered).unwrap();
    let record: Value =
        serde_json::from_slice(&fs::read(root.join(SNAPSHOT_FILE_NAME)).unwrap()).unwrap();
    assert_eq!(
        record["command_control_floor"]["previous_floor_digest"],
        previous_floor_digest
    );
    assert_eq!(record["command_control_floor"]["authority"]["epoch"], 2);
    let path = root.join("command-control-authority.v1.json");
    let mut marker: Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
    marker["mac"] = "0".repeat(64).into();
    fixture_file(&path, &canonical_json_bytes(&marker).unwrap());
    assert!(store.command_authority_lease(&recovered).is_err());
    drop(store);
    let restarted = PolicySnapshotStore::new(&root, &"a".repeat(64)).unwrap();
    publish_marker(&restarted, &original, "committed");
    assert!(push(&restarted, &original).is_err());
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn python_signed_authority_vectors_match_native_lease_and_floor_codecs() {
    use super::super::policy_store_command_floor::{floor_link_digest, CommandControlFloor};

    let fixture: Value = serde_json::from_slice(include_bytes!(
        "../../../../contracts/extensions/native-command-control-authority.v1.fixtures.json"
    ))
    .unwrap();
    let floor: CommandControlFloor =
        serde_json::from_value(fixture["legacy_floor"].clone()).unwrap();
    assert_eq!(
        floor_link_digest(Some(&floor)).unwrap(),
        fixture["legacy_floor_link_digest"]
    );
    assert_eq!(
        floor_link_digest(None).unwrap(),
        fixture["null_floor_link_digest"]
    );
    let root = test_root("command-authority-python-vectors");
    let key = install_test_key(&root, 0x11);
    assert_eq!(hex::encode(key), fixture["verifier_key_hex"]);
    let store = PolicySnapshotStore::new(&root, &"a".repeat(64)).unwrap();
    for vector in fixture["vectors"].as_array().unwrap() {
        let record = &vector["record"];
        let mut snapshot = control_snapshot(1, 1, 1, "enabled", &key, &root);
        let binding = snapshot.command_extensions.as_mut().unwrap();
        binding.authority = Some(
            serde_json::from_value(serde_json::json!({
                "epoch": record["epoch"],
                "mutation_revision": record["mutation_revision"],
                "authority_key_id": record["authority_key_id"],
                "recovery": record["recovery"],
            }))
            .unwrap(),
        );
        if let Some(digest) = record["effective_digest"].as_str() {
            binding.effective_digest = digest.into();
        }
        // The fixture exercises the signed marker codec; policy admission and
        // effective control digest validation are covered by the push tests.
        publish_marker(&store, &snapshot, "committed");
        let path = root.join("command-control-authority.v1.json");
        let signed = vector["canonical_signed_json"].as_str().unwrap();
        fixture_file(&path, signed.as_bytes());
        assert_eq!(
            store.command_authority_lease(&snapshot).is_ok(),
            record["phase"] == "committed",
            "{}",
            vector["name"]
        );
        if record["phase"] == "committed" {
            fixture_file(&path, format!(" {signed}").as_bytes());
            assert!(store.command_authority_lease(&snapshot).is_err());
            let mut extra: Value = serde_json::from_str(signed).unwrap();
            extra["unsupported"] = true.into();
            fixture_file(&path, &canonical_json_bytes(&extra).unwrap());
            assert!(store.command_authority_lease(&snapshot).is_err());
            let mut missing: Value = serde_json::from_str(signed).unwrap();
            missing.as_object_mut().unwrap().remove("recovery");
            fixture_file(&path, &canonical_json_bytes(&missing).unwrap());
            assert_eq!(
                store.command_authority_lease(&snapshot).err().unwrap(),
                "native_command_control_authority_invalid"
            );
        }
    }
    fs::remove_dir_all(root).unwrap();
}

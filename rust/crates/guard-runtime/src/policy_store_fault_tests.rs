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

/// A push that runs out of disk must not take the published generation with
/// it. Each boundary below interrupts the same generation-2 push and asks what
/// a restart would read: everything up to the rename leaves the generation-1
/// record byte-identical, and the directory sync is the one boundary where the
/// new record is already in place, so a restart honestly reads generation 2
/// rather than pretending the interrupted push never happened.
#[test]
fn a_push_that_runs_out_of_disk_leaves_the_published_generation_readable() {
    for (label, boundary) in [
        ("temporary create", PersistBoundary::TemporaryCreate),
        ("write", PersistBoundary::Write),
        ("file sync", PersistBoundary::FileSync),
        ("rename", PersistBoundary::Rename),
        ("directory sync", PersistBoundary::DirectorySync),
    ] {
        let root = test_root("fault-generation");
        let key = install_test_key(&root, boundary as u8 + 40);
        let store = PolicySnapshotStore::new(&root, &"a".repeat(64)).unwrap();
        let published = serde_json::json!({
            "schema": POLICY_SNAPSHOT_PUSH_SCHEMA,
            "snapshot": signed_snapshot(1, &key, &root),
        });
        store.push(&published).unwrap();
        assert_eq!(store.current_generation(), Some(1));
        let authority_path = root.join(SNAPSHOT_FILE_NAME);
        let published_bytes = fs::read(&authority_path).unwrap();

        let next = serde_json::json!({
            "schema": POLICY_SNAPSHOT_PUSH_SCHEMA,
            "snapshot": signed_snapshot(2, &key, &root),
        });
        PERSIST_FAILPOINT.with(|failpoint| failpoint.set(boundary as u8));
        assert!(store.push(&next).is_err(), "{label} reported success");
        PERSIST_FAILPOINT.with(|failpoint| failpoint.set(0));

        let already_renamed = matches!(boundary, PersistBoundary::DirectorySync);
        let after = fs::read(&authority_path).unwrap();
        if already_renamed {
            assert_ne!(after, published_bytes, "{label} left the old record");
        } else {
            assert_eq!(after, published_bytes, "{label} rewrote the old record");
        }
        let has_temporary = fs::read_dir(&root)
            .unwrap()
            .filter_map(Result::ok)
            .any(|entry| entry.file_name().to_string_lossy().ends_with(".tmp"));
        assert!(!has_temporary, "{label} leaked a temporary file");

        let restarted = PolicySnapshotStore::new(&root, &"a".repeat(64)).unwrap();
        assert_eq!(
            restarted.current_generation(),
            Some(if already_renamed { 2 } else { 1 }),
            "{label} left a generation a restart could not read back"
        );
        fs::remove_dir_all(root).unwrap();
    }
}

/// The verifier key is what tells a published snapshot apart from one someone
/// else wrote into the state directory, so a store that cannot read a sound key
/// must refuse to open rather than carry on unauthenticated. Each state below is
/// a different way the key can be wrong on disk, and every one of them has to
/// stop the store before it reads, migrates or writes any authority record.
#[test]
fn a_store_refuses_to_open_without_a_sound_verifier_key() {
    for (label, bytes, expected) in [
        ("no key at all", None, "native_policy_verifier_key_missing"),
        (
            "a key that stops short",
            Some(vec![7u8; VERIFIER_KEY_BYTES - 1]),
            "native_policy_verifier_key_invalid",
        ),
        (
            "a key with bytes past its end",
            Some(vec![7u8; VERIFIER_KEY_BYTES + 1]),
            "native_policy_verifier_key_invalid",
        ),
    ] {
        let root = test_root("fault-verifier-key");
        if let Some(bytes) = bytes {
            let path = root.join(VERIFIER_KEY_FILE_NAME);
            fixture_file(&path, &bytes);
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
            }
        }

        assert_eq!(
            PolicySnapshotStore::new(&root, &"a".repeat(64))
                .err()
                .as_deref(),
            Some(expected),
            "the store opened on {label}"
        );
        assert!(
            !root.join(SNAPSHOT_FILE_NAME).exists(),
            "{label} left an authority record behind"
        );
        fs::remove_dir_all(root).unwrap();
    }
}

/// A key other accounts on the machine can read is a key they can sign with, so
/// reading it is refused for what it is rather than for how it is spelled. The
/// refusal names the privacy failure, which is the one thing the operator has to
/// fix before the resident can serve again.
#[cfg(unix)]
#[test]
fn a_store_refuses_a_verifier_key_other_accounts_can_read() {
    use std::os::unix::fs::PermissionsExt;

    let root = test_root("fault-verifier-key-shared");
    let path = root.join(VERIFIER_KEY_FILE_NAME);
    fixture_file(&path, &[7u8; VERIFIER_KEY_BYTES]);
    fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();

    assert_eq!(
        PolicySnapshotStore::new(&root, &"a".repeat(64))
            .err()
            .as_deref(),
        Some("native_policy_verifier_key_not_private"),
        "the store opened on a world-readable verifier key"
    );
    assert!(
        !root.join(SNAPSHOT_FILE_NAME).exists(),
        "a world-readable key left an authority record behind"
    );
    fs::remove_dir_all(root).unwrap();
}

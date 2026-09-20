use super::*;
use crate::policy_store::policy_store_mutation::acquire_writer;

fn push(snapshot: &PolicySnapshotV3) -> Value {
    serde_json::json!({"schema": POLICY_SNAPSHOT_PUSH_SCHEMA, "snapshot": snapshot})
}

#[test]
fn stale_writer_cannot_replace_a_newer_authenticated_publication() {
    let root = test_root("durable-newer-publication");
    let key = install_test_key(&root, 52);
    let stale = PolicySnapshotStore::new(&root, &"a".repeat(64)).unwrap();
    stale.push(&push(&signed_snapshot(1, &key, &root))).unwrap();
    let newer = PolicySnapshotStore::new(&root, &"a".repeat(64)).unwrap();
    newer
        .push(&push(&signed_snapshot(10, &key, &root)))
        .unwrap();
    let durable = fs::read(root.join(SNAPSHOT_FILE_NAME)).unwrap();
    // The original implementation checks only stale's cached generation 1,
    // then accepts signed generation 9 over the valid durable generation 10.
    let ack: Value =
        serde_json::from_slice(&stale.push(&push(&signed_snapshot(9, &key, &root))).unwrap())
            .unwrap();
    assert_eq!(
        ack["status"],
        "native_policy_snapshot_requires_new_generation"
    );
    assert_eq!(ack["generation"], 10);
    assert_eq!(fs::read(root.join(SNAPSHOT_FILE_NAME)).unwrap(), durable);
    assert!(stale.current_snapshot().is_err());
    assert_eq!(newer.current_snapshot().unwrap().generation, 10);
    let fresh: Value = serde_json::from_slice(
        &stale
            .push(&push(&signed_snapshot(11, &key, &root)))
            .unwrap(),
    )
    .unwrap();
    assert_eq!(fresh["status"], "accepted");
    assert_eq!(stale.current_snapshot().unwrap().generation, 11);
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn missing_or_regressed_durable_floor_cannot_be_reset_by_a_new_push() {
    for remove in [false, true] {
        let root = test_root(if remove {
            "writer-missing"
        } else {
            "writer-regressed"
        });
        let key = install_test_key(&root, 53);
        let store = PolicySnapshotStore::new(&root, &"a".repeat(64)).unwrap();
        store.push(&push(&signed_snapshot(3, &key, &root))).unwrap();
        if remove {
            fs::remove_file(root.join(SNAPSHOT_FILE_NAME)).unwrap();
        } else {
            crate::policy_store::persist_authority(
                &root.join(SNAPSHOT_FILE_NAME),
                2,
                &"d".repeat(64),
                None,
                &key,
            )
            .unwrap();
        }
        assert!(store.push(&push(&signed_snapshot(9, &key, &root))).is_err());
        assert!(store.current_snapshot().is_err());
        fs::remove_dir_all(root).unwrap();
    }
}

#[test]
fn writer_contention_preserves_finite_refusal_and_recovery() {
    let root = test_root("writer-contention");
    let key = install_test_key(&root, 54);
    let store = PolicySnapshotStore::new(&root, &"a".repeat(64)).unwrap();
    let guard = acquire_writer(&root).unwrap();
    assert_eq!(
        store
            .push(&push(&signed_snapshot(1, &key, &root)))
            .unwrap_err(),
        "native_policy_snapshot_writer_busy"
    );
    assert!(PolicySnapshotStore::new(&root, &"a".repeat(64)).is_err());
    assert!(PolicySnapshotStore::migrate_legacy_state(&root, &"a".repeat(64)).is_err());
    drop(guard);
    store.push(&push(&signed_snapshot(1, &key, &root))).unwrap();
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn writer_child() {
    let Some(root) = std::env::var_os("GUARD_DURABLE_WRITER_TEST_ROOT") else {
        return;
    };
    let root = PathBuf::from(root);
    let _writer = acquire_writer(&root).unwrap();
    fs::write(root.join("writer-ready"), b"ready").unwrap();
    let mut line = String::new();
    std::io::stdin().read_line(&mut line).unwrap();
}

#[test]
fn writer_lock_excludes_an_actual_second_process() {
    use std::process::{Child, Command, Stdio};
    use std::time::{Duration, Instant};
    struct ChildGuard(Child);
    impl Drop for ChildGuard {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }
    let root = test_root("writer-two-process");
    let key = install_test_key(&root, 55);
    let store = PolicySnapshotStore::new(&root, &"a".repeat(64)).unwrap();
    let mut child = ChildGuard(
        Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "policy_store::tests::durable_writer_tests::writer_child",
                "--nocapture",
            ])
            .env("GUARD_DURABLE_WRITER_TEST_ROOT", &root)
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap(),
    );
    let end = Instant::now() + Duration::from_secs(5);
    while !root.join("writer-ready").exists() {
        assert!(Instant::now() < end, "writer child did not become ready");
        assert!(
            child.0.try_wait().unwrap().is_none(),
            "writer child exited early"
        );
        std::thread::sleep(Duration::from_millis(2));
    }
    assert_eq!(
        store
            .push(&push(&signed_snapshot(1, &key, &root)))
            .unwrap_err(),
        "native_policy_snapshot_writer_busy"
    );
    child
        .0
        .stdin
        .take()
        .unwrap()
        .write_all(b"release\n")
        .unwrap();
    assert!(child.0.wait().unwrap().success());
    store.push(&push(&signed_snapshot(1, &key, &root))).unwrap();
    fs::remove_dir_all(root).unwrap();
}

#[cfg(unix)]
#[test]
fn replacement_between_open_and_lock_cannot_authorize_an_obsolete_file() {
    let root = test_root("writer-replacement");
    let result =
        crate::policy_store::policy_store_mutation::acquire_writer_with_hook(&root, |path| {
            fs::rename(path, root.join("retired-lock")).unwrap();
            fixture_file(path, b"0");
            fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
        });
    assert!(
        matches!(result, Err(ref error) if error == "native_policy_snapshot_writer_lock_invalid")
    );
    assert!(acquire_writer(&root).is_ok());
    fs::remove_dir_all(root).unwrap();
}

#[cfg(unix)]
#[test]
fn private_runtime_child_does_not_authorize_a_nonprivate_lock_parent() {
    let root = test_root("writer-parent");
    let state = root.join("native-runtime");
    fixture_directory(&state);
    fs::set_permissions(&state, fs::Permissions::from_mode(0o700)).unwrap();
    install_test_key(&state, 56);
    fs::set_permissions(&root, fs::Permissions::from_mode(0o755)).unwrap();
    assert!(PolicySnapshotStore::new(&state, &"a".repeat(64)).is_err());
    assert!(!root
        .join("native-policy-snapshot-generation-v3.lock")
        .exists());
    fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
    assert!(PolicySnapshotStore::new(&state, &"a".repeat(64)).is_ok());
    fs::remove_dir_all(root).unwrap();
}

#[cfg(windows)]
#[test]
fn bound_windows_child_comparison_requires_the_same_private_object() {
    let root = test_root("writer-windows-identity");
    fixture_file(&root.join("first.lock"), b"0");
    fixture_file(&root.join("second.lock"), b"0");
    let binding = crate::resident_state::bind_windows_existing_directory(&root, &root).unwrap();
    let first = binding
        .open_private_file(std::ffi::OsStr::new("first.lock"))
        .unwrap();
    assert!(binding
        .matches_private_file(std::ffi::OsStr::new("first.lock"), &first)
        .unwrap());
    assert!(!binding
        .matches_private_file(std::ffi::OsStr::new("second.lock"), &first)
        .unwrap());
    drop(first);
    drop(binding);
    fs::remove_dir_all(root).unwrap();
}

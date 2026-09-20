use super::*;
use crate::policy_store::policy_store_mutation::acquire_writer;

pub(super) fn request(store: &PolicySnapshotStore, generation: u64, key: &[u8]) -> Value {
    let state = store.state.lock().unwrap();
    let expected = authority_fingerprint(&store.authority_path).map(|fingerprint| {
        serde_json::json!({
            "fingerprint": fingerprint,
            "generation_floor": state.generation_floor,
            "policy_digest": state.policy_digest,
            "usable_snapshot": state.snapshot.is_some(),
        })
    });
    let mut value = serde_json::json!({"intent": {
        "schema": "guard-policy-snapshot-withdrawal.v1",
        "runtime_identity": store.expected_runtime_identity,
        "scope_digest": store.expected_scope_digest,
        "resident_generation": store.resident_generation,
        "expected_authority": expected,
        "retirement_generation": generation,
        "retirement_policy_digest": "d".repeat(64),
    }, "mac": ""});
    sign(&mut value, key);
    value
}

fn sign(value: &mut Value, key: &[u8]) {
    value["mac"] = hex::encode(crate::hmac_sha256(
        key,
        b"hol-guard-policy-snapshot-withdrawal-v1\0",
        &canonical_json_bytes(&value["intent"]).unwrap(),
    ))
    .into();
}

fn push(snapshot: &PolicySnapshotV3) -> Value {
    serde_json::json!({"schema": POLICY_SNAPSHOT_PUSH_SCHEMA, "snapshot": snapshot})
}

#[test]
fn withdrawal_retains_floor_and_rejects_literal_retry_and_restart_replay() {
    let root = test_root("withdraw-restart");
    let key = install_test_key(&root, 42);
    let store =
        PolicySnapshotStore::new_with_resident_generation(&root, &"a".repeat(64), 7).unwrap();
    let old = signed_snapshot(1, &key, &root);
    store.push(&push(&old)).unwrap();
    let withdrawal = request(&store, 10, &key);
    let ack: Value = serde_json::from_slice(&store.withdraw(&withdrawal).unwrap()).unwrap();
    assert_eq!(ack["response"]["status"], "withdrawn");
    assert_eq!(ack["response"]["generation"], 10);
    assert!(store.current_snapshot().is_err());
    assert!(store.withdraw(&withdrawal).is_err());
    let restarted =
        PolicySnapshotStore::new_with_resident_generation(&root, &"a".repeat(64), 7).unwrap();
    assert!(restarted.current_snapshot().is_err());
    assert!(restarted.withdraw(&withdrawal).is_err());
    let retry: Value = serde_json::from_slice(&restarted.push(&push(&old)).unwrap()).unwrap();
    assert_eq!(
        retry["status"],
        "native_policy_snapshot_requires_new_generation"
    );
    assert_eq!(retry["generation"], 10);
    let fresh = signed_snapshot(11, &key, &root);
    let ack: Value = serde_json::from_slice(&restarted.push(&push(&fresh)).unwrap()).unwrap();
    assert_eq!(ack["status"], "accepted");
    assert_eq!(restarted.current_generation(), Some(11));
    assert!(restarted.withdraw(&withdrawal).is_err());
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn stale_resident_cannot_overwrite_a_durable_retirement_with_reserved_input() {
    let root = test_root("stale-durable-floor");
    let key = install_test_key(&root, 43);
    let stale = PolicySnapshotStore::new(&root, &"a".repeat(64)).unwrap();
    stale.push(&push(&signed_snapshot(1, &key, &root))).unwrap();
    // This exact durable floor represents an independent completed withdrawal.
    // The old implementation validated only its in-memory generation 1 and
    // accepted generation 9 over the authenticated retired floor 10.
    crate::policy_store::persist_authority(
        &root.join(SNAPSHOT_FILE_NAME),
        10,
        &"d".repeat(64),
        None,
        &key,
    )
    .unwrap();
    let ack: Value =
        serde_json::from_slice(&stale.push(&push(&signed_snapshot(9, &key, &root))).unwrap())
            .unwrap();
    assert_eq!(
        ack["status"],
        "native_policy_snapshot_requires_new_generation"
    );
    assert_eq!(ack["generation"], 10);
    assert!(stale.current_snapshot().is_err());
    let restarted = PolicySnapshotStore::new(&root, &"a".repeat(64)).unwrap();
    assert!(restarted.current_snapshot().is_err());
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn absent_authority_can_retire_a_first_candidate_without_creating_policy() {
    let root = test_root("withdraw-absent");
    let key = install_test_key(&root, 44);
    let first =
        PolicySnapshotStore::new_with_resident_generation(&root, &"a".repeat(64), 8).unwrap();
    let stale = PolicySnapshotStore::new(&root, &"a".repeat(64)).unwrap();
    first.withdraw(&request(&first, 5, &key)).unwrap();
    let ack: Value =
        serde_json::from_slice(&stale.push(&push(&signed_snapshot(4, &key, &root))).unwrap())
            .unwrap();
    assert_eq!(
        ack["status"],
        "native_policy_snapshot_requires_new_generation"
    );
    assert!(stale.current_snapshot().is_err());
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn withdrawal_authenticates_purpose_subject_and_exact_precondition() {
    let root = test_root("withdraw-subject");
    let key = install_test_key(&root, 45);
    let store =
        PolicySnapshotStore::new_with_resident_generation(&root, &"a".repeat(64), 9).unwrap();
    let old = signed_snapshot(1, &key, &root);
    store.push(&push(&old)).unwrap();
    let good = request(&store, 10, &key);
    let path = root.join(SNAPSHOT_FILE_NAME);
    let original = fs::read(&path).unwrap();
    let mut invalid = Vec::new();
    for field in [
        "schema",
        "runtime_identity",
        "scope_digest",
        "resident_generation",
        "retirement_generation",
        "retirement_policy_digest",
        "expected_authority",
    ] {
        let mut missing = good.clone();
        missing["intent"].as_object_mut().unwrap().remove(field);
        sign(&mut missing, &key);
        invalid.push(missing);
    }
    for (field, replacement) in [
        ("runtime_identity", Value::from("b".repeat(64))),
        ("scope_digest", Value::from("c".repeat(64))),
        ("resident_generation", Value::from(10)),
        ("retirement_generation", Value::from(1)),
    ] {
        let mut altered = good.clone();
        altered["intent"][field] = replacement;
        sign(&mut altered, &key);
        invalid.push(altered);
    }
    for field in ["fingerprint", "policy_digest"] {
        let mut altered = good.clone();
        altered["intent"]["expected_authority"][field] = "e".repeat(64).into();
        sign(&mut altered, &key);
        invalid.push(altered);
    }
    let mut changed_kind = good.clone();
    changed_kind["intent"]["expected_authority"]["usable_snapshot"] = false.into();
    sign(&mut changed_kind, &key);
    invalid.push(changed_kind);
    let mut floor_mac = good.clone();
    floor_mac["mac"] = generation_floor_mac(10, &"d".repeat(64), &key).into();
    invalid.push(floor_mac);
    let mut unknown = good.clone();
    unknown["intent"]["extra"] = true.into();
    sign(&mut unknown, &key);
    invalid.push(unknown);
    for bad in invalid {
        assert!(store.withdraw(&bad).is_err());
        assert_eq!(fs::read(&path).unwrap(), original);
        assert_eq!(store.current_generation(), Some(1));
    }
    store.withdraw(&good).unwrap();
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn missing_or_regressed_durable_state_closes_stale_admission() {
    for remove in [false, true] {
        let root = test_root(if remove {
            "withdraw-missing"
        } else {
            "withdraw-regressed"
        });
        let key = install_test_key(&root, 46);
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
fn writer_contention_refuses_without_a_new_wait_or_file_replacement() {
    let root = test_root("withdraw-contention");
    let key = install_test_key(&root, 47);
    let store =
        PolicySnapshotStore::new_with_resident_generation(&root, &"a".repeat(64), 10).unwrap();
    let withdrawal = request(&store, 4, &key);
    let guard = acquire_writer(&root).unwrap();
    assert_eq!(
        store.withdraw(&withdrawal).unwrap_err(),
        "native_policy_snapshot_writer_busy"
    );
    assert_eq!(
        store
            .push(&push(&signed_snapshot(1, &key, &root)))
            .unwrap_err(),
        "native_policy_snapshot_writer_busy"
    );
    assert!(PolicySnapshotStore::new(&root, &"a".repeat(64)).is_err());
    assert!(PolicySnapshotStore::migrate_legacy_state(&root, &"a".repeat(64)).is_err());
    drop(guard);
    store.withdraw(&withdrawal).unwrap();
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn withdrawal_write_failure_never_returns_a_successful_ack() {
    for boundary in [
        PersistBoundary::TemporaryCreate,
        PersistBoundary::Write,
        PersistBoundary::FileSync,
        PersistBoundary::Rename,
        PersistBoundary::DirectorySync,
    ] {
        let root = test_root("withdraw-fault");
        let key = install_test_key(&root, 48);
        let store =
            PolicySnapshotStore::new_with_resident_generation(&root, &"a".repeat(64), 11).unwrap();
        store.push(&push(&signed_snapshot(1, &key, &root))).unwrap();
        let withdrawal = request(&store, 4, &key);
        PERSIST_FAILPOINT.with(|failpoint| failpoint.set(boundary as u8));
        assert!(store.withdraw(&withdrawal).is_err());
        assert!(store.current_snapshot().is_err());
        let restarted =
            PolicySnapshotStore::new_with_resident_generation(&root, &"a".repeat(64), 11).unwrap();
        if matches!(boundary, PersistBoundary::DirectorySync) {
            assert!(restarted.current_snapshot().is_err());
            assert!(restarted.withdraw(&withdrawal).is_err());
        } else {
            assert_eq!(restarted.current_generation(), Some(1));
        }
        fs::remove_dir_all(root).unwrap();
    }
}

#[test]
fn approval_authority_change_cannot_be_cleared_by_withdrawal_or_push() {
    let root = test_root("withdraw-approval");
    let key = install_test_key(&root, 49);
    let store =
        PolicySnapshotStore::new_with_resident_generation(&root, &"a".repeat(64), 12).unwrap();
    store.push(&push(&signed_snapshot(1, &key, &root))).unwrap();
    let withdrawal = request(&store, 4, &key);
    fixture_file(
        &root.join(crate::policy_store::approval_authority::APPROVAL_AUTHORITY_FILE_NAME),
        b"changed",
    );
    assert!(store.withdraw(&withdrawal).is_err());
    assert!(store.current_snapshot().is_err());
    assert!(store.push(&push(&signed_snapshot(5, &key, &root))).is_err());
    assert!(store.current_snapshot().is_err());
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn writer_child() {
    let Some(root) = std::env::var_os("GUARD_WITHDRAWAL_TEST_WRITER_ROOT") else {
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
    let root = test_root("withdraw-two-process");
    let key = install_test_key(&root, 50);
    let store =
        PolicySnapshotStore::new_with_resident_generation(&root, &"a".repeat(64), 13).unwrap();
    let withdrawal = request(&store, 4, &key);
    let mut child = ChildGuard(
        Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "policy_store::tests::withdrawal_tests::writer_child",
                "--nocapture",
            ])
            .env("GUARD_WITHDRAWAL_TEST_WRITER_ROOT", &root)
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
        store.withdraw(&withdrawal).unwrap_err(),
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
    store.withdraw(&withdrawal).unwrap();
    fs::remove_dir_all(root).unwrap();
}

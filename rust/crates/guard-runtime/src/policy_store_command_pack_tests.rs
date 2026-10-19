use super::*;
use std::sync::Arc;

#[test]
fn warm_native_security_quarantine_is_terminal_and_survives_restart() {
    let root = test_root("command-pack-security");
    let key = install_test_key(&root, 96);
    let store = PolicySnapshotStore::new(&root, &"a".repeat(64)).unwrap();
    let before = command_floor_tests::control_snapshot(1, 5, 9, "enabled", &key, &root);
    command_authority_tests::publish_marker(&store, &before, "committed");
    store
        .push(&serde_json::json!({"schema":POLICY_SNAPSHOT_PUSH_SCHEMA,"snapshot":before}))
        .unwrap();
    let warm = store.current_admitted_snapshot().unwrap();
    let mut after = before.clone();
    after.generation = 2;
    let binding = after.command_extensions.as_mut().unwrap();
    let (record, digest) =
        crate::active_pack_security::fixture_record(&binding.program_digest, &key, false);
    fixture_file(
        &root.join(crate::active_pack_security::FILE),
        record.as_bytes(),
    );
    #[cfg(unix)]
    fs::set_permissions(
        root.join(crate::active_pack_security::FILE),
        fs::Permissions::from_mode(0o600),
    )
    .unwrap();
    binding.active_security_digest = Some(digest);
    binding.effective_digest = binding.compute_effective_digest().unwrap();
    binding.authority.as_mut().unwrap().mutation_revision += 1;
    command_floor_tests::resign(&mut after, &key);
    command_authority_tests::publish_marker(&store, &after, "committed");
    assert!(store.command_authority_lease(&warm).is_err());
    store
        .push(&serde_json::json!({"schema":POLICY_SNAPSHOT_PUSH_SCHEMA,"snapshot":after}))
        .unwrap();
    let check = |store: &PolicySnapshotStore| {
        let snapshot = store.current_admitted_snapshot().unwrap();
        let _lease = store.command_authority_lease(&snapshot).unwrap();
        let result = guard_command::pretool::evaluate_pre_tool_envelope_with_execution_context(
            "claude",
            "PreToolUse",
            &serde_json::json!({"tool_name":"Bash","tool_input":{"command":"git status"}}),
            snapshot.command_extensions.as_ref(),
            None,
            guard_command::pretool::PathContext::default(),
            None,
        );
        assert_eq!(result.minimum_action, "block");
        assert_eq!(result.policy_action, "block");
        assert_eq!(result.reason_code, "native_active_pack_quarantine");
    };
    check(&store);
    drop(store);
    let restarted = PolicySnapshotStore::new(&root, &"a".repeat(64)).unwrap();
    check(&restarted);
    remove_pack_test_root(&root);
}

fn remove_pack_test_root(root: &Path) {
    assert!(root
        .file_name()
        .unwrap()
        .to_str()
        .unwrap()
        .starts_with("hol-guard-policy-store-command-pack-"));
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn slow_candidate_admission_keeps_previous_decision_state_readable() {
    let root = test_root("command-pack-concurrent-admission");
    let key = install_test_key(&root, 93);
    let store = Arc::new(PolicySnapshotStore::new(&root, &"a".repeat(64)).unwrap());
    let current = command_floor_tests::control_snapshot(1, 5, 9, "enabled", &key, &root);
    command_authority_tests::publish_marker(&store, &current, "committed");
    store
        .push(&serde_json::json!({"schema":POLICY_SNAPSHOT_PUSH_SCHEMA,"snapshot":current}))
        .unwrap();
    let previous = store.state.lock().unwrap().snapshot.clone().unwrap();
    let mut candidate = current.clone();
    candidate.generation = 2;
    command_floor_tests::resign(&mut candidate, &key);
    let request = serde_json::from_value(serde_json::json!({
        "schema":POLICY_SNAPSHOT_PUSH_SCHEMA,"snapshot":candidate
    }))
    .unwrap();
    let (entered, started) = std::sync::mpsc::sync_channel(0);
    let (release, wait) = std::sync::mpsc::sync_channel(0);
    let worker_store = Arc::clone(&store);
    let worker = std::thread::spawn(move || {
        worker_store.push_locked_with_admission(request, |snapshot, state_base| {
            entered.send(()).unwrap();
            wait.recv_timeout(std::time::Duration::from_secs(5))
                .unwrap();
            super::super::policy_store_command_packs::admit(snapshot, state_base)
        })
    });
    started
        .recv_timeout(std::time::Duration::from_secs(5))
        .unwrap();
    let readable = store.state.try_lock().is_ok_and(|state| {
        state
            .snapshot
            .as_ref()
            .is_some_and(|active| Arc::ptr_eq(active, &previous))
    });
    release.send(()).unwrap();
    worker.join().unwrap().unwrap();
    assert!(
        readable,
        "candidate I/O must not block reads of the previous snapshot"
    );
    assert_eq!(store.current_generation(), Some(2));
    remove_pack_test_root(&root);
}

#[test]
fn admission_rechecks_authority_state_before_publishing() {
    let root = test_root("command-pack-obsolete-admission");
    let key = install_test_key(&root, 94);
    let store = PolicySnapshotStore::new(&root, &"a".repeat(64)).unwrap();
    let current = command_floor_tests::control_snapshot(1, 5, 9, "enabled", &key, &root);
    command_authority_tests::publish_marker(&store, &current, "committed");
    store
        .push(&serde_json::json!({"schema":POLICY_SNAPSHOT_PUSH_SCHEMA,"snapshot":current}))
        .unwrap();
    let previous = store.state.lock().unwrap().snapshot.clone().unwrap();
    let mut candidate = current.clone();
    candidate.generation = 2;
    command_floor_tests::resign(&mut candidate, &key);
    let request = serde_json::from_value(serde_json::json!({
        "schema":POLICY_SNAPSHOT_PUSH_SCHEMA,"snapshot":candidate
    }))
    .unwrap();
    let error = store
        .push_locked_with_admission(request, |snapshot, state_base| {
            // Model an independently observed authority change during slow I/O.
            store.state.try_lock().unwrap().generation_floor = 3;
            super::super::policy_store_command_packs::admit(snapshot, state_base)
        })
        .unwrap_err();
    assert_eq!(error, "native_policy_snapshot_admission_obsolete");
    assert!(Arc::ptr_eq(
        &previous,
        store.state.lock().unwrap().snapshot.as_ref().unwrap()
    ));
    assert_eq!(store.current_generation(), Some(1));
    remove_pack_test_root(&root);
}

#[test]
fn unprepared_pack_candidate_keeps_the_previous_authenticated_generation() {
    let root = test_root("command-pack-incomplete");
    let key = install_test_key(&root, 91);
    let store = PolicySnapshotStore::new(&root, &"a".repeat(64)).unwrap();
    let current = command_floor_tests::control_snapshot(1, 5, 9, "enabled", &key, &root);
    command_authority_tests::publish_marker(&store, &current, "committed");
    store
        .push(&serde_json::json!({"schema":POLICY_SNAPSHOT_PUSH_SCHEMA,"snapshot":current}))
        .unwrap();
    let before = store.state.lock().unwrap().snapshot.clone().unwrap();
    let mut candidate = current.clone();
    candidate.generation = 2;
    candidate
        .command_extensions
        .as_mut()
        .unwrap()
        .program_digest = "f".repeat(64);
    command_floor_tests::resign(&mut candidate, &key);
    let error = store
        .push(&serde_json::json!({"schema":POLICY_SNAPSHOT_PUSH_SCHEMA,"snapshot":candidate}))
        .unwrap_err();
    assert_eq!(error, "native_command_control_authority_not_current");
    assert_eq!(store.current_generation(), Some(1));
    assert!(Arc::ptr_eq(
        &before,
        store.state.lock().unwrap().snapshot.as_ref().unwrap()
    ));
    assert!(store.command_authority_lease(&before).unwrap().is_some());
    drop(before);
    drop(store);
    let restarted = PolicySnapshotStore::new(&root, &"a".repeat(64)).unwrap();
    assert_eq!(restarted.current_generation(), Some(1));
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn pack_marker_authenticates_its_program_and_uses_a_distinct_domain() {
    let root = test_root("command-pack-marker");
    let key = install_test_key(&root, 92);
    let store = PolicySnapshotStore::new(&root, &"a".repeat(64)).unwrap();
    let snapshot = command_floor_tests::control_snapshot(1, 5, 9, "enabled", &key, &root);
    command_authority_tests::publish_marker(&store, &snapshot, "committed");
    let path = root.join("command-control-authority.v1.json");
    let mut value: Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
    value["schema"] = "guard.native-command-control-authority.v2".into();
    value["pack_program_digest"] = snapshot
        .command_extensions
        .as_ref()
        .unwrap()
        .program_digest
        .clone()
        .into();
    value.as_object_mut().unwrap().remove("mac");
    let mut bytes = b"hol-guard.native-command-control-authority.v2\0".to_vec();
    bytes.extend(canonical_json_bytes(&value).unwrap());
    value["mac"] = hex::encode(
        ring::hmac::sign(
            &ring::hmac::Key::new(ring::hmac::HMAC_SHA256, &store.verifier_key),
            &bytes,
        )
        .as_ref(),
    )
    .into();
    fixture_file(&path, &canonical_json_bytes(&value).unwrap());
    assert!(store.command_authority_lease(&snapshot).unwrap().is_some());
    value["pack_program_digest"] = "f".repeat(64).into();
    fixture_file(&path, &canonical_json_bytes(&value).unwrap());
    assert!(store.command_authority_lease(&snapshot).is_err());
    fs::remove_dir_all(root).unwrap();
}

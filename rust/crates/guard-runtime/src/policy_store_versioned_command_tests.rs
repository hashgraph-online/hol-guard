//! Compose scoped source authority with independent command controls.
use super::*;
use crate::policy_store::tests::{command_authority_tests, command_floor_tests, withdrawal_tests};

fn controlled(
    generation: u64,
    key: &[u8],
    root: &Path,
    mode: &str,
) -> (PolicySnapshotV4, PolicySnapshotV3) {
    let mut controls =
        command_floor_tests::control_snapshot(generation, generation, 1, "enabled", key, root);
    let binding = controls.command_extensions.as_mut().unwrap();
    binding.layers[0].global_lockdown = true;
    binding.effective_digest = binding.compute_effective_digest().unwrap();
    command_floor_tests::resign(&mut controls, key);
    let mut candidate = defaults_snapshot(generation, key, root, "allow", mode);
    candidate.command_extensions = controls.command_extensions.clone();
    sign(&mut candidate, key);
    (candidate, controls)
}

#[test]
fn scoped_source_and_command_authority_are_both_required_at_admission() {
    let root = test_root("v4-command-admission");
    let key = install_test_key(&root, 85);
    let store = PolicySnapshotStore::new(&root, &"a".repeat(64)).unwrap();
    let (candidate, controls) = controlled(1, &key, &root, "enforce");
    assert!(store.push(&push_value(&candidate)).is_err());
    command_authority_tests::publish_marker(&store, &controls, "committed");
    for field in ["program_digest", "catalog_digest", "trust_digest"] {
        let mut value = serde_json::to_value(&candidate).unwrap();
        value["command_extensions"][field] = "b".repeat(64).into();
        let altered: PolicySnapshotV4 = serde_json::from_value(value).unwrap();
        assert_ne!(policy_digest_v4(&altered).unwrap(), candidate.policy_digest);
        assert!(store.push(&push_value(&altered)).is_err());
    }
    store.push(&push_value(&candidate)).unwrap();
    let loaded = store
        .validate_versioned_request_snapshot(&reference(&candidate), root.to_str().unwrap(), 1)
        .unwrap();
    assert_eq!(
        loaded.source_input_digest(),
        Some(candidate.source_input_digest.as_str())
    );
    assert_eq!(
        loaded.command_extensions(),
        candidate.command_extensions.as_ref()
    );
    command_authority_tests::publish_marker(&store, &controls, "closed");
    assert!(
        store.push(&push_value(&candidate)).is_err(),
        "retry cannot bypass a closed control authority"
    );
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn command_lockdown_survives_scoped_allow_observe_and_receipt_composition() {
    let root = test_root("v4-command-scoped-floor");
    let key = install_test_key(&root, 86);
    let store =
        PolicySnapshotStore::new_with_resident_generation(&root, &"a".repeat(64), 47).unwrap();
    for (generation, mode) in [(1, "enforce"), (2, "observe")] {
        let (candidate, controls) = controlled(generation, &key, &root, mode);
        command_authority_tests::publish_marker(&store, &controls, "committed");
        store.push(&push_value(&candidate)).unwrap();
        // printf exercises scoped generic composition; ollama takes the defaults
        // path. Both retain the independent command-control block.
        for command in ["printf synthetic", "ollama list"] {
            let source = request(
                &candidate,
                &root,
                "PreToolUse",
                json!({
                    "tool_name":"Shell", "tool_input":{"command":command},
                    "source_scope":"project", "approval_requests":[]
                }),
            );
            let lock = fs::OpenOptions::new()
                .read(true)
                .write(true)
                .open(root.join("extension-control-authority.lock"))
                .unwrap();
            crate::edge::AFTER_EVALUATION.with(|observer| {
                *observer.borrow_mut() = Some(Box::new(move || {
                    assert!(
                        fs2::FileExt::try_lock_exclusive(&lock).is_err(),
                        "command authority lease must cover completed evaluation"
                    );
                }));
            });
            let result = edge(&store, source);
            assert_eq!(result["result"]["decision"], "deny", "{command}/{mode}");
            assert_eq!(result["result"]["minimum_action"], "block");
            assert_eq!(
                result["receipt"]["command_extensions"],
                result["result"]["command_extensions"]["binding"]
            );
            assert!(!result["receipt"]["command_extensions"].is_null());
            assert_eq!(
                result["policy_binding"]["source_input_digest"],
                candidate.source_input_digest
            );
        }
    }
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn withdrawal_keeps_independent_command_floor_across_versions_and_restart() {
    let root = test_root("v4-command-withdrawal-floor");
    let key = install_test_key(&root, 87);
    let store =
        PolicySnapshotStore::new_with_resident_generation(&root, &"a".repeat(64), 48).unwrap();
    let (candidate, controls) = controlled(1, &key, &root, "enforce");
    command_authority_tests::publish_marker(&store, &controls, "committed");
    store.push(&push_value(&candidate)).unwrap();
    store
        .withdraw(&withdrawal_tests::request(&store, 2, &key))
        .unwrap();
    drop(store);
    let restarted = PolicySnapshotStore::new(&root, &"a".repeat(64)).unwrap();
    let missing = defaults_snapshot(3, &key, &root, "allow", "enforce");
    assert_eq!(
        restarted.push(&push_value(&missing)).unwrap_err(),
        "native_command_control_binding_removed"
    );
    let legacy = signed_snapshot(3, &key, &root);
    assert_eq!(
        restarted
            .push(&json!({"schema":POLICY_SNAPSHOT_PUSH_SCHEMA,"snapshot":legacy}))
            .unwrap_err(),
        "native_command_control_binding_removed"
    );
    let (fresh, controls) = controlled(3, &key, &root, "enforce");
    command_authority_tests::publish_marker(&restarted, &controls, "committed");
    restarted.push(&push_value(&fresh)).unwrap();
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn native_composition_cannot_erase_an_equal_independent_command_review() {
    let root = test_root("composed-command-equal-review");
    let key = install_test_key(&root, 88);
    let snapshot = command_floor_tests::control_snapshot(1, 1, 1, "enabled", &key, &root);
    let controls = guard_command::native_command_controls::CompiledNativeCommandControls::new(
        snapshot.command_extensions.as_ref().unwrap(),
    )
    .unwrap();
    let payload = json!({"tool_name":"Shell", "tool_input":{"command":"ollama push synthetic"}});
    // This unit exercises the native composition boundary directly. The V4
    // source producer currently refuses this command shape; it is not evidence
    // of a supported source-to-resident route for that producer.
    let (result, metadata) = guard_command::pretool::evaluate_pre_tool_envelope_with_composition(
        "codex",
        "PreToolUse",
        &payload,
        Some(&controls),
        None,
        |mut intrinsic| {
            assert_eq!(intrinsic.minimum_action, "review");
            intrinsic.minimum_action = "allow".into();
            intrinsic.policy_action = "allow".into();
            intrinsic.decision = "allow".into();
            intrinsic.explicitly_benign = true;
            Ok((intrinsic, "authenticated-composition"))
        },
    )
    .unwrap();
    assert_eq!(metadata, "authenticated-composition");
    assert_eq!(result.minimum_action, "review");
    assert_eq!(result.decision, "deny");
    assert_eq!(result.reason_code, "native_command_extension_review");
    assert!(result.command_extensions.unwrap().binding.observation_count > 0);
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn command_bound_defaults_preserve_legacy_observe_and_enforce_ordering() {
    let root = test_root("v4-command-default-ordering");
    let key = install_test_key(&root, 89);
    let payload = json!({"tool_name":"Shell", "tool_input":{"command":"ollama push synthetic"}});
    for mode in ["enforce", "observe"] {
        for action in [
            "allow",
            "warn",
            "review",
            "require-reapproval",
            "sandbox-required",
            "block",
        ] {
            let controls = command_floor_tests::control_snapshot(1, 1, 1, "enabled", &key, &root);
            let mut candidate = defaults_snapshot(1, &key, &root, action, mode);
            candidate.command_extensions = controls.command_extensions.clone();
            sign(&mut candidate, &key);
            let mut legacy = controls;
            legacy.effective_policy = candidate.effective_policy.clone();
            legacy.mode = mode.into();
            let source = request(&candidate, &root, "PreToolUse", payload.clone());
            assert!(
                crate::policy_scoped_request::derive_scoped_policy_request(&source, "codex")
                    .is_err()
            );
            let admitted = crate::policy_enforcement::AdmittedPolicySnapshot::new(legacy).unwrap();
            let expected: Value = serde_json::from_slice(
                &crate::edge::evaluate_envelope_with_snapshot(source.clone(), &admitted).unwrap(),
            )
            .unwrap();
            let actual: Value =
                serde_json::from_slice(&crate::edge_v4::evaluate(source, &candidate, 0).unwrap())
                    .unwrap();
            assert_eq!(actual["result"], expected["result"], "{mode}/{action}");
        }
    }
    fs::remove_dir_all(root).unwrap();
}

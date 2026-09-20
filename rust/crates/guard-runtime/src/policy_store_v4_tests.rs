use super::*;
use guard_policy_snapshot::{
    integrity_mac_v4, policy_digest_v4, PolicySnapshotAckV2, PolicySnapshotV4,
    POLICY_SNAPSHOT_V4_PUSH_SCHEMA, POLICY_SNAPSHOT_V4_SCHEMA,
};

#[path = "edge_v4_defaults_tests.rs"]
mod defaults_edge_tests;

#[path = "policy_store_withdrawal_v4_tests.rs"]
mod withdrawal_tests;

fn snapshot_v4(generation: u64, key: &[u8], root: &Path) -> PolicySnapshotV4 {
    let base = signed_snapshot(generation, key, root);
    let mut value = serde_json::to_value(base).unwrap();
    value["schema"] = POLICY_SNAPSHOT_V4_SCHEMA.into();
    value["version"] = 4.into();
    value["source_input_digest"] = "b".repeat(64).into();
    value["scoped_authority"] = serde_json::json!({
        "schema":"guard-native-policy-authority.v1", "generic_precedence":"specificity-recency.v1",
        "rows":[{"decision_id":1,"harness":"codex","scope":"artifact","action":"block",
            "source_kind":"signed-bundle","updated_at_us":1,"artifact_id":"synthetic-artifact",
            "artifact_hash":null,"workspace":null,"publisher":null,"exact_command_sha256":"c".repeat(64),
            "expires_at_ms":null,"requires_exact_context":false}], "managed":null,
    });
    let mut candidate: PolicySnapshotV4 = serde_json::from_value(value).unwrap();
    sign(&mut candidate, key);
    candidate
}

fn sign(candidate: &mut PolicySnapshotV4, key: &[u8]) {
    candidate.config_digest = config_digest(&candidate.effective_policy).unwrap();
    candidate.policy_digest = policy_digest_v4(candidate).unwrap();
    candidate.integrity.mac = integrity_mac_v4(candidate, key).unwrap();
}

fn push_value(candidate: &PolicySnapshotV4) -> Value {
    serde_json::json!({"schema":POLICY_SNAPSHOT_V4_PUSH_SCHEMA,"snapshot":candidate})
}

fn reference(candidate: &PolicySnapshotV4) -> Value {
    serde_json::json!({"generation":candidate.generation,"policy_digest":candidate.policy_digest,
        "runtime_identity":candidate.runtime_identity,"source_input_digest":candidate.source_input_digest})
}

#[test]
fn scoped_snapshot_is_durable_exact_and_never_projected_to_legacy_consumer() {
    let root = test_root("v4-durable");
    let key = install_test_key(&root, 19);
    let candidate = snapshot_v4(4, &key, &root);
    let store =
        PolicySnapshotStore::new_with_resident_generation(&root, &"a".repeat(64), 29).unwrap();
    let ack: PolicySnapshotAckV2 =
        serde_json::from_slice(&store.push(&push_value(&candidate)).unwrap()).unwrap();
    assert_eq!(ack.source_input_digest, candidate.source_input_digest);
    assert_eq!(ack.policy_digest, candidate.policy_digest);
    assert_eq!(ack.generation, 4);
    assert_eq!(ack.resident_generation, 29);
    assert!(!ack.idempotent);
    let retry: PolicySnapshotAckV2 =
        serde_json::from_slice(&store.push(&push_value(&candidate)).unwrap()).unwrap();
    assert!(retry.idempotent);
    assert_eq!(
        store.current_snapshot().unwrap_err(),
        "native_policy_snapshot_consumer_version_unsupported"
    );
    let loaded = store
        .validate_versioned_request_snapshot(&reference(&candidate), root.to_str().unwrap(), 4)
        .unwrap();
    assert_eq!(
        loaded.source_input_digest(),
        Some(candidate.source_input_digest.as_str())
    );
    assert!(store
        .validate_request_snapshot(&reference(&candidate), root.to_str().unwrap(), 4)
        .is_err());
    drop(store);
    let reopened = PolicySnapshotStore::new(&root, &"a".repeat(64)).unwrap();
    let reopened_value = reopened
        .validate_versioned_request_snapshot(&reference(&candidate), root.to_str().unwrap(), 4)
        .unwrap();
    assert_eq!(
        serde_json::to_value(reopened_value.as_ref()).unwrap(),
        serde_json::to_value(&candidate).unwrap()
    );
    assert_eq!(reopened.current_generation(), Some(4));
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn scoped_request_requires_the_exact_source_commitment() {
    let root = test_root("v4-reference");
    let key = install_test_key(&root, 20);
    let candidate = snapshot_v4(6, &key, &root);
    let store = PolicySnapshotStore::new(&root, &"a".repeat(64)).unwrap();
    store.push(&push_value(&candidate)).unwrap();
    let mut missing = reference(&candidate);
    missing
        .as_object_mut()
        .unwrap()
        .remove("source_input_digest");
    assert!(store
        .validate_versioned_request_snapshot(&missing, root.to_str().unwrap(), 6)
        .is_err());
    let mut wrong = reference(&candidate);
    wrong["source_input_digest"] = "c".repeat(64).into();
    assert!(store
        .validate_versioned_request_snapshot(&wrong, root.to_str().unwrap(), 6)
        .is_err());
    assert!(store
        .validate_versioned_request_snapshot(
            &serde_json::to_value(&candidate).unwrap(),
            root.to_str().unwrap(),
            6
        )
        .is_ok());
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn scoped_and_legacy_snapshots_share_one_authenticated_generation_floor() {
    let root = test_root("v4-floor");
    let key = install_test_key(&root, 21);
    let store = PolicySnapshotStore::new(&root, &"a".repeat(64)).unwrap();
    let legacy = signed_snapshot(5, &key, &root);
    store
        .push(&serde_json::json!({"schema":POLICY_SNAPSHOT_PUSH_SCHEMA,"snapshot":legacy}))
        .unwrap();
    assert!(store
        .push(&push_value(&snapshot_v4(4, &key, &root)))
        .is_err());
    store
        .push(&push_value(&snapshot_v4(6, &key, &root)))
        .unwrap();
    assert!(store
        .push(&serde_json::json!({"schema":POLICY_SNAPSHOT_PUSH_SCHEMA,"snapshot":legacy}))
        .is_err());
    drop(store);
    let reopened = PolicySnapshotStore::new(&root, &"a".repeat(64)).unwrap();
    assert!(reopened
        .push(&serde_json::json!({"schema":POLICY_SNAPSHOT_PUSH_SCHEMA,"snapshot":legacy}))
        .is_err());
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn tampered_source_and_wrong_scope_never_receive_an_acceptance_ack() {
    let root = test_root("v4-tamper");
    let key = install_test_key(&root, 22);
    let store = PolicySnapshotStore::new(&root, &"a".repeat(64)).unwrap();
    let candidate = snapshot_v4(7, &key, &root);
    let mut tampered = candidate.clone();
    tampered.source_input_digest = "c".repeat(64);
    assert!(store.push(&push_value(&tampered)).is_err());
    let mut wrong_scope = candidate.clone();
    wrong_scope.scope_contract.scope_digest = "e".repeat(64);
    sign(&mut wrong_scope, &key);
    assert_eq!(
        store.push(&push_value(&wrong_scope)).unwrap_err(),
        "native_policy_snapshot_scope_mismatch"
    );
    assert_eq!(store.current_generation(), None);
    store.push(&push_value(&candidate)).unwrap();
    let mut changed = candidate.clone();
    changed.source_input_digest = "f".repeat(64);
    sign(&mut changed, &key);
    assert_eq!(
        store.push(&push_value(&changed)).unwrap_err(),
        "native_policy_snapshot_generation_reused"
    );
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn scoped_authority_replacement_and_expiry_fail_closed() {
    let root = test_root("v4-expiry");
    let key = install_test_key(&root, 23);
    let store = PolicySnapshotStore::new(&root, &"a".repeat(64)).unwrap();
    let mut candidate = snapshot_v4(8, &key, &root);
    candidate.issued_at_ms = now_ms().unwrap() - 120_000;
    candidate.expires_at_ms = now_ms().unwrap() - 1;
    sign(&mut candidate, &key);
    assert!(store.push(&push_value(&candidate)).is_err());
    candidate = snapshot_v4(9, &key, &root);
    store.push(&push_value(&candidate)).unwrap();
    let file = root.join(SNAPSHOT_FILE_NAME);
    let bytes = fs::read(&file).unwrap();
    let mut value: Value = serde_json::from_slice(&bytes).unwrap();
    value["snapshot"]["source_input_digest"] = "f".repeat(64).into();
    fs::write(&file, canonical_json_bytes(&value).unwrap()).unwrap();
    assert!(store
        .validate_versioned_request_snapshot(&reference(&candidate), root.to_str().unwrap(), 9)
        .is_err());
    let reopened = PolicySnapshotStore::new(&root, &"a".repeat(64)).unwrap();
    assert!(reopened
        .validate_versioned_request_snapshot(&reference(&candidate), root.to_str().unwrap(), 9)
        .is_err());
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn missing_scoped_snapshot_recovery_never_claims_acceptance() {
    let root = test_root("v4-recovery");
    let key = install_test_key(&root, 24);
    let store = PolicySnapshotStore::new(&root, &"a".repeat(64)).unwrap();
    let candidate = snapshot_v4(10, &key, &root);
    store.push(&push_value(&candidate)).unwrap();
    drop(store);
    let file = root.join(SNAPSHOT_FILE_NAME);
    let mut record: Value = serde_json::from_slice(&fs::read(&file).unwrap()).unwrap();
    record["snapshot"] = Value::Null;
    fs::write(&file, canonical_json_bytes(&record).unwrap()).unwrap();
    let reopened = PolicySnapshotStore::new(&root, &"a".repeat(64)).unwrap();
    let recovery: PolicySnapshotAckV2 =
        serde_json::from_slice(&reopened.push(&push_value(&candidate)).unwrap()).unwrap();
    assert_eq!(
        recovery.status,
        guard_policy_snapshot::POLICY_SNAPSHOT_ACK_REQUIRES_NEW_GENERATION
    );
    assert_eq!(recovery.source_input_digest, candidate.source_input_digest);
    assert_eq!(recovery.generation, 10);
    assert!(!recovery.idempotent);
    assert_eq!(reopened.current_generation(), None);
    assert!(reopened
        .validate_versioned_request_snapshot(&reference(&candidate), root.to_str().unwrap(), 10)
        .is_err());
    let mut changed = candidate.clone();
    changed.source_input_digest = "f".repeat(64);
    sign(&mut changed, &key);
    assert!(reopened.push(&push_value(&changed)).is_err());
    changed.generation = 11;
    sign(&mut changed, &key);
    assert!(reopened.push(&push_value(&changed)).is_ok());
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn retry_never_acknowledges_a_removed_or_changed_durable_authority() {
    for changed in [false, true] {
        let root = test_root(if changed {
            "v4-retry-rewritten"
        } else {
            "v4-retry-removed"
        });
        let key = install_test_key(&root, 25);
        let store = PolicySnapshotStore::new(&root, &"a".repeat(64)).unwrap();
        let candidate = snapshot_v4(12, &key, &root);
        store.push(&push_value(&candidate)).unwrap();
        let file = root.join(SNAPSHOT_FILE_NAME);
        if changed {
            fs::write(&file, b"{}").unwrap();
        } else {
            fs::remove_file(&file).unwrap();
        }
        assert!(store.push(&push_value(&candidate)).is_err());
        fs::remove_dir_all(root).unwrap();
    }
}

#[test]
fn scoped_resident_edge_consumes_exact_rule_and_binds_actual_winner() {
    let root = test_root("v4-edge");
    let key = install_test_key(&root, 47);
    let command = "printf hello";
    let mut value = serde_json::to_value(snapshot_v4(9, &key, &root)).unwrap();
    value["effective_policy"]["default_action"] = "review".into();
    value["scoped_authority"]["rows"][0]["action"] = "allow".into();
    value["scoped_authority"]["rows"][0]["scope"] = "workspace".into();
    value["scoped_authority"]["rows"][0]["workspace"] = root.to_str().unwrap().into();
    value["scoped_authority"]["rows"][0]["exact_command_sha256"] =
        guard_command::exact_command::exact_command_sha256(command)
            .unwrap()
            .into();
    let mut candidate: PolicySnapshotV4 = serde_json::from_value(value).unwrap();
    sign(&mut candidate, &key);
    let store =
        PolicySnapshotStore::new_with_resident_generation(&root, &"a".repeat(64), 91).unwrap();
    store.push(&push_value(&candidate)).unwrap();
    let envelope: GuardHookEnvelopeV2 = serde_json::from_value(serde_json::json!({
        "schema":"guard-hook-envelope.v2", "harness":"codex", "event":"PreToolUse",
        "request_id":"scoped-edge-request", "policy_generation":9,"policy_snapshot":reference(&candidate),
        "raw_payload":{"tool_name":"Bash","tool_input":{"command":command},"artifact_id":"synthetic-artifact"},
        "source":{"cwd":root,"home_dir":root,"guard_home":root}
    })).unwrap();
    let evaluate = |input| -> Value {
        serde_json::from_slice(&crate::edge::evaluate_envelope_with_store(input, &store).unwrap())
            .unwrap()
    };
    let result = evaluate(envelope.clone());
    assert_eq!(result["schema"], "guard-hook-edge-result.v3");
    assert_eq!(result["result"]["decision"], "allow");
    assert_eq!(
        result["policy_binding"],
        serde_json::json!({
            "policy_generation":9,"policy_digest":candidate.policy_digest,
            "source_input_digest":candidate.source_input_digest,"runtime_identity":candidate.runtime_identity,
            "resident_generation":91,"selected_decision_id":1
        })
    );
    assert_eq!(result["receipt"]["policy_digest"], candidate.policy_digest);
    assert_eq!(result["receipt"]["rule_digest"], candidate.rule_digest);
    assert_eq!(result["receipt"]["policy_generation"], 9);
    for changed in ["bytes", "artifact", "workspace"] {
        let mut changed_request = envelope.clone();
        match changed {
            "bytes" => {
                changed_request.raw_payload["tool_input"]["command"] = "printf  hello".into()
            }
            "artifact" => changed_request.raw_payload["artifact_id"] = "different-artifact".into(),
            _ => changed_request.source.cwd = Some(std::env::temp_dir().to_str().unwrap().into()),
        }
        let rejected = evaluate(changed_request);
        assert_eq!(rejected["result"]["decision"], "deny", "{changed}");
        assert_eq!(rejected["result"]["minimum_action"], "review", "{changed}");
        assert!(rejected["policy_binding"]["selected_decision_id"].is_null());
    }
    let mut unsupported = envelope.clone();
    unsupported.raw_payload["tool_input"]["command"] = "ssh synthetic-host true".into();
    assert!(crate::edge::evaluate_envelope_with_store(unsupported, &store).is_err());
    let mut stale = envelope.clone();
    stale.policy_snapshot["source_input_digest"] = "f".repeat(64).into();
    assert!(crate::edge::evaluate_envelope_with_store(stale, &store).is_err());
    let mut post_tool = envelope.clone();
    post_tool.event = "PostToolUse".into();
    assert!(crate::edge::evaluate_envelope_with_store(post_tool, &store).is_err());
    fs::remove_file(root.join(SNAPSHOT_FILE_NAME)).unwrap();
    assert!(crate::edge::evaluate_envelope_with_store(envelope, &store).is_err());
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn scoped_observe_receipt_retains_the_would_enforce_action() {
    for mode in ["enforce", "observe"] {
        let root = test_root(&format!("v4-observed-{mode}"));
        let key = install_test_key(&root, 49);
        let mut value = serde_json::to_value(snapshot_v4(11, &key, &root)).unwrap();
        value["mode"] = mode.into();
        value["effective_policy"]["default_action"] = "allow".into();
        value["scoped_authority"]["rows"][0]["scope"] = "global".into();
        value["scoped_authority"]["rows"][0]["artifact_id"] = Value::Null;
        value["scoped_authority"]["rows"][0]["exact_command_sha256"] = Value::Null;
        let mut candidate: PolicySnapshotV4 = serde_json::from_value(value).unwrap();
        sign(&mut candidate, &key);
        let store = PolicySnapshotStore::new(&root, &"a".repeat(64)).unwrap();
        store.push(&push_value(&candidate)).unwrap();
        let envelope: GuardHookEnvelopeV2 = serde_json::from_value(serde_json::json!({
            "schema":"guard-hook-envelope.v2", "harness":"codex", "event":"PreToolUse",
            "request_id":"scoped-observe-request", "policy_generation":11,
            "policy_snapshot":reference(&candidate),
            "raw_payload":{"tool_name":"Bash","tool_input":{"command":"printf safe"}},
            "source":{"cwd":root,"home_dir":root,"guard_home":root}
        }))
        .unwrap();
        let result: Value = serde_json::from_slice(
            &crate::edge::evaluate_envelope_with_store(envelope, &store).unwrap(),
        )
        .unwrap();
        let observed = if mode == "observe" {
            serde_json::json!("block")
        } else {
            Value::Null
        };
        assert_eq!(result["observed_policy_action"], observed);
        assert_eq!(result["receipt"]["observed_policy_action"], observed);
        assert_eq!(result["receipt"]["observe_mode"], mode == "observe");
        // The actual generic consumer projects a policy-only Block to Allow;
        // the original Block and selected rule remain in the receipt binding.
        let actual_action = if mode == "observe" { "allow" } else { "block" };
        assert_eq!(result["result"]["policy_action"], actual_action);
        assert_eq!(result["receipt"]["policy_action"], actual_action);
        assert_eq!(
            result["result"]["decision"],
            if mode == "observe" { "allow" } else { "deny" }
        );
        assert_eq!(result["policy_binding"]["selected_decision_id"], 1);
        fs::remove_dir_all(root).unwrap();
    }
}

#[test]
fn managed_catalog_and_target_semantics_are_checked_before_durable_ack() {
    let root = test_root("v4-managed-admission");
    let key = install_test_key(&root, 37);
    let store = PolicySnapshotStore::new(&root, &"a".repeat(64)).unwrap();
    let mut candidate = snapshot_v4(4, &key, &root);
    let mut authority = serde_json::to_value(&candidate.scoped_authority).unwrap();
    authority["managed"] = serde_json::json!({"revision":2,"managed_revision":7,
        "catalog_digest":"e".repeat(64),"global_lockdown":true,"controls":[]});
    candidate.scoped_authority = serde_json::from_value(authority.clone()).unwrap();
    sign(&mut candidate, &key);
    assert_eq!(
        store.push(&push_value(&candidate)).unwrap_err(),
        "native_scoped_managed_catalog_mismatch"
    );
    assert_eq!(store.current_generation(), None);
    authority["managed"]["catalog_digest"] = crate::policy_scoped_managed::catalog_digest().into();
    authority["managed"]["controls"] = serde_json::json!([
        {"target_kind":"extension","target_id":"command.package.node","state":"enabled"}]);
    candidate.scoped_authority = serde_json::from_value(authority.clone()).unwrap();
    sign(&mut candidate, &key);
    assert_eq!(
        store.push(&push_value(&candidate)).unwrap_err(),
        "native_scoped_managed_policy_unsupported"
    );
    assert_eq!(store.current_generation(), None);
    authority["managed"]["controls"] = serde_json::json!([
        {"target_kind":"extension","target_id":"command.filesystem","state":"disabled"}]);
    candidate.scoped_authority = serde_json::from_value(authority).unwrap();
    sign(&mut candidate, &key);
    let ack: PolicySnapshotAckV2 =
        serde_json::from_slice(&store.push(&push_value(&candidate)).unwrap()).unwrap();
    assert_eq!(ack.status, "accepted");
    assert_eq!(ack.policy_digest, candidate.policy_digest);
    assert_eq!(ack.source_input_digest, candidate.source_input_digest);
    drop(store);
    let reopened = PolicySnapshotStore::new(&root, &"a".repeat(64)).unwrap();
    let current = reopened
        .validate_versioned_request_snapshot(&reference(&candidate), root.to_str().unwrap(), 4)
        .unwrap();
    assert_eq!(
        serde_json::to_value(current.as_ref()).unwrap(),
        serde_json::to_value(candidate).unwrap()
    );
    fs::remove_dir_all(root).unwrap();
}

#[path = "policy_store_expression_tests.rs"]
mod expression_tests;

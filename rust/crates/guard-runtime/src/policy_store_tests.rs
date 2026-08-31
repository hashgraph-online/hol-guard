use super::{
    now_ms, read_private_json, scope_digest, GenerationFloorV1, PersistBoundary,
    PolicySnapshotStore, AUTHORITY_RECORD_MAX_BYTES, AUTHORITY_RECORD_SCHEMA,
    GENERATION_FLOOR_FILE_NAME, GENERATION_FLOOR_SCHEMA, PERSIST_FAILPOINT, SNAPSHOT_FILE_NAME,
    VERIFIER_KEY_BYTES, VERIFIER_KEY_FILE_NAME,
};
use guard_contracts::{
    GuardHookEdgeResultV2, GuardHookEnvelopeV2, GuardHookSourceMetadataV2,
    GUARD_HOOK_ENVELOPE_V2_SCHEMA,
};
use guard_policy_snapshot::{
    canonical_json_bytes, config_digest, generation_floor_mac, integrity_mac, policy_digest,
    verifier_key_id, EffectiveNativePolicyV3, PolicySnapshotAckV1, PolicySnapshotV3,
    ScopeContractV3, SnapshotIntegrityV3, POLICY_SNAPSHOT_INTEGRITY_ALGORITHM,
    POLICY_SNAPSHOT_PUSH_SCHEMA, POLICY_SNAPSHOT_SCHEMA,
};
use serde_json::Value;
use std::collections::BTreeMap;
use std::fs;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

fn policy() -> EffectiveNativePolicyV3 {
    EffectiveNativePolicyV3 {
        protection_posture: "protected".into(),
        security_level: "balanced".into(),
        default_action: "warn".into(),
        unknown_publisher_action: "review".into(),
        changed_hash_action: "require-reapproval".into(),
        new_network_domain_action: "warn".into(),
        subprocess_action: "warn".into(),
        risk_actions: BTreeMap::new(),
        harness_risk_actions: BTreeMap::new(),
        harness_actions: BTreeMap::new(),
        publisher_actions: BTreeMap::new(),
        artifact_actions: BTreeMap::new(),
        sandbox_analysis: "off".into(),
        receipt_redaction_level: "full".into(),
    }
}

fn policy_with_default(default_action: &str) -> EffectiveNativePolicyV3 {
    let mut value = policy();
    value.default_action = default_action.to_owned();
    value
}

fn signed_snapshot(generation: u64, key: &[u8], guard_home: &Path) -> PolicySnapshotV3 {
    signed_snapshot_with_policy(generation, key, guard_home, policy())
}

fn signed_snapshot_with_policy(
    generation: u64,
    key: &[u8],
    guard_home: &Path,
    effective_policy: EffectiveNativePolicyV3,
) -> PolicySnapshotV3 {
    let mut snapshot = PolicySnapshotV3 {
        schema: POLICY_SNAPSHOT_SCHEMA.into(),
        version: 3,
        generation,
        policy_digest: String::new(),
        config_digest: config_digest(&effective_policy).unwrap(),
        rule_digest: guard_rule_contract::rule_digest(),
        runtime_identity: "a".repeat(64),
        protocol_version: 1,
        mode: "enforce".into(),
        scope_contract: ScopeContractV3 {
            schema: "guard-native-scope.v1".into(),
            kind: "guard-home".into(),
            scope_digest: scope_digest(guard_home.to_string_lossy().as_ref()),
            workspace_binding: "request-source".into(),
        },
        effective_policy,
        issued_at_ms: now_ms().unwrap().saturating_sub(1),
        expires_at_ms: now_ms().unwrap() + 60_000,
        integrity: SnapshotIntegrityV3 {
            algorithm: POLICY_SNAPSHOT_INTEGRITY_ALGORITHM.into(),
            key_id: verifier_key_id(key),
            mac: String::new(),
        },
    };
    snapshot.policy_digest = policy_digest(&snapshot).unwrap();
    snapshot.integrity.mac = integrity_mac(&snapshot, key).unwrap();
    snapshot
}

fn test_root(label: &str) -> PathBuf {
    let root = std::env::temp_dir().join(format!(
        "hol-guard-policy-store-{label}-{}-{}",
        std::process::id(),
        now_ms().unwrap()
    ));
    fs::create_dir(&root).unwrap();
    #[cfg(unix)]
    fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
    #[cfg(windows)]
    crate::resident_state::protect_windows_private_path(&root, true).unwrap();
    root
}

fn install_test_key(root: &Path, value: u8) -> [u8; VERIFIER_KEY_BYTES] {
    let key = [value; VERIFIER_KEY_BYTES];
    let path = root.join(VERIFIER_KEY_FILE_NAME);
    fs::write(&path, key).unwrap();
    #[cfg(unix)]
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
    #[cfg(windows)]
    crate::resident_state::protect_windows_private_path(&path, false).unwrap();
    key
}

fn protect_test_file(path: &Path) {
    let _ = path;
    #[cfg(windows)]
    crate::resident_state::protect_windows_private_path(path, false).unwrap();
}

fn legacy_floor_value(generation: u64, policy_digest: &str, key: &[u8]) -> Value {
    serde_json::to_value(GenerationFloorV1 {
        schema: GENERATION_FLOOR_SCHEMA.to_owned(),
        generation,
        policy_digest: policy_digest.to_owned(),
        mac: generation_floor_mac(generation, policy_digest, key),
    })
    .unwrap()
}

#[test]
fn missing_snapshot_is_not_ready_but_push_can_install_it() {
    let root = test_root("missing-snapshot");
    let key = install_test_key(&root, 7);
    let store = PolicySnapshotStore::new(&root, &"a".repeat(64)).unwrap();
    let snapshot = signed_snapshot(1, &key, &root);
    let request = serde_json::json!({
        "schema": POLICY_SNAPSHOT_PUSH_SCHEMA,
        "snapshot": snapshot,
    });
    let ack: PolicySnapshotAckV1 = serde_json::from_slice(&store.push(&request).unwrap()).unwrap();
    assert_eq!(ack.generation, 1);
    assert!(!ack.idempotent);
    assert_eq!(store.current_generation(), Some(1));
    let duplicate: PolicySnapshotAckV1 =
        serde_json::from_slice(&store.push(&request).unwrap()).unwrap();
    assert!(duplicate.idempotent);
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn generation_rollback_and_same_generation_mutation_are_rejected() {
    let root = test_root("rollback");
    let key = install_test_key(&root, 8);
    let store = PolicySnapshotStore::new(&root, &"a".repeat(64)).unwrap();
    let first = signed_snapshot(3, &key, &root);
    let first_request = serde_json::json!({
        "schema": POLICY_SNAPSHOT_PUSH_SCHEMA,
        "snapshot": first,
    });
    store.push(&first_request).unwrap();
    let rollback = signed_snapshot(2, &key, &root);
    let rollback_request = serde_json::json!({
        "schema": POLICY_SNAPSHOT_PUSH_SCHEMA,
        "snapshot": rollback,
    });
    assert_eq!(
        store.push(&rollback_request).unwrap_err(),
        "snapshot_generation_downgrade"
    );
    let mut mutated = first_request["snapshot"].clone();
    mutated["mode"] = Value::String("observe".into());
    let mutated_request = serde_json::json!({
        "schema": POLICY_SNAPSHOT_PUSH_SCHEMA,
        "snapshot": mutated,
    });
    assert_eq!(
        store.push(&mutated_request).unwrap_err(),
        "snapshot_digest_mismatch"
    );
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn restart_rehydrates_snapshot_and_hook_validation_uses_memory() {
    let root = test_root("restart");
    let key = install_test_key(&root, 9);
    let store = PolicySnapshotStore::new(&root, &"a".repeat(64)).unwrap();
    let snapshot = signed_snapshot(4, &key, &root);
    let request = serde_json::json!({
        "schema": POLICY_SNAPSHOT_PUSH_SCHEMA,
        "snapshot": snapshot,
    });
    store.push(&request).unwrap();
    let restored = PolicySnapshotStore::new(&root, &"a".repeat(64)).unwrap();
    assert_eq!(restored.current_generation(), Some(4));
    let snapshot_value = request["snapshot"].clone();
    assert!(restored
        .validate_request_snapshot(&snapshot_value, root.to_string_lossy().as_ref(), 4,)
        .is_ok());
    fs::remove_file(root.join(SNAPSHOT_FILE_NAME)).unwrap();
    assert!(restored
        .validate_request_snapshot(&snapshot_value, root.to_string_lossy().as_ref(), 4,)
        .is_ok());
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn restarted_resident_applies_installed_policy_without_request_time_io() {
    let root = test_root("evaluate");
    let key = install_test_key(&root, 11);
    let store = PolicySnapshotStore::new(&root, &"a".repeat(64)).unwrap();
    let snapshot = signed_snapshot_with_policy(1, &key, &root, policy_with_default("block"));
    let snapshot_value = serde_json::to_value(&snapshot).unwrap();
    store
        .push(&serde_json::json!({
            "schema": POLICY_SNAPSHOT_PUSH_SCHEMA,
            "snapshot": snapshot_value,
        }))
        .unwrap();
    let restarted = PolicySnapshotStore::new(&root, &"a".repeat(64)).unwrap();
    let envelope = GuardHookEnvelopeV2 {
        schema: GUARD_HOOK_ENVELOPE_V2_SCHEMA.to_owned(),
        request_id: Some("resident-policy-test".into()),
        harness: "claude-code".into(),
        event: "PreToolUse".into(),
        raw_payload: serde_json::json!({
            "hook_event_name": "PreToolUse",
            "tool_name": "read_file",
            "tool_input": {"file_path": "README.md"}
        }),
        deadline_budget_ms: Some(750),
        policy_generation: 1,
        policy_snapshot: serde_json::to_value(&snapshot).unwrap(),
        source: GuardHookSourceMetadataV2 {
            cwd: Some("/workspace".into()),
            home_dir: "/home/test".into(),
            guard_home: root.to_string_lossy().into_owned(),
            source_ref_external_allowed: false,
        },
    };
    let result = crate::edge::evaluate_envelope_with_store(envelope, &restarted).unwrap();
    let result: GuardHookEdgeResultV2 = serde_json::from_slice(&result).unwrap();
    assert_eq!(result.result["minimum_action"], "block");
    assert_eq!(result.result["authority"], "rust");
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn authenticated_edge_preserves_clean_default_warning() {
    let root = test_root("warning-edge");
    let key = install_test_key(&root, 12);
    let store = PolicySnapshotStore::new(&root, &"a".repeat(64)).unwrap();
    let snapshot = signed_snapshot(1, &key, &root);
    store
        .push(&serde_json::json!({
            "schema": POLICY_SNAPSHOT_PUSH_SCHEMA,
            "snapshot": snapshot,
        }))
        .unwrap();
    let envelope = GuardHookEnvelopeV2 {
        schema: GUARD_HOOK_ENVELOPE_V2_SCHEMA.to_owned(),
        request_id: Some("warning-edge-test".into()),
        harness: "claude-code".into(),
        event: "PreToolUse".into(),
        raw_payload: serde_json::json!({
            "hook_event_name": "PreToolUse",
            "tool_input": {"command": "pwd"}
        }),
        deadline_budget_ms: Some(750),
        policy_generation: 1,
        policy_snapshot: serde_json::to_value(&snapshot).unwrap(),
        source: GuardHookSourceMetadataV2 {
            cwd: Some("/workspace".into()),
            home_dir: "/home/test".into(),
            guard_home: root.to_string_lossy().into_owned(),
            source_ref_external_allowed: false,
        },
    };
    let result = crate::edge::evaluate_envelope_with_store(envelope, &store).unwrap();
    let result: GuardHookEdgeResultV2 = serde_json::from_slice(&result).unwrap();
    assert_eq!(result.result["minimum_action"], "warn");
    assert_eq!(result.result["decision"], "allow");
    assert_eq!(result.result["authority"], "rust");
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn authenticated_observe_edge_preserves_intrinsic_pretool_floor() {
    let root = test_root("observe-edge");
    let key = install_test_key(&root, 15);
    let mut snapshot = signed_snapshot(1, &key, &root);
    snapshot.mode = "observe".into();
    snapshot.policy_digest = policy_digest(&snapshot).unwrap();
    snapshot.integrity.mac = integrity_mac(&snapshot, &key).unwrap();
    let store = PolicySnapshotStore::new(&root, &"a".repeat(64)).unwrap();
    store
        .push(&serde_json::json!({
            "schema": POLICY_SNAPSHOT_PUSH_SCHEMA,
            "snapshot": snapshot,
        }))
        .unwrap();
    let envelope = GuardHookEnvelopeV2 {
        schema: GUARD_HOOK_ENVELOPE_V2_SCHEMA.to_owned(),
        request_id: Some("observe-edge-test".into()),
        harness: "claude-code".into(),
        event: "PreToolUse".into(),
        raw_payload: serde_json::json!({
            "hook_event_name": "PreToolUse",
            "tool_name": "Bash",
            "tool_input": {"command": "rm -rf /"}
        }),
        deadline_budget_ms: Some(750),
        policy_generation: 1,
        policy_snapshot: serde_json::to_value(&snapshot).unwrap(),
        source: GuardHookSourceMetadataV2 {
            cwd: Some("/workspace".into()),
            home_dir: "/home/test".into(),
            guard_home: root.to_string_lossy().into_owned(),
            source_ref_external_allowed: false,
        },
    };
    let result = crate::edge::evaluate_envelope_with_store(envelope, &store).unwrap();
    let result: GuardHookEdgeResultV2 = serde_json::from_slice(&result).unwrap();
    assert_eq!(result.result["minimum_action"], "block");
    assert_eq!(result.result["decision"], "deny");
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn push_rejects_unknown_fields_without_mutating_state() {
    let root = test_root("unknown");
    let key = install_test_key(&root, 10);
    let store = PolicySnapshotStore::new(&root, &"a".repeat(64)).unwrap();
    let snapshot = signed_snapshot(1, &key, &root);
    let request = serde_json::json!({
        "schema": POLICY_SNAPSHOT_PUSH_SCHEMA,
        "snapshot": snapshot,
        "unexpected": true,
    });
    assert_eq!(
        store.push(&request).unwrap_err(),
        "native_policy_snapshot_push_invalid"
    );
    assert_eq!(store.current_generation(), None);
    assert!(!root.join(SNAPSHOT_FILE_NAME).exists());
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn legacy_snapshot_and_floor_migrate_to_one_authority_record() {
    let root = test_root("legacy-migration");
    let key = install_test_key(&root, 13);
    let snapshot = signed_snapshot(7, &key, &root);
    let snapshot_value = serde_json::to_value(&snapshot).unwrap();
    fs::write(
        root.join(SNAPSHOT_FILE_NAME),
        canonical_json_bytes(&snapshot_value).unwrap(),
    )
    .unwrap();
    protect_test_file(&root.join(SNAPSHOT_FILE_NAME));
    #[cfg(unix)]
    fs::set_permissions(
        root.join(SNAPSHOT_FILE_NAME),
        fs::Permissions::from_mode(0o600),
    )
    .unwrap();
    let floor_value = legacy_floor_value(7, &snapshot.policy_digest, &key);
    fs::write(
        root.join(GENERATION_FLOOR_FILE_NAME),
        canonical_json_bytes(&floor_value).unwrap(),
    )
    .unwrap();
    protect_test_file(&root.join(GENERATION_FLOOR_FILE_NAME));
    #[cfg(unix)]
    fs::set_permissions(
        root.join(GENERATION_FLOOR_FILE_NAME),
        fs::Permissions::from_mode(0o600),
    )
    .unwrap();

    PolicySnapshotStore::migrate_legacy_state(&root, &"a".repeat(64)).unwrap();
    let store = PolicySnapshotStore::new(&root, &"a".repeat(64)).unwrap();
    assert_eq!(store.current_generation(), Some(7));
    let (authority, _) = read_private_json(
        &root.join(SNAPSHOT_FILE_NAME),
        AUTHORITY_RECORD_MAX_BYTES,
        "state",
    )
    .unwrap()
    .unwrap();
    assert_eq!(authority["schema"], AUTHORITY_RECORD_SCHEMA);
    assert_eq!(authority["generation_floor"], 7);
    assert!(authority["snapshot"].is_object());
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn floor_only_migration_preserves_generation_and_allows_only_newer_push() {
    let root = test_root("floor-only-migration");
    let key = install_test_key(&root, 14);
    let digest = "b".repeat(64);
    let floor_value = legacy_floor_value(9, &digest, &key);
    fs::write(
        root.join(GENERATION_FLOOR_FILE_NAME),
        canonical_json_bytes(&floor_value).unwrap(),
    )
    .unwrap();
    protect_test_file(&root.join(GENERATION_FLOOR_FILE_NAME));
    #[cfg(unix)]
    fs::set_permissions(
        root.join(GENERATION_FLOOR_FILE_NAME),
        fs::Permissions::from_mode(0o600),
    )
    .unwrap();
    PolicySnapshotStore::migrate_legacy_state(&root, &"a".repeat(64)).unwrap();
    let store = PolicySnapshotStore::new(&root, &"a".repeat(64)).unwrap();
    assert_eq!(store.current_generation(), None);
    let older_snapshot = signed_snapshot(8, &key, &root);
    let older_request = serde_json::json!({
        "schema": POLICY_SNAPSHOT_PUSH_SCHEMA,
        "snapshot": older_snapshot,
    });
    let older_ack: PolicySnapshotAckV1 =
        serde_json::from_slice(&store.push(&older_request).unwrap()).unwrap();
    assert_eq!(
        older_ack.status,
        guard_policy_snapshot::POLICY_SNAPSHOT_ACK_REQUIRES_NEW_GENERATION
    );
    assert_eq!(older_ack.generation, 9);
    assert_eq!(older_ack.policy_digest, digest);
    assert!(!older_ack.idempotent);
    let equal_snapshot = signed_snapshot(9, &key, &root);
    let equal_request = serde_json::json!({
        "schema": POLICY_SNAPSHOT_PUSH_SCHEMA,
        "snapshot": equal_snapshot,
    });
    let equal_ack: PolicySnapshotAckV1 = serde_json::from_slice(
        &crate::evaluate_resident_bytes(
            &canonical_json_bytes(&serde_json::json!({
                "operation": "policy_snapshot_push",
                "request": equal_request,
            }))
            .unwrap(),
            Some(&store),
        )
        .unwrap(),
    )
    .unwrap();
    assert_eq!(
        equal_ack.status,
        guard_policy_snapshot::POLICY_SNAPSHOT_ACK_REQUIRES_NEW_GENERATION
    );
    assert_eq!(equal_ack.generation, 9);
    assert_eq!(equal_ack.policy_digest, digest);
    assert!(!equal_ack.idempotent);
    let snapshot = signed_snapshot(10, &key, &root);
    let request = serde_json::json!({
        "schema": POLICY_SNAPSHOT_PUSH_SCHEMA,
        "snapshot": snapshot,
    });
    let ack: PolicySnapshotAckV1 = serde_json::from_slice(&store.push(&request).unwrap()).unwrap();
    assert_eq!(ack.generation, 10);
    fs::remove_dir_all(root).unwrap();
}

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

use super::{
    authority_fingerprint, now_ms, read_private_json, scope_digest, GenerationFloorV1,
    PersistBoundary, PolicySnapshotStore, AUTHORITY_RECORD_MAX_BYTES, AUTHORITY_RECORD_SCHEMA,
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
use std::io::{Read, Seek, SeekFrom, Write};
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

#[cfg(windows)]
use super::normalize_scope_text;

#[path = "policy_store_fault_tests.rs"]
mod fault_tests;
#[path = "policy_store_migration_tests.rs"]
mod migration_tests;

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

fn fixture_directory(path: &Path) {
    #[cfg(windows)]
    {
        crate::resident_state::ensure_private_directory(path, true).unwrap();
    }
    #[cfg(not(windows))]
    fs::create_dir(path).unwrap();
}

fn fixture_file(path: &Path, bytes: &[u8]) {
    #[cfg(windows)]
    {
        use std::io::Write;
        let private_root = path.parent().unwrap_or(path);
        let mut file = crate::resident_state::private_file(path, true, private_root).unwrap();
        file.write_all(bytes).unwrap();
    }
    #[cfg(not(windows))]
    fs::write(path, bytes).unwrap();
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
    fixture_directory(&root);
    #[cfg(unix)]
    fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
    root
}

fn install_test_key(root: &Path, value: u8) -> [u8; VERIFIER_KEY_BYTES] {
    let key = [value; VERIFIER_KEY_BYTES];
    let path = root.join(VERIFIER_KEY_FILE_NAME);
    fixture_file(&path, &key);
    #[cfg(unix)]
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
    key
}

#[cfg(windows)]
#[test]
fn windows_scope_aliases_share_one_digest_identity() {
    let normal = normalize_scope_text(r"C:\Users\Guard\State");
    assert_eq!(normal, r"c:\users\guard\state");
    assert_eq!(normalize_scope_text(r"\\?\C:\Users\Guard\State"), normal);
    assert_eq!(
        normalize_scope_text(r"\\?\UNC\Server\Share\State\\"),
        normalize_scope_text(r"\\server\share\state")
    );
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
    let compact_reference = serde_json::json!({
        "generation": snapshot.generation,
        "policy_digest": snapshot.policy_digest.clone(),
        "runtime_identity": snapshot.runtime_identity.clone(),
    });
    assert!(restored
        .validate_request_snapshot(&compact_reference, root.to_string_lossy().as_ref(), 4,)
        .is_ok());
    fs::remove_file(root.join(SNAPSHOT_FILE_NAME)).unwrap();
    assert_eq!(
        restored
            .validate_request_snapshot(&snapshot_value, root.to_string_lossy().as_ref(), 4,)
            .unwrap_err(),
        "native_policy_snapshot_context_mismatch"
    );
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
fn authority_fingerprint_detects_same_size_in_place_rewrite() {
    let root = test_root("authority-fingerprint");
    let key = install_test_key(&root, 19);
    let store = PolicySnapshotStore::new(&root, &"a".repeat(64)).unwrap();
    let snapshot = signed_snapshot(1, &key, &root);
    store
        .push(&serde_json::json!({
            "schema": POLICY_SNAPSHOT_PUSH_SCHEMA,
            "snapshot": snapshot,
        }))
        .unwrap();

    let path = root.join(SNAPSHOT_FILE_NAME);
    let before = authority_fingerprint(&path).unwrap();
    let mut bytes = Vec::new();
    fs::File::open(&path)
        .unwrap()
        .read_to_end(&mut bytes)
        .unwrap();
    let offset = bytes
        .iter()
        .position(|byte| *byte == b'1')
        .expect("authority record contains a generation digit");
    let replacement = if bytes[offset] == b'1' { b'2' } else { b'1' };
    let mut file = fs::OpenOptions::new().write(true).open(&path).unwrap();
    file.seek(SeekFrom::Start(offset as u64)).unwrap();
    file.write_all(&[replacement]).unwrap();
    file.sync_all().unwrap();

    let after = authority_fingerprint(&path).unwrap();
    assert_ne!(before, after);
    assert!(!store.test_authorities_unchanged());
    fs::remove_dir_all(root).unwrap();
}

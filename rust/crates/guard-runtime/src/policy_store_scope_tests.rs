use super::PolicySnapshotStore;
use guard_policy_snapshot::{
    canonical_json_bytes, config_digest, integrity_mac, policy_digest, verifier_key_id,
    EffectiveNativePolicyV3, PolicySnapshotAckV1, PolicySnapshotV3, ScopeContractV3,
    SnapshotIntegrityV3, POLICY_SNAPSHOT_INTEGRITY_ALGORITHM, POLICY_SNAPSHOT_PUSH_SCHEMA,
    POLICY_SNAPSHOT_SCHEMA,
};
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

static NEXT_ROOT: AtomicU64 = AtomicU64::new(0);

fn root() -> PathBuf {
    let path = std::env::temp_dir().join(format!(
        "hol-guard-policy-scope-race-{}-{}",
        std::process::id(),
        NEXT_ROOT.fetch_add(1, Ordering::Relaxed)
    ));
    fs::create_dir(&path).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
    }
    path
}

fn install_key(path: &Path) -> [u8; 32] {
    let key = [23u8; 32];
    fs::write(path.join("policy-verifier.key"), key).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(
            path.join("policy-verifier.key"),
            fs::Permissions::from_mode(0o600),
        )
        .unwrap();
    }
    key
}

fn snapshot(generation: u64, key: &[u8], scope_digest: String) -> PolicySnapshotV3 {
    let policy = EffectiveNativePolicyV3 {
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
    };
    let now = super::now_ms().unwrap();
    let mut value = PolicySnapshotV3 {
        schema: POLICY_SNAPSHOT_SCHEMA.into(),
        version: 3,
        generation,
        policy_digest: String::new(),
        config_digest: config_digest(&policy).unwrap(),
        rule_digest: guard_rule_contract::rule_digest(),
        runtime_identity: "a".repeat(64),
        protocol_version: 1,
        mode: "enforce".into(),
        scope_contract: ScopeContractV3 {
            schema: "guard-native-scope.v1".into(),
            kind: "guard-home".into(),
            scope_digest,
            workspace_binding: "request-source".into(),
        },
        effective_policy: policy,
        command_extensions: None,
        issued_at_ms: now.saturating_sub(1),
        expires_at_ms: now + 60_000,
        integrity: SnapshotIntegrityV3 {
            algorithm: POLICY_SNAPSHOT_INTEGRITY_ALGORITHM.into(),
            key_id: verifier_key_id(key),
            mac: String::new(),
        },
    };
    value.policy_digest = policy_digest(&value).unwrap();
    value.integrity.mac = integrity_mac(&value, key).unwrap();
    value
}

fn resident_push(store: &PolicySnapshotStore, value: PolicySnapshotV3) -> Result<Vec<u8>, String> {
    let request = serde_json::json!({
        "operation": "policy_snapshot_push",
        "request": {
            "schema": POLICY_SNAPSHOT_PUSH_SCHEMA,
            "snapshot": value,
        },
    });
    let bytes = canonical_json_bytes(&request).unwrap();
    crate::resident_protocol::evaluate_resident_bytes(&bytes, Some(store))
}

#[test]
fn resident_rejects_signed_scope_change_without_replacing_current_snapshot() {
    let root = root();
    let key = install_key(&root);
    let store = PolicySnapshotStore::new(&root, &"a".repeat(64)).unwrap();
    let (_, expected_scope) = super::policy_store_authority::scope_binding_for_state_base(&root);
    resident_push(&store, snapshot(1, &key, expected_scope.clone())).unwrap();

    let changed = snapshot(
        2,
        &key,
        super::policy_store_authority::scope_digest_string("/different-guard-home"),
    );
    assert_eq!(
        resident_push(&store, changed).unwrap_err(),
        "native_policy_snapshot_scope_mismatch"
    );
    assert_eq!(store.current_generation(), Some(1));
    assert_eq!(
        store
            .current_snapshot()
            .unwrap()
            .scope_contract
            .scope_digest,
        expected_scope
    );
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn resident_accepts_signed_same_scope_generation_advance() {
    let root = root();
    let key = install_key(&root);
    let store = PolicySnapshotStore::new(&root, &"a".repeat(64)).unwrap();
    let (_, expected_scope) = super::policy_store_authority::scope_binding_for_state_base(&root);
    let first = resident_push(&store, snapshot(1, &key, expected_scope.clone())).unwrap();
    let first_ack: PolicySnapshotAckV1 = serde_json::from_slice(&first).unwrap();
    assert_eq!(first_ack.generation, 1);

    let second = resident_push(&store, snapshot(2, &key, expected_scope)).unwrap();
    let second_ack: PolicySnapshotAckV1 = serde_json::from_slice(&second).unwrap();
    assert_eq!(second_ack.generation, 2);
    assert!(!second_ack.idempotent);
    assert_eq!(store.current_generation(), Some(2));
    fs::remove_dir_all(root).unwrap();
}

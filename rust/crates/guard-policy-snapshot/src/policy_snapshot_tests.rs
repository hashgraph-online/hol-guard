use super::*;

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

fn snapshot(generation: u64, key: &[u8]) -> PolicySnapshotV3 {
    let effective_policy = policy();
    let mut result = PolicySnapshotV3 {
        schema: POLICY_SNAPSHOT_SCHEMA.into(),
        version: 3,
        generation,
        policy_digest: String::new(),
        config_digest: config_digest(&effective_policy).unwrap(),
        rule_digest: "b".repeat(64),
        runtime_identity: "a".repeat(64),
        protocol_version: 1,
        mode: "enforce".into(),
        scope_contract: ScopeContractV3 {
            schema: "guard-native-scope.v1".into(),
            kind: "guard-home".into(),
            scope_digest: "c".repeat(64),
            workspace_binding: "request-source".into(),
        },
        effective_policy,
        issued_at_ms: 100,
        expires_at_ms: 1_000,
        integrity: SnapshotIntegrityV3 {
            algorithm: POLICY_SNAPSHOT_INTEGRITY_ALGORITHM.into(),
            key_id: verifier_key_id(key),
            mac: String::new(),
        },
    };
    result.policy_digest = policy_digest(&result).unwrap();
    result.integrity.mac = integrity_mac(&result, key).unwrap();
    result
}

#[test]
fn validates_authenticated_v3_snapshot() {
    let key = [7u8; 32];
    let snapshot = snapshot(1, &key);
    assert!(validate_v3(&snapshot, 1, &"a".repeat(64), &"b".repeat(64), &key, 200).is_ok());
}

#[test]
fn rejects_mutated_effective_policy_and_mac() {
    let key = [7u8; 32];
    let mut snapshot = snapshot(1, &key);
    snapshot.effective_policy.default_action = "block".into();
    assert_eq!(
        validate_v3(&snapshot, 1, &"a".repeat(64), &"b".repeat(64), &key, 200),
        Err(SnapshotError::DigestMismatch)
    );
}

#[test]
fn rejects_expired_and_replayed_generation() {
    let key = [7u8; 32];
    let snapshot = snapshot(1, &key);
    assert_eq!(
        validate_v3(&snapshot, 1, &"a".repeat(64), &"b".repeat(64), &key, 1_000),
        Err(SnapshotError::Expired)
    );
    assert_eq!(
        validate_v3(&snapshot, 2, &"a".repeat(64), &"b".repeat(64), &key, 200),
        Err(SnapshotError::Downgrade)
    );
}

#[test]
fn rejects_runtime_rule_and_protocol_mismatch() {
    let key = [7u8; 32];
    let snapshot = snapshot(1, &key);
    assert_eq!(
        validate_v3(&snapshot, 1, &"c".repeat(64), &"b".repeat(64), &key, 200),
        Err(SnapshotError::RuntimeIdentity)
    );
    assert_eq!(
        validate_v3(&snapshot, 1, &"a".repeat(64), &"c".repeat(64), &key, 200),
        Err(SnapshotError::RuleDigest)
    );
    let mut incompatible = snapshot;
    incompatible.protocol_version = 2;
    assert_eq!(
        validate_v3(
            &incompatible,
            1,
            &"a".repeat(64),
            &"b".repeat(64),
            &key,
            200,
        ),
        Err(SnapshotError::Protocol)
    );
}

#[test]
fn rejects_unknown_risk_selector_and_conflicting_harness_aliases() {
    let key = [7u8; 32];
    let mut unknown = snapshot(1, &key);
    unknown
        .effective_policy
        .risk_actions
        .insert("future-risk".into(), "allow".into());
    assert_eq!(
        validate_v3(&unknown, 1, &"a".repeat(64), &"b".repeat(64), &key, 200),
        Err(SnapshotError::Policy)
    );

    let mut conflicting = snapshot(1, &key);
    conflicting
        .effective_policy
        .harness_actions
        .insert("claude".into(), "allow".into());
    conflicting
        .effective_policy
        .harness_actions
        .insert("claude-code".into(), "block".into());
    conflicting.policy_digest = policy_digest(&conflicting).unwrap();
    conflicting.integrity.mac = integrity_mac(&conflicting, &key).unwrap();
    assert_eq!(
        validate_v3(&conflicting, 1, &"a".repeat(64), &"b".repeat(64), &key, 200,),
        Err(SnapshotError::Policy)
    );
}

#[test]
fn canonical_json_sorts_object_keys() {
    let value = serde_json::json!({"z": 1, "a": {"b": true, "a": null}});
    assert_eq!(
        String::from_utf8(canonical_json_bytes(&value).unwrap()).unwrap(),
        r#"{"a":{"a":null,"b":true},"z":1}"#
    );
}

use super::*;
use serde_json::Value;

fn fixture() -> (PolicySnapshotV4, Vec<u8>) {
    let value: Value = serde_json::from_str(include_str!(
        "../../../../contracts/native-policy-snapshot/v4/policy-snapshot-vector.json"
    ))
    .unwrap();
    (
        serde_json::from_value(value["snapshot"].clone()).unwrap(),
        hex::decode(value["verifierKeyHex"].as_str().unwrap()).unwrap(),
    )
}

fn check(snapshot: &PolicySnapshotV4, key: &[u8]) -> Result<(), SnapshotError> {
    validate_v4(snapshot, 7, &"a".repeat(64), &"b".repeat(64), key, 1500)
}

#[test]
fn authenticates_actual_python_v4_bytes() {
    let (snapshot, key) = fixture();
    assert_eq!(check(&snapshot, &key), Ok(()));
    let value: Value = serde_json::from_str(include_str!(
        "../../../../contracts/native-policy-snapshot/v4/policy-snapshot-vector.json"
    ))
    .unwrap();
    assert_eq!(
        digest_bytes(&snapshot_signing_bytes_v4(&snapshot).unwrap()),
        value["signingBytesSha256"].as_str().unwrap()
    );
    assert_eq!(policy_digest_v4(&snapshot).unwrap(), snapshot.policy_digest);
    assert_eq!(
        integrity_mac_v4(&snapshot, &key).unwrap(),
        snapshot.integrity.mac
    );
}

#[test]
fn binds_source_identity_even_when_effective_rules_are_unchanged() {
    let (mut snapshot, key) = fixture();
    snapshot.source_input_digest = "e".repeat(64);
    assert_eq!(check(&snapshot, &key), Err(SnapshotError::DigestMismatch));
    snapshot.policy_digest = policy_digest_v4(&snapshot).unwrap();
    assert_eq!(
        check(&snapshot, &key),
        Err(SnapshotError::IntegrityMismatch)
    );
}

#[test]
fn binds_scoped_authority_into_digest_and_mac() {
    let (mut snapshot, key) = fixture();
    let mut authority = serde_json::to_value(&snapshot.scoped_authority).unwrap();
    authority["rows"][0]["action"] = Value::String("allow".into());
    snapshot.scoped_authority = serde_json::from_value(authority).unwrap();
    assert_eq!(check(&snapshot, &key), Err(SnapshotError::DigestMismatch));
    snapshot.policy_digest = policy_digest_v4(&snapshot).unwrap();
    assert_eq!(
        check(&snapshot, &key),
        Err(SnapshotError::IntegrityMismatch)
    );
}

#[test]
fn rejects_old_protocol_and_unknown_or_missing_authority_fields() {
    let (snapshot, _) = fixture();
    let value = serde_json::to_value(&snapshot).unwrap();
    assert!(serde_json::from_value::<PolicySnapshotV3>(value.clone()).is_err());
    for field in ["scoped_authority", "source_input_digest"] {
        let mut missing = value.clone();
        missing.as_object_mut().unwrap().remove(field);
        assert!(serde_json::from_value::<PolicySnapshotV4>(missing).is_err());
    }
    let mut unknown = value;
    unknown["extra"] = Value::Bool(true);
    assert!(serde_json::from_value::<PolicySnapshotV4>(unknown).is_err());
}

#[test]
fn preserves_replay_expiry_and_runtime_fences() {
    let (snapshot, key) = fixture();
    assert_eq!(
        validate_v4(&snapshot, 8, &"a".repeat(64), &"b".repeat(64), &key, 1500),
        Err(SnapshotError::Downgrade)
    );
    assert_eq!(
        validate_v4(&snapshot, 7, &"e".repeat(64), &"b".repeat(64), &key, 1500),
        Err(SnapshotError::RuntimeIdentity)
    );
    assert_eq!(
        validate_v4(&snapshot, 7, &"a".repeat(64), &"e".repeat(64), &key, 1500),
        Err(SnapshotError::RuleDigest)
    );
    assert_eq!(
        validate_v4(&snapshot, 7, &"a".repeat(64), &"b".repeat(64), &key, 2000),
        Err(SnapshotError::Expired)
    );
    assert_eq!(check(&snapshot, &[0; 32]), Err(SnapshotError::Integrity));
}

#[test]
fn rejects_cross_version_mac_replay() {
    let (mut snapshot, key) = fixture();
    let bytes = snapshot_signing_bytes_v4(&snapshot).unwrap();
    snapshot.integrity.mac = hex::encode(crypto::hmac_sha256(
        &key,
        POLICY_SNAPSHOT_INTEGRITY_DOMAIN,
        &bytes,
    ));
    assert_eq!(
        check(&snapshot, &key),
        Err(SnapshotError::IntegrityMismatch)
    );
}

#[test]
fn authenticated_snapshot_keeps_present_null_distinct_from_omission() {
    let (original, key) = fixture();
    let mut value = serde_json::to_value(&original).unwrap();
    value["scoped_authority"]["rows"][0]["scope"] = Value::String("harness".into());
    let fields = [
        "artifact_id",
        "artifact_hash",
        "workspace",
        "publisher",
        "expires_at_ms",
        "exact_command_sha256",
    ];
    for field in fields {
        value["scoped_authority"]["rows"][0][field] = Value::Null;
    }
    value["scoped_authority"]["managed"] = Value::Null;
    let mut snapshot: PolicySnapshotV4 = serde_json::from_value(value).unwrap();
    snapshot.policy_digest = policy_digest_v4(&snapshot).unwrap();
    snapshot.integrity.mac = integrity_mac_v4(&snapshot, &key).unwrap();
    assert_eq!(check(&snapshot, &key), Ok(()));
    let encoded = snapshot_bytes_v4(&snapshot).unwrap();
    let roundtrip: PolicySnapshotV4 = serde_json::from_slice(&encoded).unwrap();
    assert_eq!(snapshot_bytes_v4(&roundtrip).unwrap(), encoded);
    for field in fields {
        let mut missing = serde_json::to_value(&snapshot).unwrap();
        missing["scoped_authority"]["rows"][0]
            .as_object_mut()
            .unwrap()
            .remove(field);
        assert!(
            serde_json::from_value::<PolicySnapshotV4>(missing).is_err(),
            "missing {field}"
        );
    }
    let mut missing = serde_json::to_value(&snapshot).unwrap();
    missing["scoped_authority"]
        .as_object_mut()
        .unwrap()
        .remove("managed");
    assert!(serde_json::from_value::<PolicySnapshotV4>(missing).is_err());
}

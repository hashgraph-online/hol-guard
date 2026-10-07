use super::*;
use business_policy::{BusinessPolicyBindingV1, BUSINESS_POLICY_BINDING_SCHEMA};
use serde_json::{json, Value};

fn binding_value() -> Value {
    json!({"schema": BUSINESS_POLICY_BINDING_SCHEMA, "version": 1,
        "defaultAction": "allow", "rules": [{"id": "mail.external", "action": "block",
        "match": {"schema": "guard.business-policy-match.v1", "version": 1,
            "services": ["google_gmail"], "operations": ["mail_send"]}}]})
}

fn binding() -> BusinessPolicyBindingV1 {
    serde_json::from_value(binding_value()).unwrap()
}

#[test]
fn complete_source_digest_changes_signed_identity_and_cannot_be_null_or_malformed() {
    let original = signed_business_snapshot();
    let mut sourced = original.clone();
    sourced
        .business_policy
        .as_mut()
        .unwrap()
        .source_document_digest = Some("a".repeat(64));
    assert_ne!(policy_digest(&sourced).unwrap(), original.policy_digest);
    assert_ne!(
        integrity_mac(&sourced, &[7; 32]).unwrap(),
        integrity_mac(&original, &[7; 32]).unwrap()
    );
    for value in [
        Value::Null,
        json!(""),
        json!("A".repeat(64)),
        json!("a".repeat(63)),
    ] {
        let mut payload = binding_value();
        payload["sourceDocumentDigest"] = value;
        assert!(serde_json::from_value::<BusinessPolicyBindingV1>(payload)
            .map(|binding| binding.validate().is_err())
            .unwrap_or(true));
    }
}

#[test]
fn expiry_is_signed_and_malformed_or_null_expiry_cannot_be_permanent() {
    let permanent = binding_value();
    assert_eq!(serde_json::to_value(binding()).unwrap(), permanent);
    let mut value = permanent.clone();
    value["rules"][0]["expiresAt"] = json!("2026-07-16T12:00:00.000000001Z");
    let until: BusinessPolicyBindingV1 = serde_json::from_value(value.clone()).unwrap();
    assert!(until.validate().is_ok());
    let old = signed_business_snapshot();
    let mut bounded = old.clone();
    bounded.business_policy = Some(until);
    assert_ne!(policy_digest(&bounded).unwrap(), old.policy_digest);
    assert_ne!(
        integrity_mac(&bounded, &[7; 32]).unwrap(),
        old.integrity.mac
    );
    for expiry in [json!(null), json!(17), json!({"mode":"permanent"})] {
        value["rules"][0]["expiresAt"] = expiry;
        assert!(serde_json::from_value::<BusinessPolicyBindingV1>(value.clone()).is_err());
    }
    for expiry in [
        "2026-02-29T00:00:00Z",
        "2026-01-01T00:00:00+00:00",
        "2026-01-01T00:00:00.1234567890Z",
    ] {
        value["rules"][0]["expiresAt"] = json!(expiry);
        let invalid: BusinessPolicyBindingV1 = serde_json::from_value(value.clone()).unwrap();
        assert!(invalid.validate().is_err());
    }
}

fn signed_business_snapshot() -> PolicySnapshotV3 {
    let mut value = tests::snapshot(1, &[7; 32]);
    value.business_policy = Some(binding());
    value.policy_digest = policy_digest(&value).unwrap();
    value.integrity.mac = integrity_mac(&value, &[7; 32]).unwrap();
    value
}

#[test]
fn business_binding_is_signed_and_changes_semantic_policy_identity() {
    let legacy = tests::snapshot(1, &[7; 32]);
    let business = signed_business_snapshot();
    assert_ne!(business.policy_digest, legacy.policy_digest);
    assert_ne!(business.integrity.mac, legacy.integrity.mac);
    assert!(validate_v3(
        &business,
        1,
        &"a".repeat(64),
        &"b".repeat(64),
        &[7; 32],
        200
    )
    .is_ok());
    for (field, patch) in [("defaultAction", json!("review")), ("rules", json!([]))] {
        let mut tampered = serde_json::to_value(&business).unwrap();
        tampered["business_policy"][field] = patch;
        let mut tampered: PolicySnapshotV3 = serde_json::from_value(tampered).unwrap();
        assert_eq!(
            validate_v3(
                &tampered,
                1,
                &"a".repeat(64),
                &"b".repeat(64),
                &[7; 32],
                200
            ),
            Err(SnapshotError::DigestMismatch)
        );
        tampered.policy_digest = policy_digest(&tampered).unwrap();
        assert_eq!(
            validate_v3(
                &tampered,
                1,
                &"a".repeat(64),
                &"b".repeat(64),
                &[7; 32],
                200
            ),
            Err(SnapshotError::IntegrityMismatch)
        );
    }
}

#[test]
fn explicit_null_unknown_and_duplicate_binding_fields_never_remove_rules() {
    let mut value = serde_json::to_value(tests::snapshot(1, &[7; 32])).unwrap();
    value["business_policy"] = Value::Null;
    assert!(serde_json::from_value::<PolicySnapshotV3>(value).is_err());
    for (field, patch) in [
        ("ignored", json!(true)),
        ("defaultAction", Value::Null),
        ("rules", Value::Null),
    ] {
        let mut value = binding_value();
        value[field] = patch;
        assert!(serde_json::from_value::<BusinessPolicyBindingV1>(value).is_err());
    }
    let duplicate = format!("{{\"schema\":\"{BUSINESS_POLICY_BINDING_SCHEMA}\",\"version\":1,\"defaultAction\":\"allow\",\"defaultAction\":\"block\",\"rules\":[]}}");
    assert!(serde_json::from_str::<BusinessPolicyBindingV1>(&duplicate).is_err());
    let mut value = binding_value();
    value["rules"][0]["ignored"] = json!(true);
    assert!(serde_json::from_value::<BusinessPolicyBindingV1>(value).is_err());
}

#[test]
fn malformed_versions_actions_ids_selectors_and_rule_limits_are_rejected() {
    for (field, patch) in [
        ("schema", json!("guard.native-business-policy.v2")),
        ("version", json!(2)),
        ("defaultAction", json!("ask")),
    ] {
        let mut value = binding_value();
        value[field] = patch;
        assert_eq!(
            serde_json::from_value::<BusinessPolicyBindingV1>(value)
                .unwrap()
                .validate(),
            Err(SnapshotError::Policy)
        );
    }
    for (field, patch) in [
        ("id", json!("raw@example.test")),
        ("action", json!("ask")),
        (
            "match",
            json!({"schema":"guard.business-policy-match.v1","version":1,"services":[],"operations":[]}),
        ),
    ] {
        let mut value = binding_value();
        value["rules"][0][field] = patch;
        assert_eq!(
            serde_json::from_value::<BusinessPolicyBindingV1>(value)
                .unwrap()
                .validate(),
            Err(SnapshotError::Policy)
        );
    }
    let mut duplicate = binding();
    duplicate.rules.push(duplicate.rules[0].clone());
    assert_eq!(duplicate.validate(), Err(SnapshotError::Policy));
    let mut excessive = binding();
    excessive.rules = (0..=POLICY_SNAPSHOT_MAX_MAP_ENTRIES)
        .map(|n| {
            let mut rule = binding().rules.remove(0);
            rule.id = format!("rule.{n}");
            rule
        })
        .collect();
    assert_eq!(excessive.validate(), Err(SnapshotError::Policy));
}

#[test]
fn absent_binding_preserves_snapshot_wire_shape_and_fingerprint() {
    let baseline = tests::snapshot(1, &[7; 32]);
    let bytes = snapshot_bytes(&baseline).unwrap();
    let expected = json!({
        "schema": baseline.schema, "version": baseline.version,
        "generation": baseline.generation, "policy_digest": baseline.policy_digest,
        "config_digest": baseline.config_digest, "rule_digest": baseline.rule_digest,
        "runtime_identity": baseline.runtime_identity, "protocol_version": baseline.protocol_version,
        "mode": baseline.mode, "scope_contract": baseline.scope_contract,
        "effective_policy": baseline.effective_policy, "issued_at_ms": baseline.issued_at_ms,
        "expires_at_ms": baseline.expires_at_ms, "integrity": baseline.integrity,
    });
    assert_eq!(canonical_json_bytes(&expected).unwrap(), bytes);
    let restored: PolicySnapshotV3 = serde_json::from_slice(&bytes).unwrap();
    assert!(restored.business_policy.is_none());
    assert_eq!(restored.policy_digest, baseline.policy_digest);
    assert_eq!(restored.integrity.mac, baseline.integrity.mac);
    let present: Value =
        serde_json::from_slice(&snapshot_bytes(&signed_business_snapshot()).unwrap()).unwrap();
    assert!(present["business_policy"].is_object());
}

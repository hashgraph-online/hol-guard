use super::*;
use guard_policy_snapshot::validate_v3;
use serde_json::{json, Value};

fn signed() -> PolicySnapshotV3 {
    let request = super::super::tests::request();
    let bytes =
        super::super::build_from_reader(serde_json::to_vec(&request).unwrap().as_slice()).unwrap();
    serde_json::from_slice(&bytes).unwrap()
}

fn inspect(snapshot: &PolicySnapshotV3) -> Value {
    serde_json::from_slice(
        &inspect_from_reader(snapshot_bytes(snapshot).unwrap().as_slice()).unwrap(),
    )
    .unwrap()
}

#[test]
fn inspection_returns_only_bound_digests_and_explicit_unverified_states() {
    let snapshot = signed();
    let result = inspect(&snapshot);
    assert_eq!(result.as_object().unwrap().len(), 8);
    assert_eq!(result["authenticity"], "not_checked");
    assert_eq!(result["currentness"], "not_checked");
    assert_eq!(result["business_policy_present"], true);
    assert_eq!(result["policy_digest"], snapshot.policy_digest);
    assert_eq!(result["config_digest"], snapshot.config_digest);
    assert_eq!(
        result["snapshot_digest"],
        digest_bytes(&snapshot_bytes(&snapshot).unwrap())
    );
    assert!(result.get("rules").is_none());
    assert!(result.get("integrity").is_none());
}

#[test]
fn content_success_cannot_authenticate_forged_mac_or_expired_snapshot() {
    let mut snapshot = signed();
    snapshot.integrity.mac = "0".repeat(64);
    assert_eq!(inspect(&snapshot)["authenticity"], "not_checked");
    assert!(validate_v3(
        &snapshot,
        4,
        &"a".repeat(64),
        &"b".repeat(64),
        &[7; 32],
        200
    )
    .is_err());
    let snapshot = signed();
    assert_eq!(inspect(&snapshot)["currentness"], "not_checked");
    assert!(validate_v3(
        &snapshot,
        4,
        &"a".repeat(64),
        &"b".repeat(64),
        &[7; 32],
        2000
    )
    .is_err());
}

#[test]
fn tampered_claimed_digest_is_not_used_as_computed_identity() {
    let mut snapshot = signed();
    let expected = snapshot.policy_digest.clone();
    snapshot.policy_digest = "f".repeat(64);
    assert_eq!(inspect(&snapshot)["policy_digest"], expected);
    assert!(validate_v3(
        &snapshot,
        4,
        &"a".repeat(64),
        &"b".repeat(64),
        &[7; 32],
        200
    )
    .is_err());
}

#[test]
fn malformed_business_unknown_field_and_size_refuse_without_echo() {
    let original = serde_json::to_value(signed()).unwrap();
    for patch in [
        json!({"business_policy":null}),
        json!({"private_canary":"not-reflected"}),
        json!({"generation":0}),
    ] {
        let mut value = original.clone();
        value
            .as_object_mut()
            .unwrap()
            .extend(patch.as_object().unwrap().clone());
        assert_eq!(
            inspect_from_reader(serde_json::to_vec(&value).unwrap().as_slice()),
            Err(ERROR.into())
        );
    }
    let input = vec![b' '; guard_policy_snapshot::POLICY_SNAPSHOT_MAX_BYTES + 1];
    assert_eq!(inspect_from_reader(input.as_slice()), Err(ERROR.into()));
}

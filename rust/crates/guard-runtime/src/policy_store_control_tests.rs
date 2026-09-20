use super::*;
use crate::resident_protocol::{evaluate_resident_bytes, safe_error_response};
use sha2::{Digest, Sha256};

fn observe_request(store: &PolicySnapshotStore, key: &[u8]) -> Value {
    let intent = serde_json::json!({
        "schema": "guard-policy-snapshot-observation.v1",
        "runtime_identity": store.expected_runtime_identity,
        "scope_digest": store.expected_scope_digest,
        "nonce": "e".repeat(64),
    });
    let mac = hex::encode(crate::hmac_sha256(
        key,
        b"hol-guard-policy-snapshot-observation-v1\0",
        &canonical_json_bytes(&intent).unwrap(),
    ));
    serde_json::json!({"intent": intent, "mac": mac})
}

fn envelope(operation: &str, request: Value) -> Value {
    serde_json::json!({"operation": operation, "request": request, "deadline_budget_ms": 1000})
}

fn route(store: &PolicySnapshotStore, value: &Value) -> Result<Value, String> {
    let result = evaluate_resident_bytes(&canonical_json_bytes(value).unwrap(), Some(store))?;
    Ok(serde_json::from_slice(&result).unwrap())
}

fn checked_response(value: &Value, key: &[u8], domain: &[u8], request: &Value) -> Value {
    assert_eq!(value.as_object().unwrap().len(), 2);
    let response = value["response"].clone();
    let expected = hex::encode(crate::hmac_sha256(
        key,
        domain,
        &canonical_json_bytes(&response).unwrap(),
    ));
    assert_eq!(value["mac"], expected);
    assert_eq!(
        response["request_sha256"],
        hex::encode(Sha256::digest(canonical_json_bytes(request).unwrap()))
    );
    response
}

#[test]
fn routed_observation_and_withdrawal_bind_subject_request_and_durable_floor() {
    let root = test_root("control-route");
    let key = install_test_key(&root, 53);
    let store =
        PolicySnapshotStore::new_with_resident_generation(&root, &"a".repeat(64), 13).unwrap();
    let request = observe_request(&store, &key);
    let first = checked_response(
        &route(
            &store,
            &envelope("policy_snapshot_observe", request.clone()),
        )
        .unwrap(),
        &key,
        b"hol-guard-policy-snapshot-observation-response-v1\0",
        &request,
    );
    assert!(first["authority"].is_null());
    assert_eq!(first["nonce"], request["intent"]["nonce"]);
    assert_eq!(first["runtime_identity"], "a".repeat(64));
    assert_eq!(first["scope_digest"], store.expected_scope_digest);
    assert_eq!(first["resident_generation"], 13);
    assert!(store.current_snapshot().is_err());
    store.push(&serde_json::json!({"schema": POLICY_SNAPSHOT_PUSH_SCHEMA, "snapshot": signed_snapshot(1, &key, &root)})).unwrap();
    let observation = checked_response(
        &route(
            &store,
            &envelope("policy_snapshot_observe", request.clone()),
        )
        .unwrap(),
        &key,
        b"hol-guard-policy-snapshot-observation-response-v1\0",
        &request,
    );
    assert_eq!(observation["authority"]["generation_floor"], 1);
    assert_eq!(observation["authority"]["usable_snapshot"], true);
    let withdrawal = super::withdrawal_tests::request(&store, 10, &key);
    assert_eq!(
        withdrawal["intent"]["expected_authority"],
        observation["authority"]
    );
    let ack = checked_response(
        &route(
            &store,
            &envelope("policy_snapshot_withdraw", withdrawal.clone()),
        )
        .unwrap(),
        &key,
        b"hol-guard-policy-snapshot-withdrawal-response-v1\0",
        &withdrawal,
    );
    assert_eq!(ack["status"], "withdrawn");
    assert_eq!(ack["generation"], 10);
    assert_eq!(ack["resident_generation"], 13);
    assert!(store.current_snapshot().is_err());
    assert!(route(&store, &envelope("policy_snapshot_withdraw", withdrawal)).is_err());
    let after = checked_response(
        &route(
            &store,
            &envelope("policy_snapshot_observe", request.clone()),
        )
        .unwrap(),
        &key,
        b"hol-guard-policy-snapshot-observation-response-v1\0",
        &request,
    );
    assert_eq!(after["authority"]["generation_floor"], 10);
    assert_eq!(after["authority"]["usable_snapshot"], false);
    assert_ne!(
        after["authority"]["fingerprint"],
        observation["authority"]["fingerprint"]
    );
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn routed_observation_never_authenticates_unrequested_or_changed_subjects() {
    let root = test_root("control-subject");
    let key = install_test_key(&root, 54);
    let store =
        PolicySnapshotStore::new_with_resident_generation(&root, &"a".repeat(64), 17).unwrap();
    let good = observe_request(&store, &key);
    for field in ["schema", "runtime_identity", "scope_digest", "nonce"] {
        let mut changed = good.clone();
        changed["intent"][field] = "b".repeat(64).into();
        assert!(route(&store, &envelope("policy_snapshot_observe", changed)).is_err());
        let mut missing = good.clone();
        missing["intent"].as_object_mut().unwrap().remove(field);
        assert!(route(&store, &envelope("policy_snapshot_observe", missing)).is_err());
    }
    let mut purpose = good.clone();
    purpose["mac"] = generation_floor_mac(1, &"d".repeat(64), &key).into();
    assert!(route(&store, &envelope("policy_snapshot_observe", purpose)).is_err());
    let stale_withdrawal = super::withdrawal_tests::request(&store, 10, &key);
    store.push(&serde_json::json!({"schema": POLICY_SNAPSHOT_PUSH_SCHEMA, "snapshot": signed_snapshot(1, &key, &root)})).unwrap();
    assert!(route(
        &store,
        &envelope("policy_snapshot_withdraw", stale_withdrawal)
    )
    .is_err());
    assert_eq!(store.current_generation(), Some(1));
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn routed_controls_refuse_duplicate_noncanonical_oversized_and_unknown_fields() {
    let root = test_root("control-codec");
    let key = install_test_key(&root, 55);
    let store =
        PolicySnapshotStore::new_with_resident_generation(&root, &"a".repeat(64), 17).unwrap();
    let good = envelope("policy_snapshot_observe", observe_request(&store, &key));
    let bytes = canonical_json_bytes(&good).unwrap();
    assert_eq!(
        evaluate_resident_bytes(&bytes, None).unwrap_err(),
        "native_policy_snapshot_unavailable"
    );
    let mut padded = bytes.clone();
    padded.push(b' ');
    assert_eq!(
        evaluate_resident_bytes(&padded, Some(&store)).unwrap_err(),
        "native_policy_snapshot_control_noncanonical"
    );
    let duplicate = format!(
        "{{\"operation\":\"policy_snapshot_observe\",{}",
        String::from_utf8(bytes.clone())
            .unwrap()
            .strip_prefix('{')
            .unwrap()
    );
    assert!(evaluate_resident_bytes(duplicate.as_bytes(), Some(&store)).is_err());
    for bad in [
        Value::Null,
        Value::Bool(true),
        Value::from(0),
        Value::from(9001),
        Value::from(1.0),
    ] {
        let mut changed = good.clone();
        changed["deadline_budget_ms"] = bad;
        assert!(route(&store, &changed).is_err());
    }
    let mut unknown = good.clone();
    unknown["extra"] = true.into();
    assert!(route(&store, &unknown).is_err());
    let mut oversized = good.clone();
    oversized["request"]["intent"]["nonce"] = "x".repeat(4096).into();
    assert_eq!(
        route(&store, &oversized).unwrap_err(),
        "native_policy_snapshot_control_bounds_exceeded"
    );
    let mut nested = good.clone();
    nested["request"]["intent"]["nonce"] = serde_json::json!({"unexpected": ["value"]});
    assert!(route(&store, &nested).is_err());
    assert!(!root.join(SNAPSHOT_FILE_NAME).exists());
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn control_error_transport_uses_only_exact_finite_codes() {
    for code in [
        "native_policy_snapshot_control_invalid",
        "native_policy_snapshot_withdrawal_stale",
        "native_policy_snapshot_writer_busy",
    ] {
        let value: Value = serde_json::from_slice(&safe_error_response(code, false)).unwrap();
        assert_eq!(value["error"], code);
    }
    let value: Value = serde_json::from_slice(&safe_error_response(
        "native_policy_snapshot_withdrawal_private_text",
        false,
    ))
    .unwrap();
    assert_eq!(value["error"], "native_request_invalid_json");
}

#[test]
fn observation_of_expired_embedded_snapshot_does_not_claim_withdrawal() {
    let root = test_root("control-expired");
    let key = install_test_key(&root, 56);
    let mut expired = signed_snapshot(1, &key, &root);
    expired.issued_at_ms = now_ms().unwrap().saturating_sub(10_000);
    expired.expires_at_ms = now_ms().unwrap().saturating_sub(1);
    expired.policy_digest = policy_digest(&expired).unwrap();
    expired.integrity.mac = integrity_mac(&expired, &key).unwrap();
    let versioned = crate::policy_store::AuthenticatedPolicySnapshot::V3(expired.clone());
    crate::policy_store::persist_authority(
        &root.join(SNAPSHOT_FILE_NAME),
        1,
        &expired.policy_digest,
        Some(&versioned),
        &key,
    )
    .unwrap();
    let store =
        PolicySnapshotStore::new_with_resident_generation(&root, &"a".repeat(64), 17).unwrap();
    let request = observe_request(&store, &key);
    let response = checked_response(
        &route(
            &store,
            &envelope("policy_snapshot_observe", request.clone()),
        )
        .unwrap(),
        &key,
        b"hol-guard-policy-snapshot-observation-response-v1\0",
        &request,
    );
    assert_eq!(response["authority"]["generation_floor"], 1);
    assert_eq!(response["authority"]["usable_snapshot"], false);
    assert!(response["authority"].get("withdrawn").is_none());
    let retained: Value =
        serde_json::from_slice(&fs::read(root.join(SNAPSHOT_FILE_NAME)).unwrap()).unwrap();
    assert!(retained["snapshot"].is_object());
    assert!(store.current_snapshot().is_err());
    fs::remove_dir_all(root).unwrap();
}

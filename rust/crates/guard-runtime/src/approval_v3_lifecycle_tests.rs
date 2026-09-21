use super::*;
use guard_contracts::{
    ApprovalChallengeRequestV3, ApprovalConsumeRequestV3, ApprovalValidateRequestV3,
    NATIVE_APPROVAL_DEVICE_BINDING_DOMAIN, NATIVE_APPROVAL_INSTALLATION_BINDING_DOMAIN,
    NATIVE_APPROVAL_MAX_CLOCK_SKEW_MS, NATIVE_APPROVAL_MAX_TTL_MS,
};
use guard_policy_snapshot::{
    integrity_mac, policy_digest, PolicySnapshotPushV1, POLICY_SNAPSHOT_PUSH_SCHEMA,
};
use serde_json::Value;
use std::sync::Arc;
use std::thread;

#[test]
fn policy_material_and_public_key_replacement_cannot_authorize() {
    let (root, store, envelope) = store_and_envelope("independent-authority");
    let challenge = challenge_for(&store, &envelope);
    let artifact = artifact_from_challenge(&challenge, &store.test_approval_signing_seed());
    let policy_forged = artifact_from_challenge(&challenge, &[7u8; 32]);
    assert_eq!(
        validate_artifact_error(&store, &envelope, policy_forged),
        "native_approval_integrity_mismatch"
    );

    crate::policy_store::approval_authority::write_test_record(
        &root,
        &approval_public_key_for_tests(&[19u8; 32]),
        1,
    );
    assert!(matches!(
        validate_artifact_error(&store, &envelope, artifact).as_str(),
        "native_approval_signing_authority_replaced" | "native_approval_policy_context_mismatch"
    ));
}

#[test]
fn binding_derivation_uses_separate_runtime_purposes() {
    let (_root, store, _envelope) = store_and_envelope("binding-purpose");
    let device = store
        .approval_binding(NATIVE_APPROVAL_DEVICE_BINDING_DOMAIN)
        .unwrap();
    let installation = store
        .approval_binding(NATIVE_APPROVAL_INSTALLATION_BINDING_DOMAIN)
        .unwrap();
    assert_ne!(device, installation);
    assert!(device.bytes().all(|byte| byte.is_ascii_hexdigit()));
    assert!(installation.bytes().all(|byte| byte.is_ascii_hexdigit()));
    assert_ne!(device, store.approval_signing_key_id().unwrap());
    assert_ne!(installation, store.approval_signing_key_id().unwrap());
}

#[test]
fn policy_push_after_claim_before_consume_cannot_authorize_execution() {
    let (root, store, envelope) = store_and_envelope("consume-fence");
    let challenge = challenge_for(&store, &envelope);
    let artifact = artifact_from_challenge(&challenge, &store.test_approval_signing_seed());
    validate_approval(
        ApprovalValidateRequestV3 {
            schema: NATIVE_APPROVAL_VALIDATE_REQUEST_V3_SCHEMA.into(),
            version: 3,
            envelope: envelope.clone(),
            artifact: artifact.clone(),
        },
        &store,
    )
    .unwrap();

    let key = [7u8; 32];
    let mut next = snapshot(&root, &key);
    next.generation = 2;
    next.policy_digest = policy_digest(&next).unwrap();
    next.integrity.mac = integrity_mac(&next, &key).unwrap();
    store
        .push(
            &serde_json::to_value(PolicySnapshotPushV1 {
                schema: POLICY_SNAPSHOT_PUSH_SCHEMA.into(),
                snapshot: next,
            })
            .unwrap(),
        )
        .unwrap();

    let error = consume_approval(
        ApprovalConsumeRequestV3 {
            schema: NATIVE_APPROVAL_CONSUME_REQUEST_V3_SCHEMA.into(),
            version: 3,
            envelope,
            artifact,
        },
        &store,
    )
    .unwrap_err();
    assert_eq!(error, "native_approval_policy_context_mismatch");
}

#[test]
fn consume_requires_claim_and_is_single_use() {
    let (_root, store, envelope) = store_and_envelope("consume-single-use");
    let challenge = challenge_for(&store, &envelope);
    let artifact = artifact_from_challenge(&challenge, &store.test_approval_signing_seed());
    let request = ApprovalConsumeRequestV3 {
        schema: NATIVE_APPROVAL_CONSUME_REQUEST_V3_SCHEMA.into(),
        version: 3,
        envelope: envelope.clone(),
        artifact: artifact.clone(),
    };
    assert_eq!(
        consume_approval(request.clone(), &store).unwrap_err(),
        "native_approval_receipt_not_claimed"
    );
    validate_approval(
        ApprovalValidateRequestV3 {
            schema: NATIVE_APPROVAL_VALIDATE_REQUEST_V3_SCHEMA.into(),
            version: 3,
            envelope,
            artifact,
        },
        &store,
    )
    .unwrap();
    let response = consume_approval(request.clone(), &store).unwrap();
    let value: Value = serde_json::from_slice(&response).unwrap();
    assert_eq!(value["receipt"]["reason_code"], "native_approval_consumed");
    assert_eq!(value["receipt"]["phase"], "consumed");
    assert_eq!(value["receipt"]["request_id"], challenge.request_id);
    assert_eq!(value["receipt"]["request_digest"], challenge.request_digest);
    assert_eq!(value["receipt"]["action_digest"], challenge.action_digest);
    assert_eq!(
        value["receipt"]["policy_generation"],
        challenge.policy_generation
    );
    assert_eq!(value["receipt"]["policy_digest"], challenge.policy_digest);
    assert_eq!(value["receipt"]["rule_digest"], challenge.rule_digest);
    assert_eq!(value["receipt"]["harness"], challenge.harness);
    assert_eq!(value["receipt"]["resident_epoch"], challenge.resident_epoch);
    assert_eq!(value["receipt"]["nonce"], challenge.nonce);
    assert_eq!(value["receipt"]["expires_at_ms"], challenge.expires_at_ms);
    assert_eq!(
        consume_approval(request, &store).unwrap_err(),
        "native_approval_receipt_consumed"
    );
}

#[test]
fn replay_and_concurrent_claim_are_single_use() {
    let (_root, store, envelope) = store_and_envelope("replay");
    let challenge = challenge_for(&store, &envelope);
    let artifact = artifact_from_challenge(&challenge, &store.test_approval_signing_seed());
    let request = || ApprovalValidateRequestV3 {
        schema: NATIVE_APPROVAL_VALIDATE_REQUEST_V3_SCHEMA.into(),
        version: 3,
        envelope: envelope.clone(),
        artifact: artifact.clone(),
    };
    validate_approval(request(), &store).unwrap();
    assert_eq!(
        validate_approval(request(), &store).unwrap_err(),
        "native_approval_replay"
    );

    let (_root, store, envelope) = store_and_envelope("concurrent");
    let challenge = challenge_for(&store, &envelope);
    let artifact = artifact_from_challenge(&challenge, &store.test_approval_signing_seed());
    let store = Arc::new(store);
    let first_store = Arc::clone(&store);
    let first_envelope = envelope.clone();
    let first_artifact = artifact.clone();
    let first = thread::spawn(move || {
        validate_approval(
            ApprovalValidateRequestV3 {
                schema: NATIVE_APPROVAL_VALIDATE_REQUEST_V3_SCHEMA.into(),
                version: 3,
                envelope: first_envelope,
                artifact: first_artifact,
            },
            &first_store,
        )
    });
    let second_store = Arc::clone(&store);
    let second = thread::spawn(move || {
        validate_approval(
            ApprovalValidateRequestV3 {
                schema: NATIVE_APPROVAL_VALIDATE_REQUEST_V3_SCHEMA.into(),
                version: 3,
                envelope: envelope.clone(),
                artifact,
            },
            &second_store,
        )
    });
    let outcomes = [
        first.join().unwrap().is_ok(),
        second.join().unwrap().is_ok(),
    ];
    assert_eq!(outcomes.iter().filter(|value| **value).count(), 1);
}

#[test]
fn artifact_binding_mutation_and_hard_floors_fail_before_claim() {
    let (_root, store, envelope) = store_and_envelope("binding");
    let challenge = challenge_for(&store, &envelope);
    let mut artifact = artifact_from_challenge(&challenge, &store.test_approval_signing_seed());
    artifact.harness = "cursor".into();
    artifact.integrity.signature =
        approval_signature_for_tests(&artifact, &store.test_approval_signing_seed()).unwrap();
    assert_eq!(
        validate_approval(
            ApprovalValidateRequestV3 {
                schema: NATIVE_APPROVAL_VALIDATE_REQUEST_V3_SCHEMA.into(),
                version: 3,
                envelope: envelope.clone(),
                artifact,
            },
            &store,
        )
        .unwrap_err(),
        "native_approval_binding_mismatch"
    );

    let mut blocked = envelope;
    blocked.raw_payload = serde_json::json!({"tool_name":"bash", "command":"rm -rf /"});
    let error = create_challenge(
        ApprovalChallengeRequestV3 {
            schema: NATIVE_APPROVAL_CHALLENGE_REQUEST_V3_SCHEMA.into(),
            version: 3,
            envelope: blocked,
        },
        &store,
    )
    .unwrap_err();
    assert_eq!(error, "native_approval_floor_not_overridable");
}

#[test]
fn artifact_timing_nonce_and_integrity_are_checked() {
    let (_root, store, envelope) = store_and_envelope("timing");
    let challenge = challenge_for(&store, &envelope);
    let mut artifact = artifact_from_challenge(&challenge, &store.test_approval_signing_seed());
    artifact.expires_at_ms = artifact.issued_at_ms;
    artifact.integrity.signature =
        approval_signature_for_tests(&artifact, &store.test_approval_signing_seed()).unwrap();
    assert_eq!(
        validate_approval(
            ApprovalValidateRequestV3 {
                schema: NATIVE_APPROVAL_VALIDATE_REQUEST_V3_SCHEMA.into(),
                version: 3,
                envelope: envelope.clone(),
                artifact,
            },
            &store,
        )
        .unwrap_err(),
        "native_approval_time_invalid"
    );

    let mut nonce = artifact_from_challenge(&challenge, &store.test_approval_signing_seed());
    nonce.nonce = "00".repeat(NATIVE_APPROVAL_NONCE_BYTES);
    assert_eq!(
        validate_approval(
            ApprovalValidateRequestV3 {
                schema: NATIVE_APPROVAL_VALIDATE_REQUEST_V3_SCHEMA.into(),
                version: 3,
                envelope: envelope.clone(),
                artifact: nonce,
            },
            &store,
        )
        .unwrap_err(),
        "native_approval_integrity_mismatch"
    );

    let mut malformed = artifact_from_challenge(&challenge, &store.test_approval_signing_seed());
    malformed.integrity.signature = "0".repeat(128);
    assert_eq!(
        validate_approval(
            ApprovalValidateRequestV3 {
                schema: NATIVE_APPROVAL_VALIDATE_REQUEST_V3_SCHEMA.into(),
                version: 3,
                envelope: envelope.clone(),
                artifact: malformed,
            },
            &store,
        )
        .unwrap_err(),
        "native_approval_integrity_mismatch"
    );

    let mut future = artifact_from_challenge(&challenge, &store.test_approval_signing_seed());
    let now = now_ms().unwrap();
    future.issued_at_ms = now + NATIVE_APPROVAL_MAX_CLOCK_SKEW_MS + 1_000;
    future.expires_at_ms = future.issued_at_ms + 1_000;
    resign(&mut future, &store.test_approval_signing_seed());
    assert_eq!(
        validate_artifact_error(&store, &envelope, future),
        "native_approval_time_invalid"
    );

    let mut too_long = artifact_from_challenge(&challenge, &store.test_approval_signing_seed());
    too_long.expires_at_ms = too_long.issued_at_ms + NATIVE_APPROVAL_MAX_TTL_MS + 1;
    resign(&mut too_long, &store.test_approval_signing_seed());
    assert_eq!(
        validate_artifact_error(&store, &envelope, too_long),
        "native_approval_time_invalid"
    );
}

#[test]
fn malformed_oversize_and_deep_requests_fail_closed() {
    let (_root, store, envelope) = store_and_envelope("bounds");
    let challenge = challenge_for(&store, &envelope);
    let key = store.test_approval_signing_seed();
    let mut oversized = artifact_from_challenge(&challenge, &key);
    oversized.runtime_version = "x".repeat(NATIVE_APPROVAL_MAX_BYTES);
    assert_eq!(
        validate_artifact_error(&store, &envelope, oversized),
        "native_approval_artifact_too_large"
    );

    assert!(crate::strict_json_value(br#"{"schema":1,"schema":2}"#).is_err());
    let mut deep = Value::Null;
    for _ in 0..40 {
        deep = Value::Array(vec![deep]);
    }
    let mut deep_envelope = envelope;
    deep_envelope.raw_payload = deep;
    let error = create_challenge(
        ApprovalChallengeRequestV3 {
            schema: NATIVE_APPROVAL_CHALLENGE_REQUEST_V3_SCHEMA.into(),
            version: 3,
            envelope: deep_envelope,
        },
        &store,
    )
    .unwrap_err();
    assert!(matches!(
        error.as_str(),
        "native_hook_payload_invalid"
            | "native_approval_floor_not_overridable"
            | "native_approval_floor_not_approvable"
    ));
}

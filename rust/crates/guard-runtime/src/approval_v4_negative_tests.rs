use super::*;

#[test]
fn webauthn_origin_rp_flags_type_and_signature_are_verified_in_rust() {
    let credential_id = [5u8; 32];
    let key_pair = Ed25519KeyPair::from_seed_unchecked(&[12u8; 32]).unwrap();
    let cose = cose_ed25519(key_pair.public_key().as_ref());
    let (root, store, envelope) = store_and_envelope_v4(
        "v4-webauthn-negative",
        &cose,
        NATIVE_APPROVAL_V4_ALGORITHM_ED25519,
        &credential_id,
    );
    let challenge = challenge_for(&store, &envelope, &credential_id);
    let validate_error = |artifact: ApprovalArtifactV4| {
        validate_approval(
            ApprovalValidateRequestV4 {
                schema: NATIVE_APPROVAL_VALIDATE_REQUEST_V4_SCHEMA.to_owned(),
                version: 4,
                envelope: envelope.clone(),
                artifact,
            },
            &store,
        )
        .unwrap_err()
    };

    let wrong_origin = artifact_from_challenge(
        &challenge,
        assertion_with_values(
            &challenge,
            &credential_id,
            1,
            "https://evil.example",
            &challenge.webauthn.challenge,
            0x05,
            |message| key_pair.sign(message).as_ref().to_vec(),
        ),
    );
    assert_eq!(
        validate_error(wrong_origin),
        "native_approval_v4_origin_mismatch"
    );

    let wrong_rp = artifact_from_challenge(
        &challenge,
        assertion_with_values(
            &challenge,
            &credential_id,
            1,
            &challenge.webauthn.origin,
            &challenge.webauthn.challenge,
            0x05,
            |message| key_pair.sign(message).as_ref().to_vec(),
        ),
    );
    let wrong_rp_data = crate::approval::approval_v4_crypto::decode_base64url(
        &wrong_rp.webauthn.response.authenticator_data,
        4 * 1024,
        "test",
    )
    .unwrap();
    let mut wrong_rp_data = wrong_rp_data;
    wrong_rp_data[..32].copy_from_slice(&Sha256::digest(b"evil.example"));
    let client_data = crate::approval::approval_v4_crypto::decode_base64url(
        &wrong_rp.webauthn.response.client_data_json,
        16 * 1024,
        "test",
    )
    .unwrap();
    let client_hash = Sha256::digest(&client_data);
    let mut signed = wrong_rp_data.clone();
    signed.extend_from_slice(&client_hash);
    let mut wrong_rp = wrong_rp;
    wrong_rp.webauthn.response.authenticator_data = encode_base64url(&wrong_rp_data);
    wrong_rp.webauthn.response.signature = encode_base64url(key_pair.sign(&signed).as_ref());
    assert_eq!(
        validate_error(wrong_rp),
        "native_approval_v4_rp_id_mismatch"
    );

    let missing_up = artifact_from_challenge(
        &challenge,
        assertion_with_values(
            &challenge,
            &credential_id,
            1,
            &challenge.webauthn.origin,
            &challenge.webauthn.challenge,
            0x04,
            |message| key_pair.sign(message).as_ref().to_vec(),
        ),
    );
    assert_eq!(
        validate_error(missing_up),
        "native_approval_v4_authenticator_flags_invalid"
    );

    let missing_uv = artifact_from_challenge(
        &challenge,
        assertion_with_values(
            &challenge,
            &credential_id,
            1,
            &challenge.webauthn.origin,
            &challenge.webauthn.challenge,
            0x01,
            |message| key_pair.sign(message).as_ref().to_vec(),
        ),
    );
    assert_eq!(
        validate_error(missing_uv),
        "native_approval_v4_authenticator_flags_invalid"
    );

    let mut wrong_type = artifact_from_challenge(
        &challenge,
        assertion(&challenge, &credential_id, 1, |message| {
            key_pair.sign(message).as_ref().to_vec()
        }),
    );
    wrong_type.webauthn.assertion_type = "webauthn.get".to_owned();
    assert_eq!(
        validate_error(wrong_type),
        "native_approval_v4_artifact_invalid"
    );

    let mut bad_signature = artifact_from_challenge(
        &challenge,
        assertion(&challenge, &credential_id, 1, |message| {
            key_pair.sign(message).as_ref().to_vec()
        }),
    );
    let mut signature = crate::approval::approval_v4_crypto::decode_base64url(
        &bad_signature.webauthn.response.signature,
        256,
        "test",
    )
    .unwrap();
    signature[0] ^= 1;
    bad_signature.webauthn.response.signature = encode_base64url(&signature);
    assert_eq!(
        validate_error(bad_signature),
        "native_approval_v4_signature_invalid"
    );

    let mut duplicate_client_data = artifact_from_challenge(
        &challenge,
        assertion(&challenge, &credential_id, 1, |message| {
            key_pair.sign(message).as_ref().to_vec()
        }),
    );
    let duplicate_client_data_bytes = format!(
        "{{\"type\":\"webauthn.get\",\"type\":\"webauthn.get\",\"challenge\":\"{}\",\"origin\":\"{}\",\"crossOrigin\":false}}",
        challenge.webauthn.challenge, challenge.webauthn.origin
    )
    .into_bytes();
    let auth_data = crate::approval::approval_v4_crypto::decode_base64url(
        &duplicate_client_data.webauthn.response.authenticator_data,
        4 * 1024,
        "test",
    )
    .unwrap();
    let mut signed = auth_data;
    signed.extend_from_slice(&Sha256::digest(&duplicate_client_data_bytes));
    duplicate_client_data.webauthn.response.client_data_json =
        encode_base64url(&duplicate_client_data_bytes);
    duplicate_client_data.webauthn.response.signature =
        encode_base64url(key_pair.sign(&signed).as_ref());
    assert_eq!(
        validate_error(duplicate_client_data),
        "native_approval_v4_client_data_invalid"
    );
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn v4_request_policy_harness_expiry_and_authority_bindings_fail_closed() {
    let credential_id = [7u8; 32];
    let key_pair = Ed25519KeyPair::from_seed_unchecked(&[14u8; 32]).unwrap();
    let cose = cose_ed25519(key_pair.public_key().as_ref());
    let (root, store, envelope) = store_and_envelope_v4(
        "v4-outer-bindings",
        &cose,
        NATIVE_APPROVAL_V4_ALGORITHM_ED25519,
        &credential_id,
    );
    let challenge = challenge_for(&store, &envelope, &credential_id);
    let base = artifact_from_challenge(
        &challenge,
        assertion(&challenge, &credential_id, 1, |message| {
            key_pair.sign(message).as_ref().to_vec()
        }),
    );
    let validate_error = |artifact: ApprovalArtifactV4| {
        validate_approval(
            ApprovalValidateRequestV4 {
                schema: NATIVE_APPROVAL_VALIDATE_REQUEST_V4_SCHEMA.to_owned(),
                version: 4,
                envelope: envelope.clone(),
                artifact,
            },
            &store,
        )
        .unwrap_err()
    };

    let mut cross_request = base.clone();
    cross_request.request_id = "different-request".to_owned();
    assert_eq!(validate_error(cross_request), "native_approval_v4_artifact_invalid");

    let mut cross_policy = base.clone();
    cross_policy.policy_generation += 1;
    assert_eq!(validate_error(cross_policy), "native_approval_v4_artifact_invalid");

    let mut cross_harness = base.clone();
    cross_harness.harness = "other-harness".to_owned();
    assert_eq!(validate_error(cross_harness), "native_approval_v4_artifact_invalid");

    let mut expired = base.clone();
    expired.expires_at_ms = expired.issued_at_ms;
    assert_eq!(validate_error(expired), "native_approval_v4_artifact_invalid");

    let mut wrong_key = base;
    wrong_key.signing_key_id = "f".repeat(64);
    assert_eq!(
        validate_error(wrong_key),
        "native_approval_v4_authority_provenance_mismatch"
    );
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn v4_restart_and_concurrent_claims_fail_closed() {
    let credential_id = [6u8; 32];
    let key_pair = Ed25519KeyPair::from_seed_unchecked(&[13u8; 32]).unwrap();
    let cose = cose_ed25519(key_pair.public_key().as_ref());
    let (root, store, envelope) = store_and_envelope_v4(
        "v4-restart-concurrency",
        &cose,
        NATIVE_APPROVAL_V4_ALGORITHM_ED25519,
        &credential_id,
    );
    let challenge = challenge_for(&store, &envelope, &credential_id);
    let artifact = artifact_from_challenge(
        &challenge,
        assertion(&challenge, &credential_id, 1, |message| {
            key_pair.sign(message).as_ref().to_vec()
        }),
    );
    let store = std::sync::Arc::new(store);
    let first_store = std::sync::Arc::clone(&store);
    let first_envelope = envelope.clone();
    let first_artifact = artifact.clone();
    let first = std::thread::spawn(move || {
        validate_approval(
            ApprovalValidateRequestV4 {
                schema: NATIVE_APPROVAL_VALIDATE_REQUEST_V4_SCHEMA.to_owned(),
                version: 4,
                envelope: first_envelope,
                artifact: first_artifact,
            },
            &first_store,
        )
    });
    let second_store = std::sync::Arc::clone(&store);
    let second_envelope = envelope.clone();
    let second_artifact = artifact.clone();
    let second = std::thread::spawn(move || {
        validate_approval(
            ApprovalValidateRequestV4 {
                schema: NATIVE_APPROVAL_VALIDATE_REQUEST_V4_SCHEMA.to_owned(),
                version: 4,
                envelope: second_envelope,
                artifact: second_artifact,
            },
            &second_store,
        )
    });
    let outcomes = [
        first.join().unwrap().is_ok(),
        second.join().unwrap().is_ok(),
    ];
    assert_eq!(outcomes.iter().filter(|value| **value).count(), 1);
    drop(store);
    let restarted = crate::policy_store::PolicySnapshotStore::new(&root, &"a".repeat(64)).unwrap();
    assert_eq!(
        validate_approval(
            ApprovalValidateRequestV4 {
                schema: NATIVE_APPROVAL_VALIDATE_REQUEST_V4_SCHEMA.to_owned(),
                version: 4,
                envelope,
                artifact,
            },
            &restarted,
        )
        .unwrap_err(),
        "native_approval_v4_artifact_invalid"
    );
    fs::remove_dir_all(root).unwrap();
}

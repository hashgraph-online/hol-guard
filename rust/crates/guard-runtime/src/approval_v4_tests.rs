use super::*;
use crate::approval::approval_v4_crypto::encode_base64url;
use guard_contracts::{
    ApprovalArtifactV4, ApprovalAuthorityV4, ApprovalChallengeRequestV4, ApprovalChallengeV4,
    ApprovalConsumeRequestV4, ApprovalValidateRequestV4, GuardHookEnvelopeV2,
    WebAuthnAssertionResponseV4, WebAuthnAssertionV4, NATIVE_APPROVAL_ARTIFACT_V4_SCHEMA,
    NATIVE_APPROVAL_CHALLENGE_REQUEST_V4_SCHEMA, NATIVE_APPROVAL_CONSUME_REQUEST_V4_SCHEMA,
    NATIVE_APPROVAL_V4_ALGORITHM_ED25519, NATIVE_APPROVAL_V4_ALGORITHM_ES256,
    NATIVE_APPROVAL_VALIDATE_REQUEST_V4_SCHEMA,
};
use guard_policy_snapshot::digest_bytes;
use ring::rand::SystemRandom;
use ring::signature::{EcdsaKeyPair, Ed25519KeyPair, KeyPair, ECDSA_P256_SHA256_ASN1_SIGNING};
use sha2::{Digest, Sha256};
use std::fs;
use std::path::Path;

mod negative_tests {
    include!("approval_v4_negative_tests.rs");
}

fn cose_ed25519(public_key: &[u8]) -> Vec<u8> {
    let mut value = vec![0xa4, 0x01, 0x01, 0x03, 0x27, 0x20, 0x06, 0x21, 0x58, 0x20];
    value.extend_from_slice(public_key);
    value
}

fn cose_es256(public_key: &[u8]) -> Vec<u8> {
    assert_eq!(public_key.len(), 65);
    let mut value = vec![0xa5, 0x01, 0x02, 0x03, 0x26, 0x20, 0x01, 0x21, 0x58, 0x20];
    value.extend_from_slice(&public_key[1..33]);
    value.extend_from_slice(&[0x22, 0x58, 0x20]);
    value.extend_from_slice(&public_key[33..]);
    value
}

fn install_v4_authority(
    root: &Path,
    old_store: &crate::policy_store::PolicySnapshotStore,
    cose_public_key: &[u8],
    algorithm: i32,
    credential_id: &[u8],
) {
    let record = ApprovalAuthorityV4 {
        schema: guard_contracts::NATIVE_APPROVAL_AUTHORITY_V4_SCHEMA.to_owned(),
        version: 4,
        key_id: digest_bytes(cose_public_key),
        rp_id: "example.com".to_owned(),
        origin: "https://example.com".to_owned(),
        credential_id: hex::encode(credential_id),
        cose_public_key: hex::encode(cose_public_key),
        algorithm,
        device_binding: old_store
            .approval_binding(guard_contracts::NATIVE_APPROVAL_DEVICE_BINDING_DOMAIN)
            .unwrap(),
        installation_binding: old_store
            .approval_binding(guard_contracts::NATIVE_APPROVAL_INSTALLATION_BINDING_DOMAIN)
            .unwrap(),
        enrollment_generation: 1,
        previous_key_id: None,
        status: "active".to_owned(),
        enrollment_signature: String::new(),
    };
    crate::policy_store::approval_v4_authority::tests::write_test_record(root, &record).unwrap();
}

fn store_and_envelope_v4(
    label: &str,
    cose_public_key: &[u8],
    algorithm: i32,
    credential_id: &[u8],
) -> (
    std::path::PathBuf,
    crate::policy_store::PolicySnapshotStore,
    GuardHookEnvelopeV2,
) {
    let (root, old_store, envelope) = crate::approval::tests::store_and_envelope(label);
    install_v4_authority(&root, &old_store, cose_public_key, algorithm, credential_id);
    drop(old_store);
    let store = crate::policy_store::PolicySnapshotStore::new(&root, &"a".repeat(64)).unwrap();
    (root, store, envelope)
}

fn challenge_for(
    store: &crate::policy_store::PolicySnapshotStore,
    envelope: &GuardHookEnvelopeV2,
    credential_id: &[u8],
) -> ApprovalChallengeV4 {
    let response = create_challenge(
        ApprovalChallengeRequestV4 {
            schema: NATIVE_APPROVAL_CHALLENGE_REQUEST_V4_SCHEMA.to_owned(),
            version: 4,
            envelope: envelope.clone(),
        },
        store,
    )
    .unwrap();
    let challenge: ApprovalChallengeV4 = serde_json::from_slice(&response).unwrap();
    assert_eq!(
        challenge.webauthn.credential_id,
        encode_base64url(credential_id)
    );
    challenge
}

fn assertion_with_values(
    challenge: &ApprovalChallengeV4,
    credential_id: &[u8],
    sign_count: u32,
    origin: &str,
    challenge_value: &str,
    flags: u8,
    sign: impl FnOnce(&[u8]) -> Vec<u8>,
) -> WebAuthnAssertionV4 {
    let client_data = format!(
            "{{\"type\":\"webauthn.get\",\"challenge\":\"{challenge_value}\",\"origin\":\"{origin}\",\"crossOrigin\":false}}"
        )
        .into_bytes();
    let rp_hash = Sha256::digest(challenge.webauthn.rp_id.as_bytes());
    let mut authenticator_data = Vec::with_capacity(37);
    authenticator_data.extend_from_slice(&rp_hash);
    authenticator_data.push(flags);
    authenticator_data.extend_from_slice(&sign_count.to_be_bytes());
    let client_hash = Sha256::digest(&client_data);
    let mut signed = authenticator_data.clone();
    signed.extend_from_slice(&client_hash);
    let signature = sign(&signed);
    WebAuthnAssertionV4 {
        id: encode_base64url(credential_id),
        raw_id: encode_base64url(credential_id),
        assertion_type: "public-key".to_owned(),
        response: WebAuthnAssertionResponseV4 {
            client_data_json: encode_base64url(&client_data),
            authenticator_data: encode_base64url(&authenticator_data),
            signature: encode_base64url(&signature),
            user_handle: None,
        },
    }
}

fn assertion(
    challenge: &ApprovalChallengeV4,
    credential_id: &[u8],
    sign_count: u32,
    sign: impl FnOnce(&[u8]) -> Vec<u8>,
) -> WebAuthnAssertionV4 {
    assertion_with_values(
        challenge,
        credential_id,
        sign_count,
        &challenge.webauthn.origin,
        &challenge.webauthn.challenge,
        0x05,
        sign,
    )
}

fn artifact_from_challenge(
    challenge: &ApprovalChallengeV4,
    webauthn: WebAuthnAssertionV4,
) -> ApprovalArtifactV4 {
    ApprovalArtifactV4 {
        schema: NATIVE_APPROVAL_ARTIFACT_V4_SCHEMA.to_owned(),
        version: 4,
        request_id: challenge.request_id.clone(),
        request_digest: challenge.request_digest.clone(),
        action_digest: challenge.action_digest.clone(),
        action_type: challenge.action_type,
        operation: challenge.operation,
        intrinsic_action: challenge.intrinsic_action.clone(),
        minimum_action: challenge.minimum_action.clone(),
        floor_class: challenge.floor_class,
        approval_eligible: challenge.approval_eligible,
        policy_generation: challenge.policy_generation,
        policy_digest: challenge.policy_digest.clone(),
        rule_digest: challenge.rule_digest.clone(),
        runtime_identity: challenge.runtime_identity.clone(),
        runtime_protocol_version: challenge.runtime_protocol_version,
        runtime_package: challenge.runtime_package.clone(),
        runtime_version: challenge.runtime_version.clone(),
        runtime_binary_identity: challenge.runtime_binary_identity.clone(),
        harness: challenge.harness.clone(),
        workspace_binding: challenge.workspace_binding.clone(),
        device_binding: challenge.device_binding.clone(),
        installation_binding: challenge.installation_binding.clone(),
        publisher_binding: challenge.publisher_binding.clone(),
        artifact_binding: challenge.artifact_binding.clone(),
        scope_contract_version: challenge.scope_contract_version.clone(),
        scope_contract_digest: challenge.scope_contract_digest.clone(),
        scope_binding: challenge.scope_binding.clone(),
        resident_epoch: challenge.resident_epoch.clone(),
        nonce: challenge.nonce.clone(),
        issued_at_ms: challenge.issued_at_ms,
        expires_at_ms: challenge.expires_at_ms,
        requested_action: challenge.requested_action.clone(),
        approved_action: "allow".to_owned(),
        signing_key_id: challenge.signing_key_id.clone(),
        webauthn,
    }
}

#[test]
fn ed25519_assertion_validates_and_persists_counter_zero_and_one() {
    let credential_id = [1u8; 32];
    let key_pair = Ed25519KeyPair::from_seed_unchecked(&[9u8; 32]).unwrap();
    let cose = cose_ed25519(key_pair.public_key().as_ref());
    let (root, store, envelope) = store_and_envelope_v4(
        "v4-ed25519",
        &cose,
        NATIVE_APPROVAL_V4_ALGORITHM_ED25519,
        &credential_id,
    );
    let challenge = challenge_for(&store, &envelope, &credential_id);
    let artifact = artifact_from_challenge(
        &challenge,
        assertion(&challenge, &credential_id, 0, |message| {
            key_pair.sign(message).as_ref().to_vec()
        }),
    );
    let validated = validate_approval(
        ApprovalValidateRequestV4 {
            schema: NATIVE_APPROVAL_VALIDATE_REQUEST_V4_SCHEMA.to_owned(),
            version: 4,
            envelope: envelope.clone(),
            artifact: artifact.clone(),
        },
        &store,
    )
    .unwrap();
    let validated_value: serde_json::Value = serde_json::from_slice(&validated).unwrap();
    assert_eq!(validated_value["receipt"]["authenticator_sign_count"], 0);
    let consumed = consume_approval(
        ApprovalConsumeRequestV4 {
            schema: NATIVE_APPROVAL_CONSUME_REQUEST_V4_SCHEMA.to_owned(),
            version: 4,
            envelope: envelope.clone(),
            artifact,
        },
        &store,
    )
    .unwrap();
    let consumed_value: serde_json::Value = serde_json::from_slice(&consumed).unwrap();
    assert_eq!(consumed_value["receipt"]["authenticator_sign_count"], 0);

    let restarted = crate::policy_store::PolicySnapshotStore::new(&root, &"a".repeat(64)).unwrap();
    let next_challenge = challenge_for(&restarted, &envelope, &credential_id);
    let next_artifact = artifact_from_challenge(
        &next_challenge,
        assertion(&next_challenge, &credential_id, 1, |message| {
            key_pair.sign(message).as_ref().to_vec()
        }),
    );
    validate_approval(
        ApprovalValidateRequestV4 {
            schema: NATIVE_APPROVAL_VALIDATE_REQUEST_V4_SCHEMA.to_owned(),
            version: 4,
            envelope,
            artifact: next_artifact,
        },
        &restarted,
    )
    .unwrap();
    let persisted = crate::policy_store::approval_v4_authority::load(&root)
        .unwrap()
        .unwrap();
    assert_eq!(
        crate::policy_store::approval_v4_authority::sign_count(&persisted).unwrap(),
        1
    );
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn es256_assertion_validates_and_rejects_zero_after_counter_established() {
    let rng = SystemRandom::new();
    let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &rng).unwrap();
    let key_pair =
        EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, pkcs8.as_ref(), &rng).unwrap();
    let cose = cose_es256(key_pair.public_key().as_ref());
    let credential_id = [2u8; 32];
    let (root, store, envelope) = store_and_envelope_v4(
        "v4-es256",
        &cose,
        NATIVE_APPROVAL_V4_ALGORITHM_ES256,
        &credential_id,
    );
    let challenge = challenge_for(&store, &envelope, &credential_id);
    let artifact = artifact_from_challenge(
        &challenge,
        assertion(&challenge, &credential_id, 1, |message| {
            key_pair.sign(&rng, message).unwrap().as_ref().to_vec()
        }),
    );
    validate_approval(
        ApprovalValidateRequestV4 {
            schema: NATIVE_APPROVAL_VALIDATE_REQUEST_V4_SCHEMA.to_owned(),
            version: 4,
            envelope: envelope.clone(),
            artifact: artifact.clone(),
        },
        &store,
    )
    .unwrap();
    let replay_challenge = challenge_for(&store, &envelope, &credential_id);
    let replay = artifact_from_challenge(
        &replay_challenge,
        assertion(&replay_challenge, &credential_id, 1, |message| {
            key_pair.sign(&rng, message).unwrap().as_ref().to_vec()
        }),
    );
    assert_eq!(
        validate_approval(
            ApprovalValidateRequestV4 {
                schema: NATIVE_APPROVAL_VALIDATE_REQUEST_V4_SCHEMA.to_owned(),
                version: 4,
                envelope: envelope.clone(),
                artifact: replay,
            },
            &store,
        )
        .unwrap_err(),
        "native_approval_v4_counter_replay"
    );
    let synced_challenge = challenge_for(&store, &envelope, &credential_id);
    let synced = artifact_from_challenge(
        &synced_challenge,
        assertion(&synced_challenge, &credential_id, 0, |message| {
            key_pair.sign(&rng, message).unwrap().as_ref().to_vec()
        }),
    );
    assert_eq!(
        validate_approval(
            ApprovalValidateRequestV4 {
                schema: NATIVE_APPROVAL_VALIDATE_REQUEST_V4_SCHEMA.to_owned(),
                version: 4,
                envelope,
                artifact: synced,
            },
            &store,
        )
        .unwrap_err(),
        "native_approval_v4_counter_replay"
    );
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn webauthn_optional_cross_origin_is_treated_as_false() {
    let credential_id = [4u8; 32];
    let key_pair = Ed25519KeyPair::from_seed_unchecked(&[11u8; 32]).unwrap();
    let cose = cose_ed25519(key_pair.public_key().as_ref());
    let (root, store, envelope) = store_and_envelope_v4(
        "v4-optional-cross-origin",
        &cose,
        NATIVE_APPROVAL_V4_ALGORITHM_ED25519,
        &credential_id,
    );
    let challenge = challenge_for(&store, &envelope, &credential_id);
    let mut artifact = artifact_from_challenge(
        &challenge,
        assertion(&challenge, &credential_id, 0, |message| {
            key_pair.sign(message).as_ref().to_vec()
        }),
    );
    let client_data = format!(
        "{{\"type\":\"webauthn.get\",\"challenge\":\"{}\",\"origin\":\"{}\"}}",
        challenge.webauthn.challenge, challenge.webauthn.origin
    )
    .into_bytes();
    let authenticator_data = crate::approval::approval_v4_crypto::decode_base64url(
        &artifact.webauthn.response.authenticator_data,
        4 * 1024,
        "test",
    )
    .unwrap();
    let client_hash = Sha256::digest(&client_data);
    let mut signed = authenticator_data.clone();
    signed.extend_from_slice(&client_hash);
    artifact.webauthn.response.client_data_json = encode_base64url(&client_data);
    artifact.webauthn.response.signature = encode_base64url(key_pair.sign(&signed).as_ref());
    validate_approval(
        ApprovalValidateRequestV4 {
            schema: NATIVE_APPROVAL_VALIDATE_REQUEST_V4_SCHEMA.to_owned(),
            version: 4,
            envelope,
            artifact,
        },
        &store,
    )
    .unwrap();
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn assertion_mutations_fail_before_replay_claim() {
    let credential_id = [3u8; 32];
    let key_pair = Ed25519KeyPair::from_seed_unchecked(&[10u8; 32]).unwrap();
    let cose = cose_ed25519(key_pair.public_key().as_ref());
    let (root, store, envelope) = store_and_envelope_v4(
        "v4-mutations",
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
    let mut wrong_origin = base.clone();
    let client_data = b"{\"type\":\"webauthn.get\",\"challenge\":\"bad\",\"origin\":\"https://example.com\",\"crossOrigin\":false}".to_vec();
    let auth_data = crate::approval::approval_v4_crypto::decode_base64url(
        &wrong_origin.webauthn.response.authenticator_data,
        4 * 1024,
        "test",
    )
    .unwrap();
    let client_hash = Sha256::digest(&client_data);
    let mut signed = auth_data.clone();
    signed.extend_from_slice(&client_hash);
    wrong_origin.webauthn.response.client_data_json = encode_base64url(&client_data);
    wrong_origin.webauthn.response.signature = encode_base64url(key_pair.sign(&signed).as_ref());
    assert_eq!(
        validate_approval(
            ApprovalValidateRequestV4 {
                schema: NATIVE_APPROVAL_VALIDATE_REQUEST_V4_SCHEMA.to_owned(),
                version: 4,
                envelope: envelope.clone(),
                artifact: wrong_origin,
            },
            &store,
        )
        .unwrap_err(),
        "native_approval_v4_client_data_invalid"
    );
    let mut wrong_credential = base;
    wrong_credential.webauthn.id = encode_base64url(&[4u8; 32]);
    assert_eq!(
        validate_approval(
            ApprovalValidateRequestV4 {
                schema: NATIVE_APPROVAL_VALIDATE_REQUEST_V4_SCHEMA.to_owned(),
                version: 4,
                envelope,
                artifact: wrong_credential,
            },
            &store,
        )
        .unwrap_err(),
        "native_approval_v4_credential_mismatch"
    );
    fs::remove_dir_all(root).unwrap();
}

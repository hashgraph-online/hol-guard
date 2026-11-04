use std::sync::OnceLock;

use guard_command::attestation_signature::{
    load_attestation_public_key, verify_attestation_signature,
};
use rsa::pkcs1::EncodeRsaPrivateKey;
use rsa::pkcs8::EncodePrivateKey;

use super::*;

/// One RSA key for every test: generating it is the slow part.
fn rsa_key() -> &'static RsaPrivateKey {
    static KEY: OnceLock<RsaPrivateKey> = OnceLock::new();
    KEY.get_or_init(|| RsaPrivateKey::new(&mut rsa::rand_core::OsRng, 2048).expect("rsa key"))
}

fn rsa_pkcs8_pem() -> String {
    let der = rsa_key().to_pkcs8_der().expect("pkcs8");
    pem_text(PKCS8_LABEL, der.as_bytes())
}

fn rsa_pkcs1_pem() -> String {
    let der = rsa_key().to_pkcs1_der().expect("pkcs1");
    pem_text(PKCS1_LABEL, der.as_bytes())
}

fn ec_pkcs8(algorithm: &'static EcdsaSigningAlgorithm) -> Vec<u8> {
    EcdsaKeyPair::generate_pkcs8(algorithm, &SystemRandom::new())
        .expect("ec key")
        .as_ref()
        .to_vec()
}

/// One DER element of `bytes`: its tag, its content and what follows it.
fn der_element(bytes: &[u8]) -> (u8, &[u8], &[u8]) {
    let (length, header) = match bytes[1] {
        short if short < 0x80 => (usize::from(short), 2),
        0x81 => (usize::from(bytes[2]), 3),
        _ => panic!("unexpected DER length"),
    };
    let content = &bytes[header..header + length];
    (bytes[0], content, &bytes[header + length..])
}

/// The SEC1 `ECPrivateKey` a PKCS#8 EC document wraps.
fn sec1_of(pkcs8: &[u8]) -> Vec<u8> {
    let (_, document, _) = der_element(pkcs8);
    let (_, _, rest) = der_element(document);
    let (_, _, rest) = der_element(rest);
    let (tag, sec1, _) = der_element(rest);
    assert_eq!(tag, 0x04);
    sec1.to_vec()
}

fn ask(request: Value) -> Value {
    let bytes = serde_json::to_vec(&request).expect("request");
    let response = run_command(bytes.as_slice()).expect("answer");
    serde_json::from_slice(&response).expect("response")
}

fn payload() -> Value {
    json!({
        "payloadVersion": "guard-aibom-trust-attestation.v3",
        "nonce": "nonce-1",
        "note": "café ☕",
        "sequence": 7,
    })
}

fn sign_with(key: &str, algorithm: &str, thumbprint: Value) -> Value {
    ask(json!({
        "op": "sign",
        "key": key,
        "algorithm": algorithm,
        "key_id": "key-1",
        "public_jwk_thumbprint": thumbprint,
        "payloads": [
            {"payload": payload(), "signed_at": "2026-06-10T12:00:00+00:00"},
            {"payload": {"payloadVersion": "v-other"}, "signed_at": "later"},
        ],
    }))
}

/// Check every attestation the way a verifier does and return the first.
fn verified(answer: &Value, algorithm: &str) -> Value {
    let attestations = answer["attestations"].as_array().expect("attestations");
    assert_eq!(attestations.len(), 2);
    for (attestation, payload) in attestations
        .iter()
        .zip([payload(), json!({"payloadVersion": "v-other"})])
    {
        let canonical = canonical_guard_evidence_payload(payload.as_object().expect("payload"));
        let public_key_pem = attestation["publicKeyPem"].as_str().expect("pem");
        let key = load_attestation_public_key(public_key_pem).expect("public key");
        let signature = Base64::decode_vec(attestation["signature"].as_str().expect("signature"))
            .expect("base64");
        verify_attestation_signature(&key, &canonical, &signature, algorithm).expect("verifies");
        assert_eq!(
            attestation["payloadHash"],
            hex::encode(Sha256::digest(&canonical))
        );
        assert_eq!(
            attestation["fingerprintSha256"],
            public_key_fingerprint(public_key_pem)
        );
        assert_eq!(attestation["payloadVersion"], payload["payloadVersion"]);
        assert_eq!(attestation["signatureAlgorithm"], algorithm);
        assert_eq!(attestation["keyId"], "key-1");
        assert!(!public_key_pem.ends_with('\n'));
    }
    assert_eq!(attestations[1]["signedAt"], "later");
    attestations[0].clone()
}

#[test]
fn a_p256_key_signs_ecdsa_attestations_a_verifier_accepts() {
    let pem = pem_text(PKCS8_LABEL, &ec_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING));
    let first = verified(
        &sign_with(&pem, ECDSA_P256_SHA256, json!("thumb-1")),
        ECDSA_P256_SHA256,
    );
    assert_eq!(first["publicJwkThumbprint"], "thumb-1");
    assert_eq!(first["signedAt"], "2026-06-10T12:00:00+00:00");
    assert!(first["publicKeyPem"]
        .as_str()
        .expect("pem")
        .starts_with("-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE"));

    let sec1 = pem_text(
        SEC1_LABEL,
        &sec1_of(&ec_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING)),
    );
    let first = verified(
        &sign_with(&sec1, ECDSA_P256_SHA256, Value::Null),
        ECDSA_P256_SHA256,
    );
    assert!(first.get("publicJwkThumbprint").is_none());
}

#[test]
fn an_rsa_key_signs_pss_attestations_with_the_longest_salt() {
    for pem in [rsa_pkcs8_pem(), rsa_pkcs1_pem()] {
        let first = verified(
            &sign_with(&pem, RSA_PSS_SHA256, Value::Null),
            RSA_PSS_SHA256,
        );
        let signature =
            Base64::decode_vec(first["signature"].as_str().expect("signature")).expect("base64");
        // PSS.MAX_LENGTH for a 2048-bit key and SHA-256: 256 - 32 - 2.
        let verifier =
            rsa::pss::VerifyingKey::<Sha256>::new_with_salt_len(rsa_key().to_public_key(), 222);
        let canonical = canonical_guard_evidence_payload(payload().as_object().expect("payload"));
        let signature = rsa::pss::Signature::try_from(signature.as_slice()).expect("signature");
        rsa::signature::Verifier::verify(&verifier, &canonical, &signature).expect("max salt");
    }
}

#[test]
fn keys_are_refused_in_python_order() {
    let rsa = rsa_pkcs8_pem();
    let p256 = pem_text(PKCS8_LABEL, &ec_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING));
    let p384 = ec_pkcs8(&ECDSA_P384_SHA384_ASN1_SIGNING);
    let p384_sec1 = pem_text(SEC1_LABEL, &sec1_of(&p384));
    let p384 = pem_text(PKCS8_LABEL, &p384);
    let garbage = "-----BEGIN PRIVATE KEY-----\nsecret-key-material\n-----END PRIVATE KEY-----\n";
    for (key, algorithm, message) in [
        (rsa.as_str(), ECDSA_P256_SHA256, MUST_BE_EC),
        (p256.as_str(), RSA_PSS_SHA256, MUST_BE_RSA),
        (p384.as_str(), ECDSA_P256_SHA256, MUST_BE_P256),
        (p384_sec1.as_str(), ECDSA_P256_SHA256, MUST_BE_P256),
        (p384.as_str(), RSA_PSS_SHA256, MUST_BE_RSA),
        (p256.as_str(), "ed25519", UNSUPPORTED_ALGORITHM),
        (garbage, ECDSA_P256_SHA256, KEY_UNREADABLE),
        ("", "ed25519", KEY_UNREADABLE),
    ] {
        assert_eq!(
            sign_with(key, algorithm, Value::Null),
            json!({"error": message}),
            "{algorithm}"
        );
    }
    for key in [&rsa, &p256, &p384, &p384_sec1, &rsa_pkcs1_pem()] {
        assert_eq!(
            ask(json!({"op": "load", "key": key})),
            json!({"loaded": true})
        );
    }
    assert_eq!(
        ask(json!({"op": "load", "key": garbage})),
        json!({"error": KEY_UNREADABLE})
    );
}

fn reloads_as_p256(described: &Value) -> String {
    let pem = described["private_key_pem"].as_str().expect("pem");
    let key = load_private_key(pem).expect("loads");
    assert!(matches!(key, PrivateKey::P256(_)));
    let public_key_pem = public_key_pem(&key).expect("public key");
    assert_eq!(
        described["fingerprint_sha256"],
        public_key_fingerprint(&public_key_pem)
    );
    pem.to_owned()
}

#[test]
fn a_generated_key_is_a_fresh_p256_key() {
    let first = reloads_as_p256(&ask(json!({"op": "generate"})));
    let second = reloads_as_p256(&ask(json!({"op": "generate"})));
    assert_ne!(first, second);
    assert!(!first.ends_with('\n'));
}

#[test]
fn the_persistent_key_is_created_once_and_kept() {
    let home = tempfile::tempdir().expect("home");
    let guard_home = home.path().join("guard");
    let persistent = || ask(json!({"op": "persistent", "guard_home": guard_home}));
    let created = reloads_as_p256(&persistent());
    let path = guard_home.join(KEY_FILE);
    let stored = fs::read_to_string(&path).expect("stored");
    assert_eq!(stored, format!("{created}\n"));
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = fs::metadata(&path).expect("metadata").permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
    }
    assert_eq!(reloads_as_p256(&persistent()), created);

    // A key another process wrote is used as it is, RSA included.
    fs::write(&path, format!("\n{}\n", rsa_pkcs1_pem())).expect("rsa");
    let rsa = persistent();
    assert_eq!(rsa["private_key_pem"], rsa_pkcs1_pem());

    // An unreadable key is replaced.
    fs::write(&path, "not a key").expect("corrupt");
    let replaced = reloads_as_p256(&persistent());
    assert_ne!(replaced, created);
    assert_eq!(
        fs::read_to_string(&path).expect("stored"),
        format!("{replaced}\n")
    );
}

#[test]
fn a_guard_home_that_cannot_hold_the_key_has_none() {
    let home = tempfile::tempdir().expect("home");
    let blocked = home.path().join("file");
    fs::write(&blocked, "").expect("file");
    assert_eq!(
        ask(json!({"op": "persistent", "guard_home": blocked})),
        json!({"error": KEY_UNAVAILABLE})
    );
}

#[test]
fn unknown_requests_are_refused_and_the_command_is_named() {
    for request in [
        json!({"op": "forget"}),
        json!({"op": "generate", "extra": 1}),
        json!({"op": "load"}),
        json!(["load"]),
    ] {
        let bytes = serde_json::to_vec(&request).expect("request");
        assert_eq!(run_command(bytes.as_slice()).err(), Some(invalid()));
    }
    let oversized = vec![b' '; usize::try_from(MAX_REQUEST_BYTES).expect("limit") + 1];
    assert_eq!(
        run_command(oversized.as_slice()).err().as_deref(),
        Some("trust_attestation_key_request_too_large")
    );
    assert!(is_command("trust-attestation-key"));
    assert!(!is_command("trust-attestation-keys"));
}

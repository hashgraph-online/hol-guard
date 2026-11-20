use super::attestation_signature::{
    load_attestation_public_key, verify_attestation_signature, AttestationPublicKey,
};

/// Armour whose body is well-formed base64 but a truncated SubjectPublicKeyInfo:
/// the outer SEQUENCE claims 290 bytes and only a handful follow.
const TRUNCATED_SPKI_PEM: &str = concat!(
    "-----BEGIN PUBLIC KEY-----\n",
    "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAx3Qm2Cv3nCjPaXl/kqTf\n",
    "-----END PUBLIC KEY-----\n",
);

fn refusal(pem: &str) -> String {
    load_attestation_public_key(pem)
        .expect_err("the key should be refused")
        .message()
        .to_owned()
}

#[test]
fn a_pem_that_is_not_a_key_is_refused_as_neither_rsa_nor_ec() {
    assert_eq!(
        refusal("not a key"),
        "Trust attestation public key must be RSA or EC"
    );
    assert_eq!(
        refusal("-----BEGIN PUBLIC KEY-----\nQUJD\n-----END PUBLIC KEY-----\n"),
        "Trust attestation public key must be RSA or EC"
    );
    assert_eq!(
        refusal(TRUNCATED_SPKI_PEM),
        "Trust attestation public key must be RSA or EC"
    );
}

#[test]
fn armour_must_open_and_close_with_the_same_label() {
    assert_eq!(
        refusal("-----BEGIN PUBLIC KEY-----\nQUJD\n-----END CERTIFICATE-----\n"),
        "Trust attestation public key must be RSA or EC"
    );
    assert_eq!(
        refusal("-----BEGIN PUBLIC KEY-----\nQUJD\n"),
        "Trust attestation public key must be RSA or EC"
    );
}

#[test]
fn a_label_other_than_a_public_key_is_refused() {
    let private_key = concat!(
        "-----BEGIN PRIVATE KEY-----\n",
        "QUJD\n",
        "-----END PRIVATE KEY-----\n",
    );
    assert_eq!(
        refusal(private_key),
        "Trust attestation public key must be RSA or EC"
    );
}

#[test]
fn an_unsupported_algorithm_keeps_pythons_wording() {
    let key = AttestationPublicKey::EcOtherCurve;
    let error = verify_attestation_signature(&key, b"payload", b"signature", "ed25519")
        .expect_err("an unknown algorithm is refused");
    assert_eq!(
        error.message(),
        "Unsupported trust attestation signature algorithm"
    );
}

#[test]
fn a_key_that_does_not_match_the_declared_algorithm_is_refused_before_verifying() {
    let other_curve = AttestationPublicKey::EcOtherCurve;
    let error = verify_attestation_signature(&other_curve, b"payload", b"", "rsa-pss-sha256")
        .expect_err("an EC key cannot answer for RSA");
    assert_eq!(error.message(), "Trust attestation public key must be RSA");

    let error = verify_attestation_signature(&other_curve, b"payload", b"", "ecdsa-p256-sha256")
        .expect_err("P-384 cannot answer for P-256");
    assert_eq!(
        error.message(),
        "Trust attestation EC public key must use P-256"
    );
}

#[test]
fn a_malformed_ecdsa_signature_fails_verification() {
    // The right shape for a point and nothing that signed anything.
    let mut point = vec![0x04u8];
    point.extend_from_slice(&[0u8; 64]);
    let key = AttestationPublicKey::EcP256(point);
    let error =
        verify_attestation_signature(&key, b"payload", b"not a signature", "ecdsa-p256-sha256")
            .expect_err("garbage cannot verify");
    assert_eq!(
        error.message(),
        "Trust attestation signature verification failed"
    );
}

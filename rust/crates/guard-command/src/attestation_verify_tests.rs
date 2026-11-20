use serde_json::{json, Map, Value};

use super::attestation_verification::TrustAttestationVerificationPolicy;
use super::attestation_verify::verify_trust_attestation;

fn map(value: Value) -> Map<String, Value> {
    value.as_object().expect("an object").clone()
}

/// A shape the envelope reader accepts, so a case can reach past it.
fn readable_envelope() -> Value {
    json!({
        "payloadVersion": "guard-aibom-trust-attestation.v3",
        "payloadHash": "0".repeat(64),
        "signature": "QUJD",
        "signatureAlgorithm": "ecdsa-p256-sha256",
        "signedAt": "2026-07-16T12:00:00Z",
        "keyId": "guard-trust-ec",
        "publicKeyPem": "-----BEGIN PUBLIC KEY-----\nQUJD\n-----END PUBLIC KEY-----",
        "fingerprintSha256": "0".repeat(64),
    })
}

fn refusal(payload: Value, envelope: Value) -> String {
    verify_trust_attestation(
        &map(payload),
        &map(envelope),
        None,
        None,
        &TrustAttestationVerificationPolicy::default(),
    )
    .expect_err("the attestation should be refused")
    .message()
    .to_owned()
}

#[test]
fn an_unreadable_envelope_is_refused_before_the_payload_is_read() {
    let mut envelope = map(readable_envelope());
    envelope.insert("issuedBy".to_owned(), json!("someone"));
    // The payload is empty, so reading it would refuse too. The envelope's
    // refusal is the one Python reports, because it comes first.
    assert_eq!(
        refusal(json!({}), Value::Object(envelope)),
        "Unknown trust attestation envelope fields: issuedBy"
    );
}

#[test]
fn the_payload_is_read_before_anything_is_hashed() {
    // Nothing in this payload could hash to the envelope's `payloadHash`, and
    // the refusal still names the payload rather than the hash. The list of
    // names is whatever the payload reader requires, so only its opening is
    // pinned here.
    let refused = refusal(json!({}), readable_envelope());
    assert!(
        refused.starts_with("Missing trust attestation payload fields: "),
        "{refused}"
    );
}

#[test]
fn an_envelope_naming_an_algorithm_the_verifier_cannot_check_is_refused() {
    let mut envelope = map(readable_envelope());
    envelope.insert("signatureAlgorithm".to_owned(), json!("ed25519"));
    assert_eq!(
        refusal(json!({}), Value::Object(envelope)),
        "Unsupported trust attestation signature algorithm"
    );
}

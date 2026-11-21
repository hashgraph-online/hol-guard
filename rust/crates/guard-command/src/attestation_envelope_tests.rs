use serde_json::{json, Map, Value};

use super::attestation_envelope::{
    normalize_pem, payload_with_signed_at, public_key_fingerprint,
    validated_trust_attestation_envelope,
};

fn envelope() -> Map<String, Value> {
    json!({
        "payloadVersion": "guard-aibom-trust-attestation.v3",
        "payloadHash": "a",
        "signature": "c2ln",
        "signatureAlgorithm": "rsa-pss-sha256",
        "signedAt": "2026-01-02T03:04:05+00:00",
        "keyId": "guard-aibom-trust-key-local",
        "publicKeyPem": "-----BEGIN PUBLIC KEY-----\nAAAA\n-----END PUBLIC KEY-----",
        "fingerprintSha256": "b",
        "publicJwkThumbprint": "thumb",
    })
    .as_object()
    .expect("object")
    .clone()
}

fn refusal(fields: Value) -> String {
    let mut candidate = envelope();
    for (field, value) in fields.as_object().expect("object") {
        if value.is_null() {
            candidate.remove(field);
        } else {
            candidate.insert(field.clone(), value.clone());
        }
    }
    validated_trust_attestation_envelope(&candidate)
        .expect_err("refused")
        .message()
        .to_owned()
}

#[test]
fn a_complete_envelope_is_read_field_by_field() {
    let read = validated_trust_attestation_envelope(&envelope()).expect("accepted");

    assert_eq!(read.payload_hash, "a");
    assert_eq!(read.signature_algorithm, "rsa-pss-sha256");
    assert_eq!(read.key_id, "guard-aibom-trust-key-local");
    assert_eq!(read.fingerprint_sha256, "b");
    assert_eq!(read.public_jwk_thumbprint.as_deref(), Some("thumb"));
    assert_eq!(read.signature, "c2ln");
    assert_eq!(read.signed_at.as_deref(), Some("2026-01-02T03:04:05+00:00"));
}

#[test]
fn an_elliptic_curve_algorithm_is_accepted_too() {
    let mut candidate = envelope();
    candidate.insert(
        "signatureAlgorithm".to_owned(),
        Value::String("ecdsa-p256-sha256".to_owned()),
    );

    let read = validated_trust_attestation_envelope(&candidate).expect("accepted");

    assert_eq!(read.signature_algorithm, "ecdsa-p256-sha256");
}

#[test]
fn a_thumbprint_that_is_not_text_is_read_as_absent() {
    let mut candidate = envelope();
    candidate.insert("publicJwkThumbprint".to_owned(), json!(17));

    let read = validated_trust_attestation_envelope(&candidate).expect("accepted");

    assert_eq!(read.public_jwk_thumbprint, None);
}

#[test]
fn unknown_fields_are_named_in_sorted_order() {
    assert_eq!(
        refusal(json!({"zulu": "x", "alpha": "y"})),
        "Unknown trust attestation envelope fields: alpha, zulu"
    );
}

#[test]
fn an_unknown_field_is_named_before_an_absent_one() {
    assert_eq!(
        refusal(json!({"stowaway": "x", "keyId": null})),
        "Unknown trust attestation envelope fields: stowaway"
    );
}

#[test]
fn a_required_field_that_is_absent_blank_or_not_text_is_incomplete() {
    for field in [
        "payloadHash",
        "signatureAlgorithm",
        "keyId",
        "publicKeyPem",
        "fingerprintSha256",
        "signature",
    ] {
        for value in [Value::Null, json!(""), json!(5)] {
            assert_eq!(
                refusal(json!({ field: value })),
                "Trust attestation envelope is incomplete",
                "{field}"
            );
        }
    }
}

#[test]
fn a_version_this_build_does_not_read_is_refused() {
    assert_eq!(
        refusal(json!({"payloadVersion": "guard-aibom-trust-attestation.v2"})),
        "Unsupported trust attestation envelope version"
    );
    assert_eq!(
        refusal(json!({"payloadVersion": null})),
        "Unsupported trust attestation envelope version"
    );
}

#[test]
fn the_version_is_read_before_the_algorithm() {
    assert_eq!(
        refusal(json!({"payloadVersion": "v2", "signatureAlgorithm": "ed25519"})),
        "Unsupported trust attestation envelope version"
    );
}

#[test]
fn an_algorithm_no_verifier_here_can_check_is_refused() {
    assert_eq!(
        refusal(json!({"signatureAlgorithm": "ed25519"})),
        "Unsupported trust attestation signature algorithm"
    );
}

fn read(signed_at: Value) -> super::attestation_envelope::TrustAttestationEnvelope {
    let mut candidate = envelope();
    if signed_at.is_null() {
        candidate.remove("signedAt");
    } else {
        candidate.insert("signedAt".to_owned(), signed_at);
    }
    validated_trust_attestation_envelope(&candidate).expect("accepted")
}

#[test]
fn a_signing_time_is_carried_into_the_payload_it_covers() {
    let payload = json!({"itemId": "item", "signedAt": "1999-01-01T00:00:00+00:00"})
        .as_object()
        .expect("object")
        .clone();

    let enriched = payload_with_signed_at(&payload, &read(json!("2026-01-02T03:04:05+00:00")));

    assert_eq!(
        enriched.get("signedAt").and_then(Value::as_str),
        Some("2026-01-02T03:04:05+00:00"),
        "the envelope's signing time replaces whatever the payload arrived with"
    );
}

#[test]
fn an_envelope_without_a_usable_signing_time_leaves_the_payload_alone() {
    let payload = json!({"itemId": "item", "signedAt": "1999-01-01T00:00:00+00:00"})
        .as_object()
        .expect("object")
        .clone();

    for signed_at in [Value::Null, json!(""), json!(7)] {
        let read = read(signed_at);
        assert_eq!(read.signed_at, None);
        assert_eq!(payload_with_signed_at(&payload, &read), payload);
    }
}

#[test]
fn a_pem_is_hashed_the_same_whatever_its_line_endings_are() {
    let windows = "\r\n-----BEGIN PUBLIC KEY-----\r\nAAAA\r\n-----END PUBLIC KEY-----\r\n";
    let unix = "-----BEGIN PUBLIC KEY-----\nAAAA\n-----END PUBLIC KEY-----";

    assert_eq!(normalize_pem(windows), unix);
    assert_eq!(
        public_key_fingerprint(windows),
        public_key_fingerprint(unix)
    );
    assert_eq!(public_key_fingerprint(unix).len(), 64);
}

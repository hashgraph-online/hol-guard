//! The envelope checks the resident runs have to refuse what Python refuses.
//!
//! `tests/fixtures/guard-attestation-envelope.v1.json` records what
//! `verify_trust_attestation` does with each envelope shape: the refusal it
//! raises, or the fields it reads when the envelope passes. The companion
//! Python test replays the same file, so a rule that drifts on one side fails
//! on both.

use guard_command::attestation_envelope::{
    normalize_pem, public_key_fingerprint, validated_trust_attestation_envelope,
};
use serde_json::Value;

const VECTORS: &str = include_str!("../../../../tests/fixtures/guard-attestation-envelope.v1.json");

fn vectors() -> Value {
    let parsed: Value = serde_json::from_str(VECTORS).expect("the vectors parse");
    assert_eq!(
        parsed["schema"].as_str(),
        Some("guard-attestation-envelope-parity.v1")
    );
    parsed
}

#[test]
fn recorded_envelopes_are_accepted_or_refused_as_python_records() {
    let parsed = vectors();
    let cases = parsed["cases"].as_array().expect("cases");
    assert!(cases.len() >= 25, "{} cases", cases.len());
    let mut accepted = 0;

    for case in cases {
        let name = case["name"].as_str().expect("a name");
        let envelope = case["envelope"].as_object().expect("an envelope");
        let read = validated_trust_attestation_envelope(envelope);

        match (case.get("accepted"), case.get("error")) {
            (Some(expected), None) => {
                accepted += 1;
                let read = read.unwrap_or_else(|error| panic!("{name}: {error}"));
                assert_eq!(
                    Some(read.payload_hash.as_str()),
                    expected["payload_hash"].as_str(),
                    "{name}"
                );
                assert_eq!(
                    Some(read.signature_algorithm.as_str()),
                    expected["signature_algorithm"].as_str(),
                    "{name}"
                );
                assert_eq!(
                    Some(read.key_id.as_str()),
                    expected["key_id"].as_str(),
                    "{name}"
                );
                assert_eq!(
                    Some(read.public_key_pem.as_str()),
                    expected["public_key_pem"].as_str(),
                    "{name}"
                );
                assert_eq!(
                    Some(read.fingerprint_sha256.as_str()),
                    expected["fingerprint_sha256"].as_str(),
                    "{name}"
                );
                assert_eq!(
                    read.public_jwk_thumbprint.as_deref(),
                    expected["public_jwk_thumbprint"].as_str(),
                    "{name}"
                );
                assert_eq!(
                    Some(read.signature.as_str()),
                    expected["signature"].as_str(),
                    "{name}"
                );
                assert_eq!(
                    read.signed_at.as_deref(),
                    expected["signed_at"].as_str(),
                    "{name}"
                );
            }
            (None, Some(expected)) => {
                let error = read.expect_err(name);
                assert_eq!(Some(error.message()), expected.as_str(), "{name}");
            }
            _ => panic!("{name} records neither one verdict nor the other"),
        }
    }

    assert!(accepted >= 5, "{accepted} accepted");
}

#[test]
fn recorded_public_keys_fingerprint_the_way_python_fingerprints_them() {
    let parsed = vectors();
    let fingerprints = parsed["fingerprints"].as_array().expect("fingerprints");
    assert!(fingerprints.len() >= 4, "{} keys", fingerprints.len());

    for recorded in fingerprints {
        let pem = recorded["pem"].as_str().expect("a pem");
        assert_eq!(
            Some(normalize_pem(pem).as_str()),
            recorded["normalized"].as_str(),
            "{pem:?}"
        );
        assert_eq!(
            Some(public_key_fingerprint(pem).as_str()),
            recorded["fingerprint"].as_str(),
            "{pem:?}"
        );
    }
}

//! Replay recorded signature decisions through the Rust verifier.
//!
//! Every case in the fixture was produced by handing a real key, payload and
//! signature to Python's loader and `_verify_signature`, so an accepted case
//! was accepted by `cryptography` and a refusal is Python's own wording.

use base64ct::{Base64, Encoding};
use guard_command::attestation_signature::{
    load_attestation_public_key, verify_attestation_signature,
};
use serde_json::Value;

const FIXTURE: &str =
    include_str!("../../../../tests/fixtures/guard-attestation-signature.v1.json");

fn text<'a>(case: &'a Value, field: &str) -> &'a str {
    case.get(field)
        .and_then(Value::as_str)
        .unwrap_or_else(|| panic!("case is missing {field}"))
}

fn bytes(case: &Value, field: &str) -> Vec<u8> {
    Base64::decode_vec(text(case, field)).expect("recorded base64")
}

/// What the Rust half decides, in the vocabulary the fixture records.
fn decide(case: &Value) -> String {
    let public_key = match load_attestation_public_key(text(case, "public_key_pem")) {
        Ok(public_key) => public_key,
        Err(error) => return error.message().to_owned(),
    };
    match verify_attestation_signature(
        &public_key,
        &bytes(case, "canonical_payload_base64"),
        &bytes(case, "signature_base64"),
        text(case, "signature_algorithm"),
    ) {
        Ok(()) => "ok".to_owned(),
        Err(error) => error.message().to_owned(),
    }
}

#[test]
fn recorded_signature_decisions_replay() {
    let document: Value = serde_json::from_str(FIXTURE).expect("fixture parses");
    assert_eq!(
        document["schema"], "guard-attestation-signature-parity.v1",
        "fixture schema moved"
    );
    let cases = document["cases"].as_array().expect("cases");
    assert!(!cases.is_empty(), "fixture records no cases");
    let mut accepted = 0usize;
    for case in cases {
        let name = text(case, "name");
        assert_eq!(
            decide(case),
            text(case, "expected"),
            "case {name} disagrees with Python"
        );
        if text(case, "expected") == "ok" {
            accepted += 1;
        }
    }
    assert!(
        accepted >= 2,
        "the fixture must keep recording signatures that verify"
    );
}

/// Python signs with the longest salt the modulus allows, but
/// `padding.PSS.MAX_LENGTH` reads as "whatever the encoding says" on the
/// verifying side, so it accepts a PSS-SHA-256 signature made under any salt
/// length. A verifier that only knew the longest salt would refuse the
/// salt-equals-digest signatures other signers produce by default, so the
/// fixture has to keep carrying them.
#[test]
fn the_fixture_keeps_salt_lengths_other_than_the_longest() {
    let document: Value = serde_json::from_str(FIXTURE).expect("fixture parses");
    let cases = document["cases"].as_array().expect("cases");
    let outcome = |wanted: &str| -> Option<&str> {
        cases
            .iter()
            .find(|case| text(case, "name") == wanted)
            .map(|case| text(case, "expected"))
    };
    for name in [
        "rsa-2048-salt-equals-digest",
        "rsa-2048-salt-zero",
        "rsa-2048-salt-sixteen",
        "rsa-3072-salt-equals-digest",
    ] {
        assert_eq!(
            outcome(name),
            Some("ok"),
            "the fixture must keep accepting {name}"
        );
    }
    assert_eq!(
        outcome("rsa-2048-salt-equals-digest-wrong-payload"),
        Some("Trust attestation signature verification failed"),
        "a recovered salt length must not let other bytes through"
    );
}

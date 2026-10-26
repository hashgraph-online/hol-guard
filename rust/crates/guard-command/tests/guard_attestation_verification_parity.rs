//! Replay recorded verifier decisions through the Rust checks.
//!
//! Every case in the fixture was produced by driving Python's
//! `verify_trust_attestation` with a real signed attestation, so the replay
//! identity an accepted case carries is the one Python returned and a refusal
//! is Python's own wording.

use std::collections::BTreeSet;

use guard_command::attestation_envelope::{
    payload_with_signed_at, validated_trust_attestation_envelope,
};
use guard_command::attestation_payload::{validate_attestation_payload, AttestationPayloadRules};
use guard_command::attestation_verification::{
    trust_attestation_under_signature, TrustAttestationVerificationKey,
    TrustAttestationVerificationPolicy,
};
use serde_json::{Map, Value};

const FIXTURE: &str =
    include_str!("../../../../tests/fixtures/guard-attestation-verification.v1.json");

fn text(value: &Value, field: &str) -> Option<String> {
    value.get(field).and_then(Value::as_str).map(str::to_owned)
}

fn verification_key(value: &Value) -> TrustAttestationVerificationKey {
    TrustAttestationVerificationKey {
        key_id: text(value, "key_id").expect("key_id"),
        public_key_pem: text(value, "public_key_pem").expect("public_key_pem"),
        fingerprint_sha256: text(value, "fingerprint_sha256").expect("fingerprint_sha256"),
        public_jwk_thumbprint: text(value, "public_jwk_thumbprint"),
    }
}

fn verification_policy(value: &Value) -> TrustAttestationVerificationPolicy {
    let strings = |field: &str| -> BTreeSet<String> {
        value
            .get(field)
            .and_then(Value::as_array)
            .map(|entries| {
                entries
                    .iter()
                    .filter_map(Value::as_str)
                    .map(str::to_owned)
                    .collect()
            })
            .unwrap_or_default()
    };
    TrustAttestationVerificationPolicy {
        revoked_key_ids: strings("revoked_key_ids"),
        key_not_before: value
            .get("key_not_before")
            .and_then(Value::as_object)
            .map(|entries| {
                entries
                    .iter()
                    .filter_map(|(key, activated_at)| {
                        Some((key.clone(), activated_at.as_str()?.to_owned()))
                    })
                    .collect()
            })
            .unwrap_or_default(),
        minimum_sequence: value.get("minimum_sequence").and_then(Value::as_i64),
        seen_replay_keys: strings("seen_replay_keys"),
        now: text(value, "now"),
        require_nonce: value
            .get("require_nonce")
            .and_then(Value::as_bool)
            .unwrap_or_default(),
    }
}

fn cases() -> Vec<Value> {
    let document: Value = serde_json::from_str(FIXTURE).expect("fixture parses");
    document
        .get("cases")
        .and_then(Value::as_array)
        .expect("cases")
        .clone()
}

#[test]
fn recorded_attestations_are_accepted_or_refused_as_python_records() {
    let cases = cases();
    assert!(cases.len() >= 25, "the fixture lost cases");
    let mut accepted = 0;
    for case in &cases {
        let name = case
            .get("name")
            .and_then(Value::as_str)
            .unwrap_or("unnamed");
        let payload = case.get("payload").and_then(Value::as_object).expect(name);
        let envelope = validated_trust_attestation_envelope(
            case.get("envelope").and_then(Value::as_object).expect(name),
        )
        .unwrap_or_else(|refusal| panic!("{name}: {refusal}"));
        let claim = case.get("claim").and_then(Value::as_object);
        let trusted_keys: Option<Vec<TrustAttestationVerificationKey>> = case
            .get("trusted_keys")
            .and_then(Value::as_array)
            .map(|keys| keys.iter().map(verification_key).collect());
        let policy = verification_policy(case.get("policy").expect(name));

        let outcome = trust_attestation_under_signature(
            payload,
            &envelope,
            claim,
            trusted_keys.as_deref(),
            &policy,
        );
        match (case.get("replay_key"), case.get("error")) {
            (Some(Value::String(replay_key)), None) => {
                accepted += 1;
                let verified = outcome.unwrap_or_else(|refusal| panic!("{name}: {refusal}"));
                assert_eq!(&verified.replay_key, replay_key, "{name}");
                assert!(!verified.canonical_payload.is_empty(), "{name}");
            }
            (None, Some(Value::String(message))) => {
                let refusal = outcome.expect_err(name);
                assert_eq!(refusal.message(), message, "{name}");
            }
            _ => panic!("{name}: the case records neither a replay key nor a refusal"),
        }
    }
    assert!(accepted >= 8, "the fixture lost its accepted cases");
}

#[test]
fn the_canonical_payload_a_verifier_hands_on_is_what_the_envelope_hashed() {
    let mut checked = 0;
    for case in &cases() {
        let Some(Value::String(_)) = case.get("replay_key") else {
            continue;
        };
        let name = case
            .get("name")
            .and_then(Value::as_str)
            .unwrap_or("unnamed");
        let payload: &Map<String, Value> =
            case.get("payload").and_then(Value::as_object).expect(name);
        let envelope = validated_trust_attestation_envelope(
            case.get("envelope").and_then(Value::as_object).expect(name),
        )
        .unwrap_or_else(|refusal| panic!("{name}: {refusal}"));
        let policy = verification_policy(case.get("policy").expect(name));
        let trusted_keys: Option<Vec<TrustAttestationVerificationKey>> = case
            .get("trusted_keys")
            .and_then(Value::as_array)
            .map(|keys| keys.iter().map(verification_key).collect());
        let verified = trust_attestation_under_signature(
            payload,
            &envelope,
            case.get("claim").and_then(Value::as_object),
            trusted_keys.as_deref(),
            &policy,
        )
        .unwrap_or_else(|refusal| panic!("{name}: {refusal}"));
        // The bytes cover the payload the verifier read, which is the one the
        // envelope's signing time and the payload rules produced — not the one
        // the attestation happened to arrive carrying.
        let read = validate_attestation_payload(
            &payload_with_signed_at(payload, &envelope),
            AttestationPayloadRules::SIGNED,
        )
        .unwrap_or_else(|refusal| panic!("{name}: {refusal}"));
        assert_eq!(
            guard_command::evidence_hash::canonical_guard_evidence_payload(&read),
            verified.canonical_payload,
            "{name}"
        );
        checked += 1;
    }
    assert!(checked >= 8, "no accepted case carried canonical bytes");
}

#[test]
fn the_fixture_keeps_an_envelope_that_overrides_the_payloads_signing_time() {
    // The twin of the Python guard: a fixture whose envelopes always agreed
    // with their payloads could not tell a verifier reading the right time
    // from one reading the payload's own.
    let overridden: Vec<Value> = cases()
        .into_iter()
        .filter(|case| {
            case.get("envelope")
                .and_then(|envelope| envelope.get("signedAt"))
                != case
                    .get("payload")
                    .and_then(|payload| payload.get("signedAt"))
        })
        .collect();
    assert!(
        !overridden.is_empty(),
        "no case records an envelope that moves the signing time"
    );
    assert!(
        overridden
            .iter()
            .any(|case| matches!(case.get("replay_key"), Some(Value::String(_)))),
        "no accepted case records an envelope that moves the signing time"
    );
}

//! Replay recorded end-to-end verifier decisions through the Rust composition.
//!
//! Every case was produced by handing a real signed attestation to Python's
//! `verify_trust_attestation`, so an accepted case carries the replay identity
//! Python returned and a refusal carries Python's own wording. Two refusals
//! are Python's libraries speaking rather than Python itself; those cases
//! record `rust_error` instead, which `attestation_verify` documents.

use std::collections::{BTreeMap, BTreeSet};

use guard_command::attestation_verification::{
    TrustAttestationVerificationKey, TrustAttestationVerificationPolicy,
};
use guard_command::attestation_verify::verify_trust_attestation;
use serde_json::{Map, Value};

const FIXTURE: &str =
    include_str!("../../../../tests/fixtures/guard-trust-attestation-verify.v1.json");

fn text(value: &Value, field: &str) -> Option<String> {
    value.get(field).and_then(Value::as_str).map(str::to_owned)
}

fn object(value: &Value, field: &str) -> Option<Map<String, Value>> {
    value.get(field).and_then(Value::as_object).cloned()
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
                    .filter_map(|entry| entry.as_str().map(str::to_owned))
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
                    .collect::<BTreeMap<String, String>>()
            })
            .unwrap_or_default(),
        minimum_sequence: value.get("minimum_sequence").and_then(Value::as_i64),
        seen_replay_keys: strings("seen_replay_keys"),
        now: text(value, "now"),
        require_nonce: value
            .get("require_nonce")
            .and_then(Value::as_bool)
            .unwrap_or(true),
    }
}

/// What this side decides, in the vocabulary the fixture records.
fn decide(case: &Value) -> Result<String, String> {
    let payload = object(case, "payload").expect("payload");
    let envelope = object(case, "envelope").expect("envelope");
    let claim = object(case, "claim");
    let trusted_keys = case
        .get("trusted_keys")
        .and_then(Value::as_array)
        .map(|entries| entries.iter().map(verification_key).collect::<Vec<_>>());
    let policy = verification_policy(case.get("policy").expect("policy"));
    verify_trust_attestation(
        &payload,
        &envelope,
        claim.as_ref(),
        trusted_keys.as_deref(),
        &policy,
    )
    .map_err(|error| error.message().to_owned())
}

#[test]
fn recorded_verifier_decisions_replay() {
    let document: Value = serde_json::from_str(FIXTURE).expect("fixture parses");
    assert_eq!(
        document["schema"], "guard-trust-attestation-verify-parity.v1",
        "fixture schema moved"
    );
    let cases = document["cases"].as_array().expect("cases");
    let mut accepted = 0usize;
    // A refusal Python words through a library may be reached from more than
    // one case, so the replay counts the distinct wordings rather than cases.
    let mut divergent = std::collections::BTreeSet::new();
    for case in cases {
        let name = text(case, "name").expect("name");
        // `rust_error` marks a refusal Python words through a library; the
        // fixture records this side's wording for it instead.
        let expected = match (text(case, "replay_key"), text(case, "rust_error")) {
            (Some(replay_key), _) => Ok(replay_key),
            (None, Some(rust_error)) => {
                divergent.insert(rust_error.clone());
                Err(rust_error)
            }
            (None, None) => Err(text(case, "error").expect("a case records an outcome")),
        };
        accepted += usize::from(expected.is_ok());
        assert_eq!(decide(case), expected, "case {name} disagrees with Python");
    }
    assert!(
        accepted >= 4,
        "the fixture must keep recording attestations that verify"
    );
    assert!(
        divergent.len() == 2,
        "the two refusals Python words through a library are no longer recorded"
    );
    assert!(
        cases.len() >= 25,
        "the fixture stopped covering the whole chain"
    );
}

//! Replay recorded attestations through the resident operation.
//!
//! The decisions themselves are already pinned against Python in
//! `guard-command`'s parity suite. What is checked here is the transport: the
//! caller's verifier state reaches the verifier intact, an accepted
//! attestation comes back with the replay identity, a refused one comes back
//! as a refusal rather than an error, and the reply names the request it
//! answered.

use guard_contracts::{
    TRUST_ATTESTATION_VERIFY_REQUEST_SCHEMA, TRUST_ATTESTATION_VERIFY_RESULT_SCHEMA,
};
use serde_json::Value;

use super::*;

const FIXTURE: &str =
    include_str!("../../../../tests/fixtures/guard-trust-attestation-verify.v1.json");

fn recorded(name: &str) -> Value {
    let fixture: Value = serde_json::from_str(FIXTURE).expect("fixture json");
    fixture["cases"]
        .as_array()
        .expect("cases")
        .iter()
        .find(|case| case["name"] == name)
        .unwrap_or_else(|| panic!("no recorded case named {name}"))
        .clone()
}

fn request(name: &str) -> TrustAttestationVerifyRequestV1 {
    let case = recorded(name);
    let field = |field: &str| case.get(field).cloned().unwrap_or(Value::Null);
    TrustAttestationVerifyRequestV1 {
        schema: TRUST_ATTESTATION_VERIFY_REQUEST_SCHEMA.to_owned(),
        request_id: "attestation-1".to_owned(),
        payload: serde_json::from_value(field("payload")).expect("payload"),
        envelope: serde_json::from_value(field("envelope")).expect("envelope"),
        claim: serde_json::from_value(field("claim")).expect("claim"),
        trusted_keys: serde_json::from_value(field("trusted_keys")).expect("trusted keys"),
        policy: serde_json::from_value(field("policy")).expect("policy"),
    }
}

fn reply(request: &TrustAttestationVerifyRequestV1) -> Value {
    let encoded = evaluate_trust_attestation_verify_request(request).expect("reply");
    let reply: Value = serde_json::from_slice(&encoded).expect("reply json");
    assert_eq!(reply["schema"], TRUST_ATTESTATION_VERIFY_RESULT_SCHEMA);
    assert_eq!(reply["request_id"], "attestation-1");
    assert_eq!(reply["status"], "ok");
    assert_eq!(reply["code"], "ok");
    reply
}

#[test]
fn an_accepted_attestation_comes_back_with_its_replay_identity() {
    let name = "an ecdsa attestation its verifier trusts is accepted";
    let reply = reply(&request(name));

    assert_eq!(reply["payload"]["outcome"], "verified");
    assert_eq!(reply["payload"]["replay_key"], recorded(name)["replay_key"]);
}

#[test]
fn a_caller_that_lists_no_key_still_reaches_the_verifier() {
    let name = "a verifier with no key list accepts the key the envelope ships";
    let request = request(name);
    assert!(request.trusted_keys.is_none());

    let reply = reply(&request);

    assert_eq!(reply["payload"]["outcome"], "verified");
    assert_eq!(reply["payload"]["replay_key"], recorded(name)["replay_key"]);
}

#[test]
fn a_refused_attestation_comes_back_as_a_refusal_not_an_error() {
    let name = "a key the verifier does not list is refused";
    let reply = reply(&request(name));

    assert_eq!(reply["payload"]["outcome"], "refused");
    assert_eq!(reply["payload"]["message"], recorded(name)["error"]);
    assert!(reply["payload"].get("replay_key").is_none());
}

#[test]
fn the_verifier_state_the_caller_sent_decides_the_answer() {
    let name = "an ecdsa attestation its verifier trusts is accepted";
    let mut request = request(name);
    let key_id = request.trusted_keys.as_ref().expect("trusted keys")[0]
        .key_id
        .clone();
    request.policy.revoked_key_ids = vec![key_id];

    let reply = reply(&request);

    assert_eq!(reply["payload"]["outcome"], "refused");
    assert_eq!(
        reply["payload"]["message"],
        "Trust attestation key is revoked"
    );
}

#[test]
fn the_reply_names_the_request_it_answered() {
    let name = "an ecdsa attestation its verifier trusts is accepted";
    let request = request(name);
    let digest = reply(&request)["request_sha256"]
        .as_str()
        .expect("request digest")
        .to_owned();
    assert!(digest.starts_with("sha256:"), "{digest}");

    let mut other = request;
    other.request_id = "attestation-2".to_owned();
    let encoded = evaluate_trust_attestation_verify_request(&other).expect("reply");
    let other: Value = serde_json::from_slice(&encoded).expect("reply json");

    assert_ne!(other["request_sha256"].as_str().expect("digest"), digest);
}

#[test]
fn the_feature_is_advertised() {
    assert!(crate::resident_op_features::RESIDENT_OP_FEATURES
        .contains(&guard_contracts::TRUST_ATTESTATION_VERIFY_FEATURE));
}

#[test]
fn the_operation_is_reachable_under_the_name_the_bridge_sends() {
    let request = request("an ecdsa attestation its verifier trusts is accepted");
    let wire = serde_json::json!({
        "operation": "trust_attestation_verify",
        "request": serde_json::to_value(&request).expect("request json"),
    });

    let decoded: crate::resident_protocol::ResidentOperationV1 =
        serde_json::from_value(wire).expect("operation");

    assert!(matches!(
        decoded,
        crate::resident_protocol::ResidentOperationV1::TrustAttestationVerify(_)
    ));
}

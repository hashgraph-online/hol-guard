use super::*;
use base64ct::{Base64UrlUnpadded, Encoding};
use serde_json::json;

const KEY: &[u8] = b"command-envelope-test-key";
const OTHER_KEY: &[u8] = b"command-envelope-other-key";
const KEY_ID: &str = "key-1";

fn request(action: &str, payload: Value) -> CommandEnvelopeRequestV1 {
    CommandEnvelopeRequestV1 {
        schema: COMMAND_ENVELOPE_REQUEST_SCHEMA.to_owned(),
        request_id: "request-1".to_owned(),
        action: action.to_owned(),
        payload,
        integrity_key_b64: Some(Base64UrlUnpadded::encode_string(KEY)),
        integrity_key_id: Some(KEY_ID.to_owned()),
    }
}

fn grant() -> Value {
    json!({
        "version": 1,
        "issuer": "local-cli",
        "approvedAt": "2026-03-01T00:00:00+00:00",
        "identity": {"id": "job-1", "operation": "guard.app.remove"},
    })
}

fn signed_grant() -> Value {
    evaluate(&request(COMMAND_ENVELOPE_ACTION_SIGN, grant()))["result"].clone()
}

fn reason(answer: &Value) -> String {
    answer["reason"].as_str().unwrap_or_default().to_owned()
}

#[test]
fn signing_stamps_the_key_id_and_a_verifiable_signature() {
    let answer = evaluate(&request(COMMAND_ENVELOPE_ACTION_SIGN, grant()));
    assert_eq!(answer["accepted"], Value::Bool(true));
    let signed = &answer["result"];
    assert_eq!(signed["keyId"], Value::from(KEY_ID));
    assert_eq!(signed["issuer"], Value::from("local-cli"));
    assert!(signed["signature"]
        .as_str()
        .is_some_and(|value| value.len() == 64));
    let verified = evaluate(&request(COMMAND_ENVELOPE_ACTION_VERIFY, signed.clone()));
    assert_eq!(verified["accepted"], Value::Bool(true));
    assert_eq!(verified["result"]["identity"], grant()["identity"]);
    assert_eq!(verified["result"].get("signature"), None);
}

#[test]
fn signing_is_the_same_hmac_the_capability_envelope_uses() {
    // The approval grants and the capability share one key and one canonical
    // encoding, so a grant signed here verifies through the capability op's
    // own envelope check.
    let signed = signed_grant();
    let unsigned = verify_signed_envelope(
        &signed,
        Some(&Base64UrlUnpadded::encode_string(KEY)),
        Some(KEY_ID),
    )
    .expect("verified");
    assert_eq!(unsigned.get("keyId"), Some(&Value::from(KEY_ID)));
}

#[test]
fn a_tampered_grant_is_refused_rather_than_accepted() {
    let mut signed = signed_grant();
    signed["issuer"] = Value::from("attacker");
    let answer = evaluate(&request(COMMAND_ENVELOPE_ACTION_VERIFY, signed));
    assert_eq!(answer["accepted"], Value::Bool(false));
    assert_eq!(reason(&answer), "signed_payload_invalid_signature");
    assert_eq!(answer["result"], Value::Null);
}

#[test]
fn a_grant_signed_under_another_key_is_refused() {
    let signed = signed_grant();
    let mut other = request(COMMAND_ENVELOPE_ACTION_VERIFY, signed);
    other.integrity_key_b64 = Some(Base64UrlUnpadded::encode_string(OTHER_KEY));
    assert_eq!(
        reason(&evaluate(&other)),
        "signed_payload_invalid_signature"
    );
}

#[test]
fn a_grant_naming_another_key_id_is_refused_before_the_hmac() {
    let signed = signed_grant();
    let mut other = request(COMMAND_ENVELOPE_ACTION_VERIFY, signed);
    other.integrity_key_id = Some("key-2".to_owned());
    assert_eq!(reason(&evaluate(&other)), "signed_payload_key_mismatch");
}

#[test]
fn missing_envelope_fields_report_the_python_codes() {
    assert_eq!(
        reason(&evaluate(&request(
            COMMAND_ENVELOPE_ACTION_VERIFY,
            Value::Null
        ))),
        "signed_payload_missing"
    );
    assert_eq!(
        reason(&evaluate(&request(COMMAND_ENVELOPE_ACTION_VERIFY, grant()))),
        "signed_payload_missing_signature"
    );
}

#[test]
fn a_caller_without_a_key_cannot_sign_or_verify() {
    let mut keyless = request(COMMAND_ENVELOPE_ACTION_SIGN, grant());
    keyless.integrity_key_b64 = None;
    assert_eq!(reason(&evaluate(&keyless)), "local_signing_key_unavailable");
    let mut keyless = request(COMMAND_ENVELOPE_ACTION_VERIFY, signed_grant());
    keyless.integrity_key_id = None;
    assert_eq!(reason(&evaluate(&keyless)), "local_signing_key_unavailable");
}

#[test]
fn digesting_an_identity_needs_no_key_and_is_stable() {
    let identity = json!({"id": "job-1", "operation": "guard.app.remove"});
    let mut keyless = request(COMMAND_ENVELOPE_ACTION_DIGEST, identity.clone());
    keyless.integrity_key_b64 = None;
    keyless.integrity_key_id = None;
    let answer = evaluate(&keyless);
    assert_eq!(answer["accepted"], Value::Bool(true));
    let digest = answer["result"].as_str().expect("digest").to_owned();
    // Key order never changes the digest: the canonical encoding sorts keys.
    let reordered = json!({"operation": "guard.app.remove", "id": "job-1"});
    assert_eq!(
        evaluate(&request(COMMAND_ENVELOPE_ACTION_DIGEST, reordered))["result"],
        Value::from(digest.clone())
    );
    assert_eq!(digest, envelope_digest(&identity).expect("digest"));
}

#[test]
fn another_contract_or_action_is_refused_without_a_verdict() {
    let mut foreign = request(COMMAND_ENVELOPE_ACTION_SIGN, grant());
    foreign.schema = "guard-command-capability-request.v1".to_owned();
    assert_eq!(
        refusal(&foreign),
        Some("native_command_envelope_schema_mismatch")
    );
    let unknown = request("mint", grant());
    assert_eq!(
        refusal(&unknown),
        Some("native_command_envelope_action_unsupported")
    );
}

#[test]
fn the_reply_binds_its_request_without_covering_the_key() {
    let request = request(COMMAND_ENVELOPE_ACTION_SIGN, grant());
    let encoded = evaluate_command_envelope_request(&request).expect("response");
    let response: CommandEnvelopeResultV1 = serde_json::from_slice(&encoded).expect("decode");
    assert_eq!(response.schema, COMMAND_ENVELOPE_RESULT_SCHEMA);
    assert_eq!(response.request_id, "request-1");
    assert_eq!(response.status, "ok");
    assert_eq!(response.code, "ok");
    let mut other_key = request.clone();
    other_key.integrity_key_b64 = Some(Base64UrlUnpadded::encode_string(OTHER_KEY));
    let encoded = evaluate_command_envelope_request(&other_key).expect("response");
    let rotated: CommandEnvelopeResultV1 = serde_json::from_slice(&encoded).expect("decode");
    assert_eq!(rotated.request_sha256, response.request_sha256);
    let mut other_payload = request.clone();
    other_payload.payload = json!({"version": 2});
    let encoded = evaluate_command_envelope_request(&other_payload).expect("response");
    let moved: CommandEnvelopeResultV1 = serde_json::from_slice(&encoded).expect("decode");
    assert_ne!(moved.request_sha256, response.request_sha256);
}

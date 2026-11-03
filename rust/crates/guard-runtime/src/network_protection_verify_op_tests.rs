//! The operation's answers over a bundle a separate producer signed, so the
//! canonical payload, its hash and RSA-PSS-SHA256 are agreed across
//! implementations rather than only within this one. The signature covers the
//! bundle object alone, so the keyring cases change the envelope around it
//! without invalidating it.

use guard_contracts::{
    NetworkProtectionVerifyRequestV1, NetworkProtectionVerifyResultV1,
    NETWORK_PROTECTION_VERIFY_REQUEST_SCHEMA, NETWORK_PROTECTION_VERIFY_RESULT_SCHEMA,
};
use serde_json::{json, Value};

use super::evaluate_network_protection_verify_request;

const VECTOR_JSON: &str =
    include_str!("../../../../tests/fixtures/network-protection-bundle-producer-vector.v1.json");

fn vector() -> Value {
    serde_json::from_str(VECTOR_JSON).expect("producer vector parses")
}

fn verify_at() -> f64 {
    vector()["verify_at_epoch_seconds"]
        .as_f64()
        .expect("vector carries a verification time")
}

fn workspace_id() -> String {
    vector()["workspace_id"]
        .as_str()
        .expect("vector names its workspace")
        .to_owned()
}

fn response() -> Value {
    vector()["response"].clone()
}

fn advertised_keys(response: &Value) -> Value {
    response["verificationKeys"].clone()
}

fn request(response: Value, trusted_keys: Option<Value>) -> NetworkProtectionVerifyRequestV1 {
    NetworkProtectionVerifyRequestV1 {
        schema: NETWORK_PROTECTION_VERIFY_REQUEST_SCHEMA.to_owned(),
        request_id: "network-protection-verify-test".to_owned(),
        response,
        workspace_id: workspace_id(),
        trusted_keys,
        cached_bundle_version: None,
        now: Some(verify_at()),
    }
}

fn result(request: &NetworkProtectionVerifyRequestV1) -> NetworkProtectionVerifyResultV1 {
    let bytes = evaluate_network_protection_verify_request(request).expect("the operation answers");
    let parsed: NetworkProtectionVerifyResultV1 =
        serde_json::from_slice(&bytes).expect("the reply parses");
    assert_eq!(parsed.schema, NETWORK_PROTECTION_VERIFY_RESULT_SCHEMA);
    assert_eq!(parsed.request_id, request.request_id);
    assert_eq!(parsed.status, "ok");
    assert_eq!(parsed.code, "ok");
    assert!(parsed.request_sha256.starts_with("sha256:"));
    parsed
}

fn refusal(request: &NetworkProtectionVerifyRequestV1) -> String {
    let payload = result(request).payload;
    assert_eq!(payload["outcome"], "refused", "expected a refusal");
    payload["message"]
        .as_str()
        .expect("a refusal carries the message the caller raises")
        .to_owned()
}

#[test]
fn accepts_the_producer_signed_bundle_under_its_own_keyring() {
    let response = response();
    let keys = advertised_keys(&response);

    let payload = result(&request(response.clone(), Some(keys))).payload;

    assert_eq!(payload["outcome"], "verified");
    // The bundle object stays with the caller that sent it; the reply names it
    // by the hash this verifier computed over it.
    assert!(payload["saved"].get("bundle").is_none());
    assert_eq!(payload["saved"]["payloadHash"], response["payloadHash"]);
    assert_eq!(payload["saved"]["keyId"], json!("network-producer-key"));
    assert_eq!(
        payload["saved"]["expiresAtEpoch"],
        json!(verify_at() as i64 + 6 * 3_600)
    );
}

#[test]
fn reads_a_keyring_saved_in_its_envelope_form() {
    let response = response();
    let keyring = json!({ "keys": advertised_keys(&response) });

    let payload = result(&request(response, Some(keyring))).payload;

    assert_eq!(payload["outcome"], "verified");
}

#[test]
fn refuses_a_bundle_the_caller_has_no_keyring_to_anchor() {
    // Unlike the supply-chain bundle, an absent keyring leaves the pinned
    // production fingerprint as the only anchor, so a test key is refused.
    let message = refusal(&request(response(), None));

    assert_eq!(
        message,
        "Network protection bundle signing key is not trusted"
    );
}

#[test]
fn refuses_a_payload_hash_that_does_not_cover_the_bundle() {
    let mut response = response();
    let keys = advertised_keys(&response);
    response["payloadHash"] = json!("0".repeat(64));

    let message = refusal(&request(response, Some(keys)));

    assert_eq!(
        message,
        "Network protection bundle payloadHash does not match its payload"
    );
}

#[test]
fn refuses_a_bundle_issued_for_another_workspace() {
    let response = response();
    let keys = advertised_keys(&response);
    let mut request = request(response, Some(keys));
    request.workspace_id = "workspace-somewhere-else".to_owned();

    let message = refusal(&request);

    assert_eq!(
        message,
        "Network protection bundle belongs to a different workspace"
    );
}

#[test]
fn refuses_a_bundle_older_than_the_one_already_saved() {
    let response = response();
    let keys = advertised_keys(&response);
    let mut request = request(response, Some(keys));
    request.cached_bundle_version = Some("network-9999999999999-0123456789abcdef".to_owned());

    assert!(refusal(&request).contains("is older than saved"));
}

#[test]
fn refuses_a_keyring_it_cannot_read_rather_than_falling_back() {
    let message = refusal(&request(response(), Some(json!(["not-a-key"]))));

    assert_eq!(message, "verificationKeys must contain objects");
}

#[test]
fn refuses_a_saved_keyring_envelope_that_carries_no_entries() {
    // The sync writes `{"workspace_id": ..., "keys": [...]}`, so an envelope
    // without a list of entries is a damaged row, not a device that has saved
    // nothing. Reading it as empty would hand trust back to the pinned
    // production fingerprint.
    let message = refusal(&request(
        response(),
        Some(json!({ "workspace_id": workspace_id() })),
    ));

    assert_eq!(message, "Saved network protection keyring is malformed");
}

#[test]
fn refuses_a_saved_keyring_whose_entries_are_not_a_list() {
    let message = refusal(&request(response(), Some(json!({ "keys": "none" }))));

    assert_eq!(message, "Saved network protection keyring is malformed");
}

#[test]
fn refuses_a_saved_keyring_that_is_not_an_envelope_at_all() {
    let message = refusal(&request(response(), Some(json!("corrupt"))));

    assert_eq!(message, "Saved network protection keyring is malformed");
}

#[test]
fn still_reads_an_envelope_that_lists_no_entries_as_an_empty_keyring() {
    // An empty list is a readable keyring: the workspace has revoked every
    // entry, and the pinned production fingerprint is the remaining anchor,
    // which the producer's test key does not match.
    let message = refusal(&request(response(), Some(json!({ "keys": [] }))));

    assert_eq!(
        message,
        "Network protection bundle signing key is not trusted"
    );
}

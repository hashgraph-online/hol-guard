//! Refusal classes the caller re-raises, over a bundle a separate producer
//! signed. The vector's signature covers only the bundle object, so the
//! keyring cases mutate the envelope around it without invalidating it.

use guard_contracts::{
    SupplyChainBundleVerifyRequestV1, SupplyChainBundleVerifyResultV1,
    SUPPLY_CHAIN_BUNDLE_VERIFY_REQUEST_SCHEMA, SUPPLY_CHAIN_BUNDLE_VERIFY_RESULT_SCHEMA,
};
use serde_json::{json, Value};

use super::evaluate_supply_chain_bundle_verify_request;

const VECTOR_JSON: &str =
    include_str!("../../../../tests/fixtures/supply-chain-bundle-producer-vector.v1.json");

fn vector() -> Value {
    serde_json::from_str(VECTOR_JSON).expect("producer vector parses")
}

fn verify_at() -> f64 {
    vector()["verify_at_epoch_seconds"]
        .as_f64()
        .expect("vector carries a verification time")
}

fn response() -> Value {
    vector()["response"].clone()
}

fn request(response: Value, trusted_keys: Option<Vec<Value>>) -> SupplyChainBundleVerifyRequestV1 {
    SupplyChainBundleVerifyRequestV1 {
        schema: SUPPLY_CHAIN_BUNDLE_VERIFY_REQUEST_SCHEMA.to_owned(),
        request_id: "supply-chain-bundle-verify-test".to_owned(),
        response,
        trusted_keys,
        cached_bundle_version: None,
        now: Some(verify_at()),
    }
}

fn advertised_keys(response: &Value) -> Vec<Value> {
    response["verificationKeys"]
        .as_array()
        .expect("vector advertises a keyring")
        .clone()
}

fn result(request: &SupplyChainBundleVerifyRequestV1) -> SupplyChainBundleVerifyResultV1 {
    let bytes =
        evaluate_supply_chain_bundle_verify_request(request).expect("the operation answers");
    let parsed: SupplyChainBundleVerifyResultV1 =
        serde_json::from_slice(&bytes).expect("the reply parses");
    assert_eq!(parsed.schema, SUPPLY_CHAIN_BUNDLE_VERIFY_RESULT_SCHEMA);
    assert_eq!(parsed.request_id, request.request_id);
    assert_eq!(parsed.status, "ok");
    assert_eq!(parsed.code, "ok");
    assert!(parsed.request_sha256.starts_with("sha256:"));
    parsed
}

fn refusal(request: &SupplyChainBundleVerifyRequestV1) -> (String, String) {
    let payload = result(request).payload;
    assert_eq!(payload["outcome"], "refused", "expected a refusal");
    (
        payload["kind"]
            .as_str()
            .expect("a refusal names its kind")
            .to_owned(),
        payload["message"]
            .as_str()
            .expect("a refusal carries the message the caller raises")
            .to_owned(),
    )
}

/// The summary a verified answer carries, read from the vector's own bundle.
fn expected_verified(response: &Value) -> Value {
    let bundle = &response["bundle"];
    json!({
        "outcome": "verified",
        "summary": {
            "bundle_version": bundle["bundleVersion"],
            "key_id": bundle["keyId"],
            "policy_hash": bundle["policyHash"],
            "tier": bundle["tier"],
            "feed_snapshot_hash": bundle["feedSnapshotHash"],
            "advisory_count": bundle["advisories"].as_array().expect("advisories").len(),
            "package_count": bundle["packages"].as_array().expect("packages").len(),
        },
    })
}

#[test]
fn accepts_the_producer_signed_bundle_under_its_own_keyring() {
    let response = response();
    let keys = advertised_keys(&response);
    let expected = expected_verified(&response);

    let payload = result(&request(response, Some(keys))).payload;

    assert_eq!(payload, expected);
}

#[test]
fn accepts_the_bundle_when_the_caller_holds_no_keyring_yet() {
    let response = response();
    let expected = expected_verified(&response);

    let payload = result(&request(response, None)).payload;

    assert_eq!(payload, expected);
}

#[test]
fn refuses_a_payload_hash_that_does_not_cover_the_bundle() {
    let mut response = response();
    response["payloadHash"] = json!("0".repeat(64));

    let (kind, message) = refusal(&request(response, None));

    assert_eq!(kind, "payload_hash");
    assert_eq!(
        message,
        "Bundle payloadHash does not match the canonical payload"
    );
}

#[test]
fn refuses_a_signing_key_that_is_not_anchored_to_the_trusted_keyring() {
    let response = response();
    let mut other = advertised_keys(&response)[0].clone();
    other["fingerprintSha256"] = json!("1".repeat(64));
    other["keyId"] = json!("some-other-key");

    let (kind, message) = refusal(&request(response, Some(vec![other])));

    assert_eq!(kind, "keyring");
    assert_eq!(
        message,
        "Bundle signing key is not anchored to the trusted keyring"
    );
}

#[test]
fn refuses_a_keyring_entry_whose_fingerprint_does_not_match_its_public_key() {
    let mut response = response();
    response["verificationKeys"][0]["fingerprintSha256"] = json!("2".repeat(64));

    let (kind, message) = refusal(&request(response, None));

    assert_eq!(kind, "keyring");
    assert_eq!(
        message,
        "Verification key fingerprint does not match its public key"
    );
}

#[test]
fn refuses_a_bundle_whose_key_id_is_absent_from_the_advertised_keyring() {
    let mut response = response();
    response["verificationKeys"][0]["keyId"] = json!("a-key-the-bundle-was-not-signed-with");

    let (kind, message) = refusal(&request(response, None));

    assert_eq!(kind, "keyring");
    assert_eq!(
        message,
        "Bundle keyId is not present in the advertised verification keyring"
    );
}

#[test]
fn refuses_a_revoked_signing_key() {
    let mut response = response();
    response["verificationKeys"][0]["state"] = json!("revoked");

    let (kind, message) = refusal(&request(response, None));

    assert_eq!(kind, "keyring");
    assert_eq!(
        message,
        "Revoked verification key cannot sign supply-chain bundles"
    );
}

#[test]
fn refuses_a_grace_signing_key_past_its_validity() {
    let mut response = response();
    response["verificationKeys"][0]["state"] = json!("grace");
    response["verificationKeys"][0]["validUntil"] = json!("2020-01-01T00:00:00.000Z");

    let (kind, message) = refusal(&request(response, None));

    assert_eq!(kind, "keyring");
    assert_eq!(message, "Grace verification key is expired");
}

#[test]
fn refuses_a_signature_that_does_not_cover_the_canonical_payload() {
    let mut response = response();
    let signature = response["signature"]
        .as_str()
        .expect("the vector is signed")
        .to_owned();
    let flipped = if signature.starts_with('A') { 'B' } else { 'A' };
    response["signature"] = json!(format!("{flipped}{}", &signature[1..]));

    let (kind, message) = refusal(&request(response, None));

    assert_eq!(kind, "signature");
    assert_eq!(message, "Supply-chain bundle signature verification failed");
}

#[test]
fn refuses_a_bundle_older_than_the_version_the_caller_already_holds() {
    let mut request = request(response(), None);
    request.cached_bundle_version = Some("1892000000000-later01".to_owned());

    let (kind, message) = refusal(&request);

    assert_eq!(kind, "rollback");
    assert!(
        message.contains("is older than cached version"),
        "unexpected rollback wording: {message}"
    );
}

#[test]
fn refuses_a_bundle_whose_expiry_has_passed() {
    let mut request = request(response(), None);
    request.now = Some(verify_at() + 86_400.0 * 30.0);

    let (kind, message) = refusal(&request);

    assert_eq!(kind, "expired");
    assert!(
        message.starts_with("Bundle expired at "),
        "unexpected wording: {message}"
    );
}

#[test]
fn refuses_a_response_that_does_not_carry_a_supported_signature_algorithm() {
    let mut response = response();
    response["signatureAlgorithm"] = json!("hmac-sha256");

    let (kind, message) = refusal(&request(response, None));

    assert_eq!(kind, "malformed");
    assert_eq!(message, "Unsupported bundle signature algorithm");
}

#[test]
fn refuses_a_response_that_advertises_no_verification_keys() {
    let mut response = response();
    response["verificationKeys"] = json!([]);

    let (kind, message) = refusal(&request(response, None));

    assert_eq!(kind, "malformed");
    assert_eq!(message, "Bundle response must include verification keys");
}

#[test]
fn refuses_a_trusted_keyring_that_lists_no_keys() {
    // Not the bootstrap case: the caller declared a trust boundary, so it must
    // not receive a verified result for a bundle signed by the keyring the
    // response itself advertises.
    let (kind, message) = refusal(&request(response(), Some(Vec::new())));

    assert_eq!(kind, "keyring");
    assert_eq!(
        message,
        "Trusted keyring is present but lists no verification keys"
    );
}

#[test]
fn refuses_a_request_bearing_a_schema_this_resident_does_not_know() {
    let mut request = request(response(), None);
    request.schema = "guard-supply-chain-bundle-verify-request.v99".to_owned();

    let error = evaluate_supply_chain_bundle_verify_request(&request)
        .expect_err("an unknown request schema is refused, not interpreted");

    assert_eq!(error, "native_supply_chain_bundle_verify_schema_mismatch");
}

//! Verify a supply-chain bundle that an independent producer signed.
//!
//! The vector carries non-ASCII advisory text. The producer writes it as UTF-8
//! and sorts keys by code point, so the verifier's canonical bytes have to do
//! the same or the payload hash and the RSA-PSS signature both fail.

use guard_command::supply_chain_bundle::{
    canonical_supply_chain_bundle_payload, load_supply_chain_bundle_response,
    verify_supply_chain_bundle_response, RingRsaPssVerify, SupplyChainBundleError,
};
use serde_json::Value;

const VECTOR: &str =
    include_str!("../../../../tests/fixtures/supply-chain-bundle-producer-vector.v1.json");

fn vector() -> Value {
    serde_json::from_str(VECTOR).expect("vector parses")
}

fn verify_at(raw: &Value, now: f64) -> Result<(), SupplyChainBundleError> {
    let response = load_supply_chain_bundle_response(raw)?;
    let trusted = response.verification_keys.clone();
    verify_supply_chain_bundle_response(
        &response,
        Some(trusted.as_slice()),
        None,
        Some(now),
        &RingRsaPssVerify,
    )
}

fn verify_time(vector: &Value) -> f64 {
    vector["verify_at_epoch_seconds"]
        .as_f64()
        .expect("verify time is recorded")
}

#[test]
fn canonical_payload_keeps_non_ascii_text_as_utf8() {
    let vector = vector();
    let bundle = vector["response"]["bundle"].as_object().expect("bundle");

    let canonical = canonical_supply_chain_bundle_payload(bundle);

    assert_eq!(
        canonical,
        vector["canonical_payload_utf8"]
            .as_str()
            .expect("canonical payload")
            .as_bytes()
    );
    assert!(!String::from_utf8(canonical).expect("utf-8").contains("\\u"));
}

#[test]
fn string_escaping_matches_the_producer() {
    let vector = vector();
    let cases = vector["string_vectors"].as_array().expect("string vectors");
    assert!(!cases.is_empty());
    for case in cases {
        let text = case["text"].as_str().expect("text");
        let mut payload = serde_json::Map::new();
        payload.insert("text".to_owned(), Value::String(text.to_owned()));

        assert_eq!(
            canonical_supply_chain_bundle_payload(&payload),
            case["canonical"].as_str().expect("canonical").as_bytes(),
            "canonical bytes for {text:?}"
        );
    }
}

#[test]
fn verifier_accepts_a_producer_signed_bundle_with_non_ascii_advisories() {
    let vector = vector();

    assert_eq!(verify_at(&vector["response"], verify_time(&vector)), Ok(()));
}

#[test]
fn verifier_still_rejects_changed_text_under_the_producer_hash() {
    let vector = vector();
    let mut raw = vector["response"].clone();
    raw["bundle"]["advisories"][0]["title"] = Value::String("Creation de chemin".to_owned());

    assert!(matches!(
        verify_at(&raw, verify_time(&vector)),
        Err(SupplyChainBundleError::PayloadHash(_))
    ));
}

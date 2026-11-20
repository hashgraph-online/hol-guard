//! What the claim gate admits, and what the digest it hands back covers.

use serde_json::{json, Map, Value};

use super::evidence_hash::guard_evidence_hash;
use super::trust_claim::{
    trust_attestation_replay_key, trust_claim_hash, validated_local_trust_claim,
};

fn evidence() -> Value {
    json!({"deviceId": "device-7", "layers": [1, 2, 3]})
}

fn local_claim() -> Map<String, Value> {
    let evidence = evidence();
    let digest = guard_evidence_hash(evidence.as_object().expect("evidence object"));
    json!({
        "provenance": {
            "origin": "hol-guard-local",
            "verificationStatus": "locally_derived",
            "derivation": "native-scan",
        },
        "evidenceAuthority": "device_claim",
        "affectsV4Score": false,
        "capturedAt": "2026-10-23T12:00:00Z",
        "layerId": "layer-1",
        "layerType": "model",
        "resolutionSource": "local",
        "metadata": {
            "evidence": evidence,
            "evidenceHash": digest,
            "evidenceSchemaVersion": "guard-aibom-evidence.v1",
            "collector": "native",
        },
    })
    .as_object()
    .expect("claim object")
    .clone()
}

fn with_metadata(claim: &Map<String, Value>, key: &str, value: Value) -> Map<String, Value> {
    let mut updated = claim.clone();
    let mut metadata = updated["metadata"]
        .as_object()
        .expect("metadata object")
        .clone();
    metadata.insert(key.to_owned(), value);
    updated.insert("metadata".to_owned(), Value::Object(metadata));
    updated
}

#[test]
fn a_local_claim_is_named_by_its_digest() {
    let claim = local_claim();
    let digest = trust_claim_hash(&claim, true).expect("a local claim is admitted");
    assert_eq!(digest.len(), 64);
    assert!(digest
        .chars()
        .all(|character| character.is_ascii_hexdigit()));
}

#[test]
fn a_prior_attestation_does_not_change_the_name() {
    // The gate strips every prior attestation before hashing, so re-attesting
    // a claim cannot give the verifier a second name for the same claim.
    let claim = local_claim();
    let expected = trust_claim_hash(&claim, true).expect("admitted");
    for key in [
        "attestation",
        "attestationBindings",
        "attestationRef",
        "attestationVerification",
    ] {
        let carried = with_metadata(&claim, key, json!({"signature": "stale"}));
        assert_eq!(
            trust_claim_hash(&carried, true).expect("admitted"),
            expected,
            "{key} leaked into the claim name"
        );
    }
}

#[test]
fn the_normalized_claim_is_always_unsigned() {
    let signed = with_metadata(&local_claim(), "attestationStatus", json!("signed"));
    let normalized = validated_local_trust_claim(&Value::Object(signed), true).expect("admitted");
    assert_eq!(
        normalized["metadata"]["attestationStatus"],
        json!("unsigned")
    );
}

#[test]
fn evidence_has_to_hash_to_the_digest_it_advertises() {
    let tampered = with_metadata(&local_claim(), "evidenceHash", json!("0".repeat(64)));
    assert!(trust_claim_hash(&tampered, true).is_err());
    let unrelated = with_metadata(
        &local_claim(),
        "evidenceSchemaVersion",
        json!("guard-other.v1"),
    );
    assert!(trust_claim_hash(&unrelated, true).is_err());
}

#[test]
fn only_a_locally_derived_claim_is_admitted() {
    for (field, value) in [
        ("evidenceAuthority", json!("vendor_claim")),
        ("affectsV4Score", json!(true)),
        // `0` is not `False`; Python compares identity here.
        ("affectsV4Score", json!(0)),
        ("capturedAt", json!("2026-10-23T12:00:00")),
        ("provenance", json!({"origin": "hol-guard-cloud"})),
    ] {
        let mut claim = local_claim();
        claim.insert(field.to_owned(), value.clone());
        assert!(
            trust_claim_hash(&claim, true).is_err(),
            "{field}={value} was admitted"
        );
    }
}

#[test]
fn layer_identity_is_required_only_when_it_is_asked_for() {
    let mut claim = local_claim();
    claim.remove("layerId");
    claim.remove("layerType");
    assert!(trust_claim_hash(&claim, true).is_err());
    // Without layer identity the claim has to say it was resolved locally.
    assert!(trust_claim_hash(&claim, false).is_ok());
    claim.insert("resolutionSource".to_owned(), json!("remote"));
    assert!(trust_claim_hash(&claim, false).is_err());
}

#[test]
fn an_absent_replay_field_matches_an_explicit_null() {
    let present = json!({"nonce": "n-1", "itemId": "item-1"});
    let explicit = json!({
        "nonce": "n-1",
        "itemId": "item-1",
        "domainSeparator": null,
        "scope": null,
        "layerId": null,
        "workspaceId": null,
        "repositoryId": null,
    });
    assert_eq!(
        trust_attestation_replay_key(present.as_object().expect("object")),
        trust_attestation_replay_key(explicit.as_object().expect("object"))
    );
}

#[test]
fn a_field_outside_the_replay_identity_does_not_change_the_key() {
    let payload = json!({"nonce": "n-1", "itemId": "item-1"});
    let mut extended = payload.as_object().expect("object").clone();
    extended.insert("agentId".to_owned(), json!("agent-1"));
    assert_eq!(
        trust_attestation_replay_key(payload.as_object().expect("object")),
        trust_attestation_replay_key(&extended)
    );
}

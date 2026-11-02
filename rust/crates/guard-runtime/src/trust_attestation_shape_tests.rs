use guard_command::evidence_hash::guard_evidence_hash;
use serde_json::{json, Value};

use super::*;

fn local_claim() -> Value {
    let evidence = json!({"deviceId": "device-7", "layers": [1, 2, 3]});
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
            "attestation": {"signature": "stale"},
        },
    })
}

fn payload() -> Value {
    json!({
        "payloadVersion": "guard-aibom-trust-attestation.v3",
        "domainSeparator": "hol-guard:aibom-trust-attestation:v3",
        "agentId": " agent-1 ",
        "itemId": "item-1",
        "itemKind": "skill",
        "contentHash": "a",
        "capturedAt": "2026-10-23T12:00:00Z",
        "claimHash": "b",
        "evidenceHash": "c",
        "scope": "trust_resolution",
    })
}

fn payload_args(payload: Value, signed: bool) -> Value {
    json!({
        "op": "payload",
        "payload": payload,
        "require_signed_at": signed,
        "require_nonce": signed,
        "require_subject_bindings": signed,
    })
}

#[test]
fn admitted_claims_come_back_unsigned_with_their_hash() {
    let claim = local_claim();
    let answer = dispatch(&json!({
        "op": "claims",
        "resolution": claim,
        "layers": [claim, {"provenance": {"origin": "hol-guard-cloud"}}, "not a claim"],
    }))
    .expect("claims answer");

    let resolution = &answer["resolution"];
    assert_eq!(
        resolution["claim"]["metadata"]["attestationStatus"],
        "unsigned"
    );
    assert!(resolution["claim"]["metadata"].get("attestation").is_none());
    let expected = trust_claim_hash(local_claim().as_object().expect("claim"), false)
        .expect("local claim hash");
    assert_eq!(resolution["claim_hash"], expected);
    assert_eq!(answer["layers"].as_array().map(Vec::len), Some(1));
}

#[test]
fn a_refused_resolution_and_absent_layers_answer_empty() {
    let mut remote = local_claim();
    remote["resolutionSource"] = json!("remote");
    let answer = dispatch(&json!({"op": "claims", "resolution": remote, "layers": {}}))
        .expect("claims answer");
    assert_eq!(answer, json!({"resolution": null, "layers": []}));

    let answer = dispatch(&json!({"op": "claims"})).expect("claims answer");
    assert_eq!(answer, json!({"resolution": null, "layers": []}));
}

#[test]
fn a_claim_without_layer_identity_hashes_only_as_a_resolution() {
    let mut claim = local_claim();
    claim
        .as_object_mut()
        .expect("claim object")
        .remove("layerId");
    let as_resolution = dispatch(&json!({
        "op": "claim_hash", "claim": claim, "require_layer_identity": false,
    }))
    .expect("hash answer");
    assert!(as_resolution["claim_hash"].is_string());
    let as_layer = dispatch(&json!({
        "op": "claim_hash", "claim": claim, "require_layer_identity": true,
    }))
    .expect("hash answer");
    assert_eq!(as_layer, json!({"claim_hash": null}));
}

#[test]
fn an_accepted_payload_comes_back_normalized() {
    let answer = dispatch(&payload_args(payload(), false)).expect("payload answer");
    assert_eq!(answer["payload"]["agentId"], "agent-1");
}

#[test]
fn a_refused_payload_carries_the_signer_message() {
    let answer = dispatch(&payload_args(payload(), true)).expect("payload answer");
    let refused = answer["refused"].as_str().expect("refusal message");
    assert!(!refused.is_empty());
    assert!(answer.get("payload").is_none());
}

#[test]
fn malformed_requests_are_invalid() {
    for args in [
        json!([]),
        json!({"op": "unknown"}),
        json!({"op": "claim_hash", "claim": "x", "require_layer_identity": true}),
        json!({"op": "claim_hash", "claim": {}}),
        json!({"op": "payload", "payload": {}, "require_signed_at": false}),
        json!({"op": "payload", "payload": [], "require_signed_at": false,
               "require_nonce": false, "require_subject_bindings": false}),
    ] {
        assert_eq!(dispatch(&args), Err(ERR_INVALID), "{args}");
    }
}

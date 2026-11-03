use guard_command::evidence_hash::guard_evidence_hash;
use serde_json::{json, Map, Value};

use super::super::dispatch;
use super::{DEFAULT_POLICY_VERSION, DOMAIN_SEPARATOR};
use crate::runner_authority_op::ERR_INVALID;

fn local_claim(layer_id: &str) -> Value {
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
        "layerId": layer_id,
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

fn fields() -> Map<String, Value> {
    json!({
        "agent_id": "agent-1",
        "item_id": "item-1",
        "item_kind": "skill",
        "content_hash": "a",
        "nonce": "nonce-1",
        "policy_version": null,
        "analyzer_id": "analyzer",
        "analyzer_version": "1.0",
        "adapter_id": "adapter",
        "adapter_version": "2.0",
        "config_path_hash": "cfg",
        "repository_id": "repo",
        "sequence": 4,
        "challenge_id": null,
    })
    .as_object()
    .expect("fields object")
    .clone()
}

fn plan(fields: Map<String, Value>, layers: Value) -> Value {
    dispatch(&json!({
        "op": "sign_plan",
        "resolution": local_claim("layer-0"),
        "layers": layers,
        "fields": fields,
    }))
    .expect("plan answer")
}

#[test]
fn every_admitted_claim_gets_a_signed_payload_and_bindings() {
    let answer = plan(
        fields(),
        json!([local_claim("layer-1"), {"provenance": {}}, local_claim("layer-2")]),
    );
    assert_eq!(
        answer["resolution"]["metadata"]["attestationStatus"],
        "unsigned"
    );
    assert_eq!(answer["layers"].as_array().map(Vec::len), Some(2));
    let signing = answer["signing"].as_array().expect("signing entries");
    assert_eq!(signing.len(), 3);
    let layers: Vec<&Value> = signing.iter().map(|entry| &entry["layer"]).collect();
    assert_eq!(layers, [&Value::Null, &json!(0), &json!(1)]);

    let resolution = &signing[0];
    assert_eq!(resolution["signed_at"], "2026-10-23T12:00:00Z");
    let payload = &resolution["payload"];
    assert_eq!(payload["scope"], "trust_resolution");
    assert_eq!(payload["signedAt"], "2026-10-23T12:00:00Z");
    assert_eq!(payload["policyVersion"], DEFAULT_POLICY_VERSION);
    assert_eq!(payload["nonce"], "nonce-1");
    assert!(payload.get("layerId").is_none());
    assert!(payload.get("analyzerId").is_none());
    assert!(payload.get("challengeId").is_none());
    let bindings = &resolution["bindings"];
    assert_eq!(bindings["domainSeparator"], DOMAIN_SEPARATOR);
    assert_eq!(bindings["sequence"], 4);
    assert_eq!(bindings["claimHash"], payload["claimHash"]);
    assert_eq!(bindings["evidenceSchemaVersion"], "guard-aibom-evidence.v1");
    assert!(bindings.get("analyzerId").is_none());

    let layer = &signing[2]["payload"];
    assert_eq!(layer["scope"], "trust_layer");
    assert_eq!(layer["layerId"], "layer-2");
    assert_eq!(layer["layerType"], "model");
    assert_ne!(layer["claimHash"], payload["claimHash"]);
}

#[test]
fn analyzer_fields_are_bound_only_beside_a_workspace_or_device() {
    let mut fields = fields();
    fields.insert("workspace_id".into(), json!("ws-1"));
    fields.insert("policy_version".into(), json!("policy-9"));
    let answer = plan(fields, json!([]));
    let entry = &answer["signing"][0];
    assert_eq!(entry["payload"]["analyzerId"], "analyzer");
    assert_eq!(entry["payload"]["workspaceId"], "ws-1");
    assert_eq!(entry["payload"]["policyVersion"], "policy-9");
    assert_eq!(entry["bindings"]["analyzerId"], "analyzer");
    assert_eq!(entry["bindings"]["analyzerVersion"], "1.0");
    assert_eq!(entry["bindings"]["policyVersion"], "policy-9");
}

#[test]
fn a_payload_without_its_subject_bindings_is_refused_not_signed() {
    let mut fields = fields();
    fields.remove("adapter_id");
    let answer = plan(fields, json!([]));
    let entry = &answer["signing"][0];
    assert!(entry.get("payload").is_none());
    assert_eq!(
        entry["refused"],
        "Missing trust attestation subject bindings: adapterId"
    );
}

#[test]
fn a_plan_needs_a_nonce() {
    let mut fields = fields();
    fields.insert("nonce".into(), json!(""));
    let args = json!({"op": "sign_plan", "resolution": null, "fields": fields});
    assert_eq!(dispatch(&args), Err(ERR_INVALID));
    assert_eq!(
        dispatch(&json!({"op": "sign_plan", "resolution": null})),
        Err(ERR_INVALID)
    );
}

#[test]
fn build_spells_an_unsigned_payload() {
    let mut fields = fields();
    fields.insert("captured_at".into(), json!("2026-10-23T12:00:00Z"));
    fields.insert("evidence_hash".into(), json!("c"));
    fields.insert("claim_hash".into(), json!("d"));
    fields.insert("scope".into(), json!("trust_resolution"));
    let answer = dispatch(&json!({"op": "build", "fields": fields})).expect("build answer");
    let payload = &answer["payload"];
    assert_eq!(payload["domainSeparator"], DOMAIN_SEPARATOR);
    assert_eq!(payload["agentId"], "agent-1");
    assert_eq!(payload["analyzerId"], "analyzer");
    assert!(payload.get("policyVersion").is_none());
    assert!(payload.get("signedAt").is_none());

    fields.remove("scope");
    let answer = dispatch(&json!({"op": "build", "fields": fields})).expect("build answer");
    assert!(answer["refused"].is_string());
}

use guard_contracts::{
    InventoryItemClassificationRequestV1, InventoryItemClassificationResultV1,
    INVENTORY_ITEM_CLASSIFICATION_MAX_ENTRIES, INVENTORY_ITEM_CLASSIFICATION_REQUEST_SCHEMA,
    INVENTORY_ITEM_CLASSIFICATION_RESULT_SCHEMA, SKILL_DIRECTORY_IDENTITY_SCHEMA,
};
use serde_json::{json, Value};

use super::{evaluate_inventory_item_classification_request, evaluate_request, refusal};

const DIGEST: &str = "ab12cd34ef56ab12cd34ef56ab12cd34ef56ab12cd34ef56ab12cd34ef56ab12";

fn entry(artifact_type: &str, metadata: Value) -> Value {
    json!({
        "artifact_id": "artifact-1",
        "artifact_type": artifact_type,
        "name": "Example",
        "metadata": metadata,
    })
}

fn request(entries: Vec<Value>) -> Value {
    json!({
        "schema": INVENTORY_ITEM_CLASSIFICATION_REQUEST_SCHEMA,
        "request_id": "inventory-item-classification-test",
        "entries": entries,
    })
}

fn parse(wire: &Value) -> InventoryItemClassificationRequestV1 {
    serde_json::from_value(wire.clone()).expect("request")
}

fn items(wire: &Value) -> Vec<Value> {
    evaluate_request(&parse(wire))["items"]
        .as_array()
        .expect("items")
        .clone()
}

fn only(wire: &Value) -> Value {
    let answers = items(wire);
    assert_eq!(answers.len(), 1);
    answers[0].clone()
}

fn complete_identity_metadata() -> Value {
    json!({
        "directory_hash": format!("sha256:{DIGEST}"),
        "skillDirectoryIdentity": {
            "schemaVersion": SKILL_DIRECTORY_IDENTITY_SCHEMA,
            "status": "complete",
            "reusable": true,
            "entryCount": 3,
            "totalBytes": 120,
            "contentHash": format!("sha256:{DIGEST}"),
        },
        "versionInfo": {
            "hashBasis": "skill-directory-v1",
            "contentHash": format!("sha256:{DIGEST}"),
        },
    })
}

#[test]
fn maps_every_artifact_type_onto_its_item_kind() {
    let wire = request(vec![
        entry("skill_file", json!({})),
        entry("gateway_config", json!({})),
        entry("prompt_pack", json!({})),
        entry("guard_launcher_shim", json!({})),
        entry("something_new", json!({})),
    ]);
    let answers = items(&wire);
    let kinds: Vec<&str> = answers
        .iter()
        .map(|item| item["item_kind"].as_str().expect("item_kind"))
        .collect();
    assert_eq!(
        kinds,
        vec!["skill", "agent", "prompt_pack", "harness", "plugin"]
    );
}

#[test]
fn answers_entries_in_the_order_they_were_asked() {
    let wire = request(vec![
        entry("channel", json!({})),
        entry("mcp_server", json!({"transport": "stdio"})),
    ]);
    let answers = items(&wire);
    assert_eq!(
        answers[0]["capability_categories"],
        json!(["network_ingress", "posts_messages", "reads_messages"])
    );
    assert_eq!(
        answers[1]["capability_categories"],
        json!(["network_egress", "runs_shell"])
    );
}

#[test]
fn reads_capabilities_and_risk_from_cpython_truthiness() {
    // `envConfigurationPresent: "no"` is a non-empty string, so CPython reads
    // it as present. An item whose risk level dropped to `info` here would be
    // a protection regression.
    let wire = request(vec![entry(
        "mcp_server",
        json!({"envConfigurationPresent": "no"}),
    )]);
    let answer = only(&wire);
    assert_eq!(answer["risk_level"], json!("high"));
    assert_eq!(
        answer["capability_categories"],
        json!(["network_egress", "reads_secrets"])
    );
}

#[test]
fn a_remote_public_endpoint_without_secrets_is_medium_risk() {
    let wire = request(vec![entry(
        "mcp_server",
        json!({"endpointHostClass": "remote_public"}),
    )]);
    assert_eq!(only(&wire)["risk_level"], json!("medium"));
}

#[test]
fn a_skill_binds_the_document_hash_it_was_handed() {
    let mut wire = request(vec![entry(
        "skill",
        json!({
            "contentEvidence": {"contentHash": "sha256:other"},
            "documentedCapabilities": ["reads_files"],
        }),
    )]);
    wire["entries"][0]["primary_content_hash"] = json!("sha256:document");
    let answer = only(&wire);
    assert_eq!(
        answer["metadata_updates"]["primaryContentHash"],
        json!("sha256:document")
    );
    // The evidence claims a body Guard did not hash, so what the skill says
    // about itself does not survive it.
    let removals = answer["metadata_removals"]
        .as_array()
        .expect("removals")
        .clone();
    assert!(removals.contains(&json!("contentEvidence")));
    assert!(removals.contains(&json!("documentedCapabilities")));
    assert_eq!(answer["content_hash"], json!("sha256:document"));
}

#[test]
fn a_skill_keeps_evidence_that_matches_the_body_guard_hashed() {
    let mut wire = request(vec![entry(
        "skill",
        json!({
            "contentEvidence": {"contentHash": "sha256:document"},
            "documentedCapabilities": ["reads_files"],
        }),
    )]);
    wire["entries"][0]["primary_content_hash"] = json!("sha256:document");
    let answer = only(&wire);
    assert_eq!(answer["metadata_removals"], json!([]));
    assert_eq!(
        answer["metadata_updates"],
        json!({"primaryContentHash": "sha256:document"})
    );
}

#[test]
fn a_complete_skill_envelope_keeps_its_directory_hash() {
    let wire = request(vec![entry("skill", complete_identity_metadata())]);
    let answer = only(&wire);
    assert_eq!(answer["metadata_removals"], json!([]));
    assert_eq!(answer["content_hash"], json!(format!("sha256:{DIGEST}")));
}

#[test]
fn an_unproven_skill_envelope_loses_its_directory_hash() {
    let mut metadata = complete_identity_metadata();
    metadata["skillDirectoryIdentity"]["status"] = json!("partial");
    let wire = request(vec![entry("skill", metadata)]);
    let answer = only(&wire);
    assert_eq!(answer["metadata_removals"], json!(["directory_hash"]));
    // Nothing verified is left to identify the directory by, so the item falls
    // back to the fingerprint of what was actually scanned.
    assert_ne!(answer["content_hash"], json!(format!("sha256:{DIGEST}")));
}

#[test]
fn an_instruction_without_a_document_hash_falls_back_to_its_fingerprint() {
    let wire = request(vec![entry("instruction", json!({"content_hash": DIGEST}))]);
    let answer = only(&wire);
    // `_resolve_item_content_hash` is not consulted for an instruction: only
    // Guard's own read of the document, or the semantic fingerprint.
    assert_ne!(answer["content_hash"], json!(format!("sha256:{DIGEST}")));
    assert_eq!(answer["capability_categories"], json!(["reads_files"]));
}

#[test]
fn an_ordinary_artifact_canonicalizes_the_hash_its_evidence_carries() {
    let wire = request(vec![entry(
        "plugin",
        json!({"versionInfo": {"contentHash": DIGEST.to_uppercase()}}),
    )]);
    assert_eq!(
        only(&wire)["content_hash"],
        json!(format!("sha256:{DIGEST}"))
    );
}

#[test]
fn an_untouched_metadata_mapping_asks_for_no_edits() {
    let wire = request(vec![entry("plugin", json!({"transport": "stdio"}))]);
    let answer = only(&wire);
    assert_eq!(answer["metadata_removals"], json!([]));
    assert_eq!(answer["metadata_updates"], json!({}));
}

#[test]
fn refuses_a_request_built_against_another_contract() {
    let mut wire = request(vec![entry("plugin", json!({}))]);
    wire["schema"] = json!("guard-inventory-source-evidence-request.v1");
    assert_eq!(
        refusal(&parse(&wire)),
        Some("native_inventory_item_classification_schema_mismatch")
    );
}

#[test]
fn refuses_more_entries_than_the_contract_accepts() {
    let entries = vec![entry("plugin", json!({})); INVENTORY_ITEM_CLASSIFICATION_MAX_ENTRIES + 1];
    assert_eq!(
        refusal(&parse(&request(entries))),
        Some("native_inventory_item_classification_too_many_entries")
    );
}

#[test]
fn a_refusal_carries_no_payload() {
    let mut wire = request(vec![entry("plugin", json!({}))]);
    wire["schema"] = json!("guard-inventory-source-evidence-request.v1");
    let encoded = evaluate_inventory_item_classification_request(&parse(&wire)).expect("response");
    let result: InventoryItemClassificationResultV1 =
        serde_json::from_slice(&encoded).expect("result");
    assert_eq!(result.schema, INVENTORY_ITEM_CLASSIFICATION_RESULT_SCHEMA);
    assert_eq!(result.status, "error");
    assert_eq!(
        result.code,
        "native_inventory_item_classification_schema_mismatch"
    );
    assert!(result.payload.is_none());
    assert!(!result.request_sha256.is_empty());
}

#[test]
fn an_answered_request_carries_one_item_per_entry() {
    let wire = request(vec![entry("plugin", json!({})), entry("hook", json!({}))]);
    let encoded = evaluate_inventory_item_classification_request(&parse(&wire)).expect("response");
    let result: InventoryItemClassificationResultV1 =
        serde_json::from_slice(&encoded).expect("result");
    assert_eq!(result.status, "ok");
    assert_eq!(result.code, "ok");
    let payload = result.payload.expect("payload");
    assert_eq!(payload["items"].as_array().expect("items").len(), 2);
}

#[test]
fn the_feature_is_advertised() {
    assert!(crate::resident_op_features::RESIDENT_OP_FEATURES
        .contains(&guard_contracts::INVENTORY_ITEM_CLASSIFICATION_FEATURE));
}

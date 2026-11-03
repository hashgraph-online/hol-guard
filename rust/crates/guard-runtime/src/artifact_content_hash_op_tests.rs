//! The content hash a saved approval is keyed by, spelled by the resident.
//!
//! `GuardStore` keys every saved decision by this digest, so the vector below
//! records what `consumer.service.artifact_hash` computed for this artifact
//! before the resident took the hash over. A different spelling would
//! silently invalidate every approval the user already granted.

use super::*;
use guard_contracts::ARTIFACT_CONTENT_HASH_REQUEST_SCHEMA;
use serde_json::{json, Map};

/// `artifact_hash(artifact())` under the Python oracle the resident replaces.
const RECORDED_CONTENT_HASH: &str =
    "34a9621644ab1750a654fa9662466156e8e49a608299318b534bfb85bccffd4d";

/// The fields a caller ships: raw, because the resident redacts before it
/// hashes and a copy redacted by the caller would hash differently.
fn artifact() -> Map<String, Value> {
    let fields = json!({
        "artifact_id": "codex:project:file-read:e11ea28d56441b4475a5c8052c26462479558576",
        "name": "read_file .env",
        "harness": "codex",
        "artifact_type": "file_read_request",
        "source_scope": "project",
        "config_path": "/tmp/ws/.mcp.json",
        "command": null,
        "args": [],
        "url": null,
        "transport": null,
        "publisher": null,
        "metadata": {
            "path_class": "local .env file",
            "tool_name": "read_file",
            "normalized_path": "/tmp/ws/.env",
            "env_keys": ["OPENAI_API_KEY"]
        }
    });
    fields
        .as_object()
        .expect("the fixture is an object")
        .clone()
}

fn request(artifacts: Vec<Map<String, Value>>) -> ArtifactContentHashRequestV1 {
    ArtifactContentHashRequestV1 {
        schema: ARTIFACT_CONTENT_HASH_REQUEST_SCHEMA.to_owned(),
        request_id: "artifact-content-hash-test".to_owned(),
        artifacts,
    }
}

#[test]
fn an_artifact_reaches_the_hash_the_retired_helper_spelled() {
    let payload = evaluate_request(&request(vec![artifact()]));

    assert_eq!(payload["content_hashes"], json!([RECORDED_CONTENT_HASH]));
}

#[test]
fn a_batch_answers_in_the_order_it_was_asked() {
    let mut other = artifact();
    other.insert("name".to_owned(), json!("read_file .npmrc"));
    let payload = evaluate_request(&request(vec![other.clone(), artifact()]));

    let hashes = payload["content_hashes"]
        .as_array()
        .expect("the payload carries an array");
    assert_eq!(hashes.len(), 2);
    assert_eq!(hashes[0], json!(artifact_hash(&other)));
    assert_eq!(hashes[1], json!(RECORDED_CONTENT_HASH));
    assert_ne!(hashes[0], hashes[1]);
}

#[test]
fn an_empty_request_answers_with_no_hashes() {
    let payload = evaluate_request(&request(Vec::new()));

    assert_eq!(payload["content_hashes"], json!([]));
}

#[test]
fn a_request_naming_another_contract_is_refused() {
    let mut other = request(vec![artifact()]);
    other.schema = "guard-hook-artifact-facts-request.v1".to_owned();

    assert_eq!(
        refusal(&other),
        Some("native_artifact_content_hash_schema_mismatch")
    );
}

#[test]
fn a_request_above_the_batch_ceiling_is_refused() {
    let artifacts = vec![artifact(); ARTIFACT_CONTENT_HASH_MAX_ARTIFACTS + 1];

    assert_eq!(
        refusal(&request(artifacts)),
        Some("native_artifact_content_hash_too_many_artifacts")
    );
    assert_eq!(
        refusal(&request(vec![
            artifact();
            ARTIFACT_CONTENT_HASH_MAX_ARTIFACTS
        ])),
        None
    );
}

/// The op answers a request whose `request_sha256` it recomputes by
/// serializing the request it parsed. A field that came back differently than
/// the caller sent it would change those bytes, and every answer would fail
/// the caller's binding check rather than reach a hash.
#[test]
fn a_request_round_trips_to_the_bytes_the_caller_sent() {
    let sent = json!({
        "schema": ARTIFACT_CONTENT_HASH_REQUEST_SCHEMA,
        "request_id": "artifact-content-hash-test",
        "artifacts": [artifact()]
    });
    let parsed: ArtifactContentHashRequestV1 =
        serde_json::from_value(sent.clone()).expect("the request deserializes");

    assert_eq!(
        serde_json::to_value(&parsed).expect("the request serializes"),
        sent
    );
}

#[test]
fn feature_is_advertised() {
    assert!(crate::resident_op_features::RESIDENT_OP_FEATURES
        .contains(&guard_contracts::ARTIFACT_CONTENT_HASH_FEATURE));
}

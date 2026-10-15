//! Parity vectors recorded from the retired Python consumer logic
//! (`normalize_artifact_capabilities`, `compute_capability_delta`,
//! `diff_artifact`, history and provenance builders, `build_incident_context`
//! and the inline result-row assembly), plus the resident transport contract.

use super::*;
use crate::store_vectors_support_tests::gunzip_json;
use guard_contracts::CONSUMER_ARTIFACT_PROJECT_RESULT_SCHEMA;
use serde_json::json;

const VECTORS: &[u8] =
    include_bytes!("../tests/fixtures/consumer_artifact_project_vectors.json.gz");

#[test]
fn matches_recorded_vectors() {
    let vectors = gunzip_json(VECTORS);
    let cases = vectors.as_array().expect("cases");
    assert!(cases.len() >= 1700);
    let structured = |case: &&Value| case["name"].as_str().unwrap().starts_with("structured-");
    assert!(cases.iter().filter(structured).count() >= 90);
    for case in cases {
        let name = case["name"].as_str().unwrap();
        let query: ConsumerArtifactProjectQueryV1 = serde_json::from_value(case["query"].clone())
            .unwrap_or_else(|error| panic!("{name}: {error}"));
        let actual = project(&query).unwrap_or_else(|code| panic!("{name}: {code}"));
        assert_eq!(actual, case["expected"], "{name}");
    }
}

fn resident(request: Value) -> Result<Value, String> {
    crate::resident_protocol::evaluate_resident_bytes(request.to_string().as_bytes(), None)
        .map(|bytes| serde_json::from_slice(&bytes).unwrap())
}

fn incident_query() -> Value {
    json!({
        "kind": "incident_context",
        "harness": "codex",
        "artifact": null,
        "artifact_id": "id",
        "artifact_name": "tool",
        "artifact_type": "mcp_server",
        "source_scope": "project",
        "config_path": "/work/.codex/config.toml",
        "changed_fields": ["first_seen"],
        "policy_action": "review",
        "launch_target": null,
        "risk_summary": null,
    })
}

fn envelope(schema: &str, query: Value) -> Value {
    json!({
        "operation": "consumer_artifact_project",
        "request": {"schema": schema, "request_id": "req-project", "query": query},
    })
}

#[test]
fn resident_transport_binds_request_and_projects() {
    let reply = resident(envelope(
        CONSUMER_ARTIFACT_PROJECT_REQUEST_SCHEMA,
        incident_query(),
    ))
    .unwrap();
    assert_eq!(reply["schema"], CONSUMER_ARTIFACT_PROJECT_RESULT_SCHEMA);
    assert_eq!(reply["status"], "ok");
    assert_eq!(reply["code"], "ok");
    assert_eq!(reply["request_id"], "req-project");
    assert!(reply["request_sha256"]
        .as_str()
        .unwrap()
        .starts_with("sha256:"));
    assert_eq!(reply["payload"]["artifact_label"], "MCP server");
}

#[test]
fn rejects_wrong_schema_unknown_fields_and_unknown_actions() {
    let err = resident(envelope("bogus", incident_query())).unwrap_err();
    assert_eq!(err, "native_consumer_artifact_project_schema_mismatch");

    let mut surprise = incident_query();
    surprise["surprise"] = json!(true);
    assert!(resident(envelope(CONSUMER_ARTIFACT_PROJECT_REQUEST_SCHEMA, surprise)).is_err());

    let mut missing = incident_query();
    missing.as_object_mut().unwrap().remove("risk_summary");
    assert!(resident(envelope(CONSUMER_ARTIFACT_PROJECT_REQUEST_SCHEMA, missing)).is_err());

    let mut action = incident_query();
    action["policy_action"] = json!("maybe");
    assert_eq!(
        resident(envelope(CONSUMER_ARTIFACT_PROJECT_REQUEST_SCHEMA, action)).unwrap_err(),
        "native_consumer_artifact_project_request_invalid"
    );
}

#[test]
fn accepts_structured_summaries_pre_rendered_for_capability_text() {
    let query = json!({
        "kind": "artifact_evidence",
        "artifact": {
            "artifact_id": "id", "name": "n", "harness": "codex", "artifact_type": "skill",
            "source_scope": "project", "config_path": "/p", "command": "node", "args": [],
            "url": null, "transport": null, "publisher": null,
            "metadata": {"capability_text_summaries": {"request_summary": "{'a': 1}"}},
        },
        "current_payload": {}, "payload_keys": [], "current_hash": "h",
        "previous_snapshot": null, "previous_capabilities": null,
        "history": {"inventory_item": null, "decision_counts": {}, "event_names": [], "advisories": []},
    });
    let query: ConsumerArtifactProjectQueryV1 = serde_json::from_value(query).unwrap();
    assert!(project(&query).is_ok());
}

#[test]
fn refuses_metadata_without_a_faithful_text_form() {
    let query = json!({
        "kind": "artifact_evidence",
        "artifact": {
            "artifact_id": "id", "name": "n", "harness": "codex", "artifact_type": "skill",
            "source_scope": "project", "config_path": "/p", "command": null, "args": [],
            "url": null, "transport": null, "publisher": null,
            "metadata": {"request_summary": ["a", "b"]},
        },
        "current_payload": {}, "payload_keys": [], "current_hash": "h",
        "previous_snapshot": null, "previous_capabilities": null,
        "history": {"inventory_item": null, "decision_counts": {}, "event_names": [], "advisories": []},
    });
    let query: ConsumerArtifactProjectQueryV1 = serde_json::from_value(query).unwrap();
    assert_eq!(
        project(&query).unwrap_err(),
        "native_consumer_artifact_project_metadata_unsupported"
    );
}

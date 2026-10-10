//! Recorded vectors and transport binding checks for `HookArtifactCompose`.

use guard_contracts::{HookArtifactComposeQueryV1, HOOK_ARTIFACT_COMPOSE_REQUEST_SCHEMA};
use serde_json::{json, Value};

use super::compose;

const VECTORS: &str = include_str!("../tests/fixtures/hook_artifact_compose_vectors.json");

#[test]
fn matches_recorded_vectors() {
    let vectors: Vec<Value> = serde_json::from_str(VECTORS).unwrap();
    assert!(vectors.len() >= 78);
    for vector in vectors {
        let name = vector["name"].as_str().unwrap();
        let query: HookArtifactComposeQueryV1 = serde_json::from_value(vector["query"].clone())
            .unwrap_or_else(|error| panic!("{name}: {error}"));
        assert_eq!(compose(&query), vector["expected"], "{name}");
    }
}

fn resident(request: Value) -> Result<Value, String> {
    crate::resident_protocol::evaluate_resident_bytes(request.to_string().as_bytes(), None)
        .map(|bytes| serde_json::from_slice(&bytes).unwrap())
}

fn envelope(schema: &str, query: Value) -> Value {
    json!({
        "operation": "hook_artifact_compose",
        "request": {"schema": schema, "request_id": "req-compose", "query": query},
    })
}

#[test]
fn resident_transport_binds_request_and_composes() {
    let reply = resident(envelope(
        HOOK_ARTIFACT_COMPOSE_REQUEST_SCHEMA,
        json!({"kind": "tool_grant_apply"}),
    ))
    .unwrap();
    assert_eq!(reply["status"], "ok");
    assert_eq!(reply["code"], "ok");
    assert_eq!(reply["schema"], "guard-hook-artifact-compose-result.v1");
    assert_eq!(reply["request_id"], "req-compose");
    assert!(reply["request_sha256"]
        .as_str()
        .unwrap()
        .starts_with("sha256:"));
    assert_eq!(reply["payload"]["policy_action"], "allow");
}

#[test]
fn rejects_wrong_schema_unknown_fields_and_missing_fields() {
    let err = resident(envelope("bogus", json!({"kind": "tool_grant_apply"}))).unwrap_err();
    assert_eq!(err, "native_hook_artifact_compose_schema_mismatch");

    let surprise = json!({
        "kind": "grant_settle", "current_action": "review", "policy_action": "review",
        "approval_context_action": "review", "granted_action": "review",
        "native_floor": null, "surprise": true,
    });
    assert!(resident(envelope(HOOK_ARTIFACT_COMPOSE_REQUEST_SCHEMA, surprise)).is_err());

    let missing = json!({"kind": "grant_settle", "current_action": "review"});
    assert!(resident(envelope(HOOK_ARTIFACT_COMPOSE_REQUEST_SCHEMA, missing)).is_err());

    let unknown = json!({"kind": "not_a_query"});
    assert!(resident(envelope(HOOK_ARTIFACT_COMPOSE_REQUEST_SCHEMA, unknown)).is_err());
}

#[test]
fn unknown_actions_never_lower_the_composed_action() {
    let reply = resident(envelope(
        HOOK_ARTIFACT_COMPOSE_REQUEST_SCHEMA,
        json!({
            "kind": "grant_settle", "current_action": 7, "policy_action": null,
            "approval_context_action": "???", "granted_action": "bogus", "native_floor": "also-bogus",
        }),
    ))
    .unwrap();
    for key in [
        "current_policy_action",
        "policy_action",
        "approval_context_policy_action",
    ] {
        assert_eq!(reply["payload"][key], "review", "{key}");
    }
}

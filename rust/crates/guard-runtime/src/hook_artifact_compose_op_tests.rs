//! Recorded vectors and transport binding checks for `HookArtifactCompose`.

use flate2::read::GzDecoder;
use guard_contracts::{
    GuardAction, HookArtifactComposeQueryV1, PolicyConfigFactsV1,
    HOOK_ARTIFACT_COMPOSE_REQUEST_SCHEMA,
};
use serde_json::{json, Value};
use std::io::Read;

use super::compose;

const VECTORS: &str = include_str!("../tests/fixtures/hook_artifact_compose_vectors.json");
const CONFIG_ACTION_VECTORS: &[u8] =
    include_bytes!("../tests/fixtures/config_action_vectors.json.gz");

#[test]
fn matches_recorded_vectors() {
    let vectors: Vec<Value> = serde_json::from_str(VECTORS).unwrap();
    assert!(vectors.len() >= 78);
    for vector in vectors {
        let name = vector["name"].as_str().unwrap();
        let query: HookArtifactComposeQueryV1 = serde_json::from_value(vector["query"].clone())
            .unwrap_or_else(|error| panic!("{name}: {error}"));
        assert_eq!(compose(&query).unwrap(), vector["expected"], "{name}");
    }
}

#[test]
fn fused_decision_copy_preserves_recorded_factory_and_overlay_outcomes() {
    let decisions: Value = serde_json::from_str(include_str!(
        "../../../../tests/fixtures/decision_authority_vectors.json"
    ))
    .unwrap();
    let copies: Vec<Value> = serde_json::from_str(VECTORS).unwrap();
    let mut checked = 0;
    for decision in decisions["vectors"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|v| v["kind"] == "decision_legacy" && v["expected"]["status"] == "ok")
    {
        for copy in copies
            .iter()
            .filter(|v| v["query"]["kind"] == "decision_copy")
        {
            let mut original = copy["query"].clone();
            original["policy_action"] = decision["args"]["action"].clone();
            let mut expected = decision["expected"]["value"].clone();
            for field in ["user_body", "harness_message", "dashboard_primary_detail"] {
                original[format!("base_{field}")] = expected[field].clone();
            }
            let query = serde_json::from_value(original.clone()).unwrap();
            let overlay = compose(&query).unwrap();
            expected
                .as_object_mut()
                .unwrap()
                .extend(overlay["decision_overrides"].as_object().unwrap().clone());
            original.as_object_mut().unwrap().remove("kind");
            // Caller-supplied base copy cannot replace the canonical native base.
            for field in [
                "base_user_body",
                "base_harness_message",
                "base_dashboard_primary_detail",
            ] {
                original[field] = json!("forged caller copy");
            }
            let fused = serde_json::from_value(json!({
                "kind": "decision_build_copy", "copy": original,
                "reason": decision["args"]["reason"], "signals": decision["args"]["signals"],
            }))
            .unwrap();
            let actual = compose(&fused).unwrap();
            assert_eq!(actual["decision_v2"], expected);
            assert_eq!(actual["risk_headline"], overlay["risk_headline"]);
            checked += 1;
        }
    }
    assert!(checked >= 600);
}

#[test]
fn config_action_matches_recorded_python_vectors() {
    let mut text = String::new();
    GzDecoder::new(CONFIG_ACTION_VECTORS)
        .read_to_string(&mut text)
        .unwrap();
    let vectors: Vec<Value> = serde_json::from_str(&text).unwrap();
    assert!(vectors.len() >= 900);
    for vector in vectors {
        let name = vector["name"].as_str().unwrap();
        let mut query = vector["query"].clone();
        query["kind"] = json!("config_action");
        let query: HookArtifactComposeQueryV1 =
            serde_json::from_value(query).unwrap_or_else(|error| panic!("{name}: {error}"));
        assert_eq!(compose(&query).unwrap(), vector["expected"], "{name}");
        // The previous Python hook evaluation sent this configured data-flow
        // action; an unrecognised value never became an action.
        let config: PolicyConfigFactsV1 =
            serde_json::from_value(vector["query"]["policy_config"].clone()).unwrap();
        for (key, strong) in [("weak", false), ("strong", true)] {
            let expected = vector["data_flow"][key]
                .as_str()
                .and_then(GuardAction::from_canonical);
            assert_eq!(
                crate::hook_policy_config::data_flow_configured_action(&config, strong),
                expected,
                "{name} {key}"
            );
        }
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

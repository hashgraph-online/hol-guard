use serde_json::{json, Value};

use super::*;

fn build(workspace_id: Value, device_id: &str, harness: &str, artifacts: Value) -> Value {
    dispatch(&json!({
        "harness": harness,
        "installed": true,
        "command_available": false,
        "workspace_id": workspace_id,
        "device_id": device_id,
        "now": "2026-07-07T00:00:00Z",
        "artifacts": artifacts,
    }))
    .unwrap()
}

fn fingerprints(items: &Value, key: &str) -> Vec<String> {
    items
        .as_array()
        .unwrap()
        .iter()
        .map(|item| item[key].as_str().unwrap().to_owned())
        .collect()
}

#[test]
fn snapshot_ids_match_the_python_stable_digest() {
    let answer = build(json!("workspace-alpha"), "dev-1", "codex", json!([]));
    assert_eq!(
        answer["snapshot_id"],
        "access-graph-e380c97c9bc9e0feed33f146"
    );
    assert_eq!(answer["payload"]["snapshotId"], answer["snapshot_id"]);
    assert_eq!(answer["payload"]["generatedAt"], "2026-07-07T00:00:00Z");
    // A missing workspace hashes as `null`; non-ASCII ids hash escaped.
    let args = json!({
        "harness": "cursor",
        "installed": false,
        "command_available": false,
        "workspace_id": null,
        "device_id": "dév-é",
        "now": "t",
        "artifacts": [],
    });
    assert_eq!(
        dispatch(&args).unwrap()["snapshot_id"],
        "access-graph-e305a9789c6c2ddf3fd27784"
    );
}

#[test]
fn the_host_is_a_device_harness_and_agent_chain() {
    let payload = build(json!(null), "dev-1", "codex", json!([]))["payload"].clone();
    assert_eq!(
        fingerprints(&payload["entities"], "fingerprint"),
        ["device:dev-1", "harness:codex", "agent:codex:local-agent"]
    );
    let harness = &payload["entities"][1];
    assert_eq!(
        harness["metadata"],
        json!({"installed": true, "commandAvailable": false})
    );
    assert_eq!(payload["entities"][0]["displayName"], "Local machine");
    assert_eq!(payload["entities"][2]["displayName"], "codex local agent");
    assert_eq!(
        fingerprints(&payload["edges"], "edgeType"),
        ["device_runs_harness", "harness_runs_agent"]
    );
    assert_eq!(payload["edges"][0]["confidence"], 100);
    assert_eq!(payload["edges"][1]["confidence"], 90);
}

#[test]
fn artifacts_become_typed_entities_with_agent_edges() {
    let payload = build(
        json!("w"),
        "dev-1",
        "codex",
        json!([
            {"artifact_id": "codex:mcp:tavily", "artifact_type": "mcp_server", "artifact_name": "tavily",
             "source_scope": "global", "policy_action": "allow"},
            {"artifact_id": "codex:project:instruction:agents-md", "artifact_type": "instruction", "removed": true},
            {"artifact_id": "codex:skill:lint", "artifact_type": "skill"},
            {"artifact_id": "codex:hook:x", "artifact_type": "hook", "artifact_name": "  "},
            {"artifact_id": "codex:repo", "artifact_type": "repository"},
            {"artifact_id": "  ", "artifact_type": "skill"},
            {"artifact_type": "skill"},
        ]),
    )["payload"]
        .clone();
    let entities = payload["entities"].as_array().unwrap();
    assert_eq!(entities.len(), 8);
    let mcp = &entities[3];
    assert_eq!(mcp["entityType"], "mcp_server");
    assert_eq!(mcp["fingerprint"], "mcp_server:codex:mcp:tavily");
    assert_eq!(mcp["displayName"], "tavily");
    assert_eq!(
        mcp["metadata"],
        json!({
            "agentId": "codex:local-agent",
            "agentType": "codex",
            "artifactType": "mcp_server",
            "harness": "codex",
            "sourceScope": "global",
            "policyAction": "allow",
            "present": true,
        })
    );
    assert_eq!(entities[4]["metadata"]["present"], false);
    // An unknown artifact type is a tool, named by its id when it has no name.
    assert_eq!(entities[6]["entityType"], "tool");
    assert_eq!(entities[6]["metadata"]["artifactType"], "hook");
    assert_eq!(entities[6]["displayName"], "codex:hook:x");
    assert_eq!(entities[6]["metadata"]["sourceScope"], Value::Null);
    assert_eq!(entities[7]["entityType"], "repository");
    assert_eq!(
        fingerprints(&payload["edges"], "edgeType")[2..],
        [
            "agent_uses_mcp_server",
            "agent_uses_instruction",
            "agent_uses_skill"
        ]
    );
    assert_eq!(
        payload["edges"][2]["sourceFingerprint"],
        "agent:codex:local-agent"
    );
    assert_eq!(payload["edges"][2]["confidence"], 80);
}

#[test]
fn repeated_fingerprints_keep_the_first_entity_and_every_edge() {
    let payload = build(
        json!(null),
        "dev-1",
        "codex",
        json!([
            {"artifact_id": "a", "artifact_type": "skill", "artifact_name": "first"},
            {"artifact_id": "a", "artifact_type": "skill", "artifact_name": "second"},
            {"artifact_id": "codex:local-agent", "artifact_type": "agent"},
        ]),
    )["payload"]
        .clone();
    let entities = payload["entities"].as_array().unwrap();
    assert_eq!(entities.len(), 4);
    assert_eq!(entities[3]["displayName"], "first");
    assert_eq!(payload["edges"].as_array().unwrap().len(), 4);
}

#[test]
fn malformed_arguments_are_refused() {
    let valid = json!({
        "harness": "codex",
        "installed": true,
        "command_available": true,
        "workspace_id": null,
        "device_id": "d",
        "now": "t",
        "artifacts": [],
    });
    assert!(dispatch(&valid).is_ok());
    for (key, bad) in [
        ("harness", json!(1)),
        ("installed", json!("yes")),
        ("command_available", Value::Null),
        ("workspace_id", json!(7)),
        ("device_id", Value::Null),
        ("now", json!([])),
        ("artifacts", json!({})),
    ] {
        let mut args = valid.clone();
        args[key] = bad;
        assert_eq!(dispatch(&args), Err(ERR_INVALID), "{key}");
    }
    let mut args = valid;
    args["artifacts"] = json!(["a"]);
    assert_eq!(dispatch(&args), Err(ERR_INVALID));
}

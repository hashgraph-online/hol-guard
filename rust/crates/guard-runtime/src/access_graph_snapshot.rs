//! `access_graph_snapshot` runner-authority kind: builds the access graph
//! snapshot one harness detection contributes to Guard Cloud. Ported from
//! `access_graph_events.queue_access_graph_snapshot`.
//!
//! Python ships the detection's harness and flags, the store's workspace and
//! device ids, and each artifact's string fields (plus `removed` when it is
//! exactly `True`). The answer is the snapshot id and the event payload;
//! Python still builds the event and writes it to the outbox.

use hmac::{Hmac, Mac};
use serde_json::{json, Map, Value};
use sha2::Sha512;

use crate::cloud_request_text::py_strip;
use crate::runner_authority_op::{KindResult, ERR_INVALID};

const STABLE_DIGEST_KEY: &[u8] = b"hol-guard-stable-digest.v3";
const ENTITY_TYPES: [&str; 8] = [
    "skill",
    "mcp_server",
    "tool",
    "repository",
    "agent",
    "policy",
    "integration",
    "instruction",
];

pub(crate) fn dispatch(args: &Value) -> KindResult {
    let (
        Some(harness),
        Some(installed),
        Some(command_available),
        Some(workspace_id),
        Some(device_id),
        Some(now),
        Some(artifacts),
    ) = (
        args.get("harness").and_then(Value::as_str),
        args.get("installed").and_then(Value::as_bool),
        args.get("command_available").and_then(Value::as_bool),
        args.get("workspace_id")
            .filter(|value| value.is_null() || value.is_string()),
        args.get("device_id").and_then(Value::as_str),
        args.get("now").and_then(Value::as_str),
        args.get("artifacts").and_then(Value::as_array),
    )
    else {
        return Err(ERR_INVALID);
    };
    let mut graph = Graph::new(now);
    graph.add_host(device_id, harness, installed, command_available);
    for artifact in artifacts {
        let Value::Object(artifact) = artifact else {
            return Err(ERR_INVALID);
        };
        graph.add_artifact(artifact, harness);
    }
    let snapshot_id = format!(
        "access-graph-{}",
        snapshot_hash(workspace_id, device_id, harness, now)?
    );
    Ok(json!({
        "snapshot_id": snapshot_id,
        "payload": {
            "snapshotId": snapshot_id,
            "generatedAt": now,
            "entities": graph.entities,
            "edges": graph.edges,
        },
    }))
}

struct Graph<'a> {
    now: &'a str,
    entities: Vec<Value>,
    edges: Vec<Value>,
    seen: Vec<String>,
}

impl<'a> Graph<'a> {
    fn new(now: &'a str) -> Self {
        Self {
            now,
            entities: Vec::new(),
            edges: Vec::new(),
            seen: Vec::new(),
        }
    }

    /// The device, the harness and the harness's local agent, with the two
    /// edges that join them.
    fn add_host(&mut self, device_id: &str, harness: &str, installed: bool, available: bool) {
        let device = format!("device:{device_id}");
        let harness_fingerprint = format!("harness:{harness}");
        let agent_id = format!("{harness}:local-agent");
        let agent = format!("agent:{agent_id}");
        self.add_entity("device", device_id, "Local machine", &device, json!({}));
        self.add_entity(
            "harness",
            harness,
            harness,
            &harness_fingerprint,
            json!({"installed": installed, "commandAvailable": available}),
        );
        self.add_edge(&device, &harness_fingerprint, "device_runs_harness", 100);
        self.add_entity(
            "agent",
            &agent_id,
            &format!("{harness} local agent"),
            &agent,
            json!({"harness": harness}),
        );
        self.add_edge(&harness_fingerprint, &agent, "harness_runs_agent", 90);
    }

    fn add_artifact(&mut self, artifact: &Map<String, Value>, harness: &str) {
        let field = |key: &str| non_empty(artifact.get(key));
        let Some(artifact_id) = field("artifact_id") else {
            return;
        };
        let artifact_type = field("artifact_type").unwrap_or("tool");
        let entity_type = if ENTITY_TYPES.contains(&artifact_type) {
            artifact_type
        } else {
            "tool"
        };
        let fingerprint = format!("{entity_type}:{artifact_id}");
        let agent_id = format!("{harness}:local-agent");
        self.add_entity(
            entity_type,
            artifact_id,
            field("artifact_name").unwrap_or(artifact_id),
            &fingerprint,
            json!({
                "agentId": agent_id,
                // agentType and harness both carry the harness slug for
                // portal topology resolution.
                "agentType": harness,
                "artifactType": artifact_type,
                "harness": harness,
                "sourceScope": field("source_scope"),
                "policyAction": field("policy_action"),
                "present": artifact.get("removed") != Some(&Value::Bool(true)),
            }),
        );
        let edge_type = match entity_type {
            "skill" => "agent_uses_skill",
            "mcp_server" => "agent_uses_mcp_server",
            "instruction" => "agent_uses_instruction",
            _ => return,
        };
        self.add_edge(&format!("agent:{agent_id}"), &fingerprint, edge_type, 80);
    }

    /// The first entity with a fingerprint wins; later repeats are dropped.
    fn add_entity(
        &mut self,
        entity_type: &str,
        entity_id: &str,
        display_name: &str,
        fingerprint: &str,
        metadata: Value,
    ) {
        if self.seen.iter().any(|seen| seen == fingerprint) {
            return;
        }
        self.seen.push(fingerprint.to_owned());
        self.entities.push(json!({
            "entityType": entity_type,
            "entityId": entity_id,
            "displayName": display_name,
            "fingerprint": fingerprint,
            "metadata": metadata,
            "firstSeenAt": self.now,
            "lastSeenAt": self.now,
        }));
    }

    fn add_edge(&mut self, source: &str, target: &str, edge_type: &str, confidence: u8) {
        self.edges.push(json!({
            "sourceFingerprint": source,
            "targetFingerprint": target,
            "edgeType": edge_type,
            "confidence": confidence,
            "metadata": {},
            "firstSeenAt": self.now,
            "lastSeenAt": self.now,
        }));
    }
}

/// `_non_empty_string`: the value itself when it is a non-blank string.
fn non_empty(value: Option<&Value>) -> Option<&str> {
    value
        .and_then(Value::as_str)
        .filter(|text| !py_strip(text).is_empty())
}

/// `stable_digest_hex(json.dumps(seed, sort_keys=True), length=24)`.
fn snapshot_hash(
    workspace_id: &Value,
    device_id: &str,
    harness: &str,
    now: &str,
) -> Result<String, &'static str> {
    let seed = json!({
        "workspace": workspace_id,
        "device": device_id,
        "harness": harness,
        "generatedAt": now,
    });
    let mut bytes = Vec::new();
    guard_contracts::write_python_default_json(&seed, &mut bytes).map_err(|_| ERR_INVALID)?;
    let mut mac = Hmac::<Sha512>::new_from_slice(STABLE_DIGEST_KEY).map_err(|_| ERR_INVALID)?;
    mac.update(&bytes);
    Ok(hex::encode(mac.finalize().into_bytes())[..24].to_owned())
}

#[cfg(test)]
#[path = "access_graph_snapshot_tests.rs"]
mod tests;

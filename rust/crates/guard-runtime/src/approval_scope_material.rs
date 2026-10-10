//! Digest of an approval scope contract.
//!
//! Only values that can change authorization scope or its binding are
//! digested. Queue rows are refreshed on every retry; delivery metadata, risk
//! copy and scanner explanations can legitimately change while the action
//! stays the same, so they never invalidate a browser decision. Stable action
//! fields, artifact identity, policy posture, package context and workflow
//! lineage stay bound.

use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};

use crate::approval_scope_contract::View;
use crate::guard_store_json::dumps_sorted;

pub(crate) const APPROVAL_SCOPE_CONTRACT_VERSION: &str = "guard.approval-scopes.v7";

const ACTION_ENVELOPE_KEYS: [&str; 22] = [
    "schema_version",
    "harness",
    "event_name",
    "action_type",
    "workspace_hash",
    "tool_name",
    "command",
    "raw_command_text",
    "command_text",
    "commandText",
    "prompt_excerpt",
    "target_paths",
    "network_hosts",
    "mcp_server",
    "mcp_tool",
    "package_manager",
    "package_name",
    "command_category",
    "package_intent_kind",
    "package_targets",
    "script_name",
    "wrapper_chain",
];
const PACKAGE_CONTEXT_KEYS: [&str; 5] = [
    "kind",
    "schema_version",
    "portable",
    "context_digest",
    "components",
];
const PACKAGE_CONTEXT_EVIDENCE_KIND: &str = "package_execution_context";

fn field(value: &Option<Value>) -> Value {
    value.clone().unwrap_or(Value::Null)
}

/// `raw_payload_redacted["permission_mode"]`, falling back to the camel-case
/// spelling only when the snake-case value is null or absent.
fn permission_mode(raw_payload: &Map<String, Value>) -> Value {
    match raw_payload.get("permission_mode") {
        Some(value) if !value.is_null() => value.clone(),
        _ => raw_payload
            .get("permissionMode")
            .cloned()
            .unwrap_or(Value::Null),
    }
}

fn action_envelope_material(view: &View<'_>) -> Value {
    let Some(envelope) = view.envelope else {
        return Value::Null;
    };
    let mut material = Map::new();
    for key in ACTION_ENVELOPE_KEYS {
        material.insert(
            key.to_owned(),
            envelope.get(key).cloned().unwrap_or(Value::Null),
        );
    }
    if let Some(Value::Object(raw_payload)) = envelope.get("raw_payload_redacted") {
        material.insert("permission_mode".to_owned(), permission_mode(raw_payload));
    }
    Value::Object(material)
}

fn wrapper_chain_material(view: &View<'_>) -> Value {
    let mut chain = view.item.wrapper_chain.as_ref();
    if !matches!(chain, Some(Value::Array(_))) {
        if let Some(envelope) = view.envelope {
            chain = envelope.get("wrapper_chain");
        }
    }
    match chain {
        Some(Value::Array(items)) => Value::Array(items.clone()),
        _ => Value::Array(Vec::new()),
    }
}

fn envelope_permission_mode(view: &View<'_>) -> Value {
    match view
        .envelope
        .and_then(|envelope| envelope.get("raw_payload_redacted"))
    {
        Some(Value::Object(raw_payload)) => permission_mode(raw_payload),
        _ => Value::Null,
    }
}

fn scanner_evidence_material(view: &View<'_>) -> Value {
    let Some(Value::Array(items)) = view.item.scanner_evidence.as_ref() else {
        return Value::Array(Vec::new());
    };
    let mut material = Vec::new();
    for item in items {
        let Some(item) = item.as_object() else {
            continue;
        };
        if item.get("kind").and_then(Value::as_str) == Some(PACKAGE_CONTEXT_EVIDENCE_KIND) {
            let mut entry = Map::new();
            for key in PACKAGE_CONTEXT_KEYS {
                entry.insert(
                    key.to_owned(),
                    item.get(key).cloned().unwrap_or(Value::Null),
                );
            }
            material.push(Value::Object(entry));
        } else if item.get("source").and_then(Value::as_str)
            == Some("github_workflow_approval_record")
        {
            material.push(json!({
                "source": "github_workflow_approval_record",
                "record": item.get("record").cloned().unwrap_or(Value::Null),
            }));
        }
    }
    Value::Array(material)
}

fn request_material(view: &View<'_>) -> Value {
    let item = view.item;
    json!({
        "harness": field(&item.harness),
        "artifact_id": field(&item.artifact_id),
        "artifact_type": field(&item.artifact_type),
        "artifact_hash": field(&item.artifact_hash),
        "policy_action": field(&item.policy_action),
        "publisher": field(&item.publisher),
        "source_scope": field(&item.source_scope),
        "config_path": field(&item.config_path),
        "wrapper_chain": wrapper_chain_material(view),
        "permission_mode": envelope_permission_mode(view),
        "workspace": item.workspace_target.clone().map_or(Value::Null, Value::String),
        "action_identity": field(&item.action_identity),
        "action_envelope": action_envelope_material(view),
        "scanner_evidence": scanner_evidence_material(view),
        "raw_command_text": field(&item.raw_command_text),
    })
}

pub(crate) fn scope_contract_digest(
    view: &View<'_>,
    allow_scopes: &[&str],
    block_scopes: &[&str],
    restrictions: &[&str],
    task_capability_eligible: bool,
    task_capability_reason_codes: &[&str],
    exact_action_persistence_eligible: bool,
) -> String {
    let material = json!({
        "version": APPROVAL_SCOPE_CONTRACT_VERSION,
        "allow_scopes": allow_scopes,
        "block_scopes": block_scopes,
        "restrictions": restrictions,
        "task_capability_eligible": task_capability_eligible,
        "task_capability_reason_codes": task_capability_reason_codes,
        "exact_action_persistence_eligible": exact_action_persistence_eligible,
        "request": request_material(view),
    });
    // Request values were decoded from JSON, so the canonical encoder only
    // fails for a value Python could not have produced either.
    let encoded = dumps_sorted(&material).unwrap_or_default();
    hex::encode(Sha256::digest(encoded.as_bytes()))
}

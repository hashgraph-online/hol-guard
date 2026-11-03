//! `surface_server_handshake` runner-authority kind: the Guard Surface Server
//! contract and the protocol version an `initialize` call settles on. Ported
//! from `schemas/surface_server.build_surface_server_contract` and
//! `runtime/surface_server._negotiate_protocol_version`.
//!
//! Python ships `supported_protocol_versions`, the versions the client listed
//! (possibly none). The answer is:
//!
//! - `contract`, the `guard-surface-server.v1` contract;
//! - `protocol`, the contract's protocol block plus `negotiated_version`;
//! - `negotiated_version`, the newest server version the client shares a
//!   major version with, the current version when the client listed none, or
//!   `null` when no listed version is compatible.

use serde_json::{json, Value};

use crate::runner_authority_detector::args_object;
use crate::runner_authority_op::{KindResult, ERR_INVALID};

const SCHEMA_VERSION: &str = "guard-surface-server.v1";
const CURRENT_PROTOCOL_VERSION: &str = "1.1";
const MINIMUM_PROTOCOL_VERSION: &str = "1.0";
/// Newest first, so the first compatible entry is the one to negotiate.
const SUPPORTED_PROTOCOL_VERSIONS: [&str; 2] = [CURRENT_PROTOCOL_VERSION, MINIMUM_PROTOCOL_VERSION];

const SESSION_FIELDS: &[&str] = &[
    "session_id",
    "harness",
    "surface",
    "status",
    "client_name",
    "created_at",
    "updated_at",
];
const OPERATION_FIELDS: &[&str] = &[
    "operation_id",
    "session_id",
    "harness",
    "operation_type",
    "status",
    "created_at",
    "updated_at",
];
const ITEM_FIELDS: &[&str] = &[
    "item_id",
    "operation_id",
    "item_type",
    "lifecycle",
    "payload",
    "created_at",
];
const RUNTIME_SNAPSHOT_FIELDS: &[&str] = &[
    "generated_at",
    "approval_center_url",
    "runtime_state",
    "pending_count",
    "receipt_count",
    "headline_state",
    "headline_label",
    "headline_detail",
    "sync_configured",
    "cloud_state",
    "cloud_state_label",
    "cloud_state_detail",
    "cloud_pairing_state",
    "dashboard_url",
    "inbox_url",
    "fleet_url",
    "connect_url",
    "items",
    "latest_receipts",
];
const CLOUD_PAIRING_FIELDS: &[&str] = &[
    "state",
    "label",
    "detail",
    "sync_configured",
    "dashboard_url",
    "inbox_url",
    "fleet_url",
    "connect_url",
];
const METHODS: &[&str] = &[
    "initialize",
    "session/start",
    "session/list",
    "session/attach",
    "operation/start",
    "operation/status",
    "operation/item/add",
    "client/attach",
    "client/heartbeat",
];
const NOTIFICATIONS: &[&str] = &[
    "session/started",
    "session/attached",
    "operation/started",
    "operation/waitingApproval",
    "operation/resumed",
    "operation/completed",
    "item/completed",
    "approval/requested",
    "approval/resolved",
    "receipt/created",
    "policy/changed",
];

pub(crate) fn dispatch(args: &Value) -> KindResult {
    let args = args_object(args)?;
    let listed = args
        .get("supported_protocol_versions")
        .and_then(Value::as_array)
        .ok_or(ERR_INVALID)?;
    let negotiated = negotiate(listed);
    let contract = contract();
    let mut protocol = contract["protocol"].clone();
    protocol["negotiated_version"] = json!(negotiated);
    Ok(json!({
        "contract": contract,
        "protocol": protocol,
        "negotiated_version": negotiated,
    }))
}

/// The newest supported version whose major version a listed version shares.
/// Entries that are not strings are ignored, as the Python negotiation did.
fn negotiate(listed: &[Value]) -> Option<&'static str> {
    if listed.is_empty() {
        return Some(CURRENT_PROTOCOL_VERSION);
    }
    let listed: Vec<&str> = listed.iter().filter_map(Value::as_str).collect();
    SUPPORTED_PROTOCOL_VERSIONS.into_iter().find(|version| {
        listed
            .iter()
            .any(|candidate| candidate == version || major(candidate) == major(version))
    })
}

fn major(version: &str) -> &str {
    version.split('.').next().unwrap_or(version)
}

fn entity(states: Option<&[&str]>, fields: &[&str]) -> Value {
    let mut entity = json!({
        "required_fields": fields,
        "json_schema": {"type": "object", "required": fields},
    });
    if let Some(states) = states {
        entity["states"] = json!(states);
    }
    entity
}

fn contract() -> Value {
    let pairing_properties = json!({
        "state": {"enum": ["local_only", "paired_waiting", "paired_active"]},
        "label": {"type": "string"},
        "detail": {"type": "string"},
        "sync_configured": {"type": "boolean"},
        "dashboard_url": {"type": "string"},
        "inbox_url": {"type": "string"},
        "fleet_url": {"type": "string"},
        "connect_url": {"type": "string"},
    });
    let mut runtime_snapshot = entity(None, RUNTIME_SNAPSHOT_FIELDS);
    runtime_snapshot["json_schema"]["properties"] = json!({
        "cloud_pairing_state": {
            "type": "object",
            "required": CLOUD_PAIRING_FIELDS,
            "properties": pairing_properties,
        },
    });
    json!({
        "schema_version": SCHEMA_VERSION,
        "protocol_versions": SUPPORTED_PROTOCOL_VERSIONS,
        "protocol": {
            "current_version": CURRENT_PROTOCOL_VERSION,
            "minimum_version": MINIMUM_PROTOCOL_VERSION,
            "supported_versions": SUPPORTED_PROTOCOL_VERSIONS,
            "compatibility": "same-major",
        },
        "entities": {
            "session": entity(
                Some(&["created", "attached", "active", "idle", "archived"]),
                SESSION_FIELDS,
            ),
            "operation": entity(
                Some(&[
                    "started",
                    "waiting_on_approval",
                    "resumed",
                    "completed",
                    "blocked",
                    "failed",
                ]),
                OPERATION_FIELDS,
            ),
            "item": entity(Some(&["created", "completed"]), ITEM_FIELDS),
            "runtime_snapshot": runtime_snapshot,
        },
        "methods": METHODS,
        "notifications": NOTIFICATIONS,
    })
}

#[cfg(test)]
#[path = "surface_server_handshake_tests.rs"]
mod tests;

//! `POST /v1/initialize`, answered as the daemon's `_handle_initialize` and
//! `initialize_client` answer a caller holding the daemon key: the same
//! negotiated protocol, the surface server contract and the newest sessions.
//!
//! A caller that also sends a dashboard session goes to the daemon, which may
//! hand back a refreshed session.

use serde_json::{json, Value};

use super::super::super::records::session_items;
use super::super::super::{NativeReads, ReadConfig};
use super::{get, optional_string, strings, uuid4_hex, Dict};
use crate::pyjson::PyVal;

const SERVER_METHODS: &[&str] = &[
    "initialize",
    "session/list",
    "session/start",
    "session/attach",
    "session/resume",
    "session/archive",
    "operation/start",
    "operation/status",
    "operation/resume",
    "approval/list",
    "approval/get",
    "approval/respond",
    "approval/subscribe",
    "receipt/list",
    "receipt/get",
    "policy/get",
];
const SERVER_NOTIFICATIONS: &[&str] = &[
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
const SURFACES: &[&str] = &[
    "cli",
    "approval-center",
    "harness-adapter",
    "cloud-dashboard",
    "agent-sdk",
];
const SESSION_LIMIT: i64 = 20;

pub(super) fn respond(
    payload: &Dict,
    config: &ReadConfig,
    reads: &NativeReads,
) -> Option<(u16, Value)> {
    let listed = |key| match get(payload, key) {
        Some(PyVal::List(items)) => strings(items),
        _ => PyVal::List(Vec::new()),
    };
    let handshake = crate::surface_server_handshake::dispatch(&json!({
        "supported_protocol_versions": listed("supported_protocol_versions").to_json()?,
    }))
    .ok()?;
    let Some(negotiated) = handshake.get("negotiated_version")?.as_str() else {
        return Some((400, json!({"error": "unsupported_protocol_version"})));
    };
    let contract = handshake.get("contract")?;
    let protocol = handshake.get("protocol")?;
    if !contract.is_object() || !protocol.is_object() {
        return None;
    }
    let sessions = session_items(SESSION_LIMIT, config, reads)?;
    Some((
        200,
        json!({
            "protocol_version": negotiated,
            "schema_version": contract.get("schema_version"),
            "schema": contract,
            "client_id": uuid4_hex()?,
            "protocol": protocol,
            "server_capabilities": {
                "methods": SERVER_METHODS,
                "notifications": SERVER_NOTIFICATIONS,
                "surfaces": SURFACES,
            },
            "client": {
                "client_name": optional_string(payload, "client_name")
                    .unwrap_or_else(|| "guard-client".to_owned()),
                "client_title": optional_string(payload, "client_title"),
                "version": optional_string(payload, "version"),
                "surface": optional_string(payload, "surface")
                    .unwrap_or_else(|| "cli".to_owned()),
                "capabilities": listed("capabilities").to_json()?,
            },
            "sessions": sessions,
        }),
    ))
}

#[cfg(all(test, unix))]
#[path = "daemon_edge_initialize_tests.rs"]
mod tests;

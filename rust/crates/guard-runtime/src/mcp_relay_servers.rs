//! The MCP servers whose catalog a relay session has reported.
//!
//! The relay learns a catalog only after it started the server, so the
//! resident remembers each reported server for later sessions: the native
//! relay and the Python proxy both report the catalog they serve. A server no
//! session reported yet is unknown, and its first session starts native and
//! reports it.
//!
//! The resident decides every call itself (`mcp_relay_decide`), including a
//! call that installs or runs a package (`mcp_relay_decide_package.rs`), and
//! refuses whatever it cannot settle. No catalog or decide therefore hands a
//! server to the proxy any more: a package call the lane cannot settle is
//! refused in place, and a tool definition with no usable name names no tool
//! the relay sends a call for (`sendable_name`).
//!
//! The registry is bounded: a server past the bound stays unknown. It only
//! steers how a session starts. Each call is still admitted by
//! `mcp_relay_decide`, so a wrong or missing report can refuse a call but
//! never allow one.

use std::collections::HashSet;
use std::sync::Mutex;

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

pub(crate) const MCP_RELAY_SERVER_REPORT_FEATURE: &str = "mcp-relay-server-report-v1";
pub(crate) const REPORT_SCHEMA: &str = "guard-mcp-relay-server-report-result.v1";
/// No session reported the server's catalog yet.
pub(crate) const SERVER_UNKNOWN: &str = "mcp_relay_session_server_unknown";
const MAX_SERVERS: usize = 1024;
const MAX_KEY_BYTES: usize = 8 * 1024;

/// The server a session runs, as the relay and the proxy both name it.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct RelayServerV1 {
    pub(crate) harness: String,
    pub(crate) server_name: String,
    pub(crate) source_scope: String,
    pub(crate) config_path: String,
    pub(crate) server_id: Option<String>,
    /// `McpServerIdentity.identity_hash`: the command, arguments, transport
    /// and configured environment.
    pub(crate) identity_hash: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct McpRelayServerReportRequestV1 {
    pub(crate) guard_home: String,
    pub(crate) server: RelayServerV1,
    /// The tool definitions of the server's whole catalog. The report keeps
    /// the field for the wire contract; recording a server reads none of it.
    #[allow(dead_code)]
    pub(crate) tools: Vec<Value>,
}

/// Each reported server.
#[derive(Debug, Default)]
pub(crate) struct RelayServers {
    servers: Mutex<HashSet<String>>,
}

impl RelayServers {
    /// Record a server; `false` when it cannot be remembered.
    pub(crate) fn record(&self, server: &RelayServerV1) -> bool {
        let Some(key) = key(server) else {
            return false;
        };
        let Ok(mut servers) = self.servers.lock() else {
            return false;
        };
        if servers.contains(&key) {
            return true;
        }
        if servers.len() >= MAX_SERVERS {
            return false;
        }
        servers.insert(key);
        true
    }

    /// `Ok` when a session reported `server` before.
    pub(crate) fn relayable(&self, server: &RelayServerV1) -> Result<(), &'static str> {
        let key = key(server).ok_or(SERVER_UNKNOWN)?;
        let servers = self.servers.lock().map_err(|_| SERVER_UNKNOWN)?;
        if servers.contains(&key) {
            Ok(())
        } else {
            Err(SERVER_UNKNOWN)
        }
    }
}

fn key(server: &RelayServerV1) -> Option<String> {
    serde_json::to_string(server)
        .ok()
        .filter(|key| key.len() <= MAX_KEY_BYTES)
}

pub(crate) fn report(
    request: &McpRelayServerReportRequestV1,
    servers: &RelayServers,
) -> Result<Vec<u8>, String> {
    let recorded = servers.record(&request.server);
    serde_json::to_vec(&json!({"schema": REPORT_SCHEMA, "recorded": recorded}))
        .map_err(|_| "mcp_relay_server_report_encoding_failed".to_owned())
}

/// A tool name the relay sends a call for (`decide_request`); a call to any
/// other name is never sent.
pub(crate) fn sendable_name(name: &str) -> bool {
    !name.is_empty()
}

/// A Composio wrapper, whose identity binds the provider catalog hash
/// (`composio_names_a_wrapper`). The tail is matched after full Unicode case
/// folding, as Python's `str.casefold()` does: `compoſio_x` is a wrapper on
/// both paths, so its call binds the same provider catalog hash either way.
pub(crate) fn composio_tool(name: &str) -> bool {
    crate::mcp_tool_policy_composio::tool_role(name).is_some()
}

#[cfg(test)]
#[path = "mcp_relay_servers_tests.rs"]
mod tests;

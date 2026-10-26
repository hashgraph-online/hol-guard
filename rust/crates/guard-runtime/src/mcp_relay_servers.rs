//! The MCP servers whose relay sessions the resident hands to the proxy.
//!
//! The relay cannot hand a call back once the MCP server runs, so a call the
//! resident does not decide is refused rather than proxied. A server whose
//! catalog offers a tool that can only carry such a call therefore runs under
//! the Python proxy instead.
//!
//! The resident decides a call that installs or runs a package itself
//! (`mcp_relay_decide_package.rs`), so a tool the package parser reads as a
//! shell (`_SHELL_TOOL_NAMES`) and a tool whose input schema declares a key
//! the proxy reads as the command (`_command_argument`) no longer hold their
//! server back; a package call the lane cannot settle defers, and that defer
//! marks the server for the proxy the same way an unknown server's first
//! session does. A Composio tool is decided there too: the resident reads the
//! provider catalog hash its identity binds from the store. What remains is a
//! definition with no usable name, which names no tool the catalog can decide
//! against.
//!
//! The relay learns a catalog only after it started the server, so the
//! resident remembers each server's catalog for later sessions:
//!
//! - the Python proxy reports a server's catalog once it has the whole of it;
//! - `mcp_relay_decide` marks a server when it defers a call to the package
//!   policy, which covers a command the schema did not declare;
//! - the native relay reports the catalog it relays the same way, so an
//!   unknown server's session starts native and reports it.
//!
//! A mark never clears while the resident runs. The registry is bounded: a
//! server past the bound stays unknown. It only steers which launcher runs.
//! Each call is still admitted by `mcp_relay_decide`, which refuses whatever
//! it does not decide, so a wrong or missing report can refuse a call but
//! never allow one.

use std::collections::HashMap;
use std::sync::Mutex;

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

pub(crate) const MCP_RELAY_SERVER_REPORT_FEATURE: &str = "mcp-relay-server-report-v1";
pub(crate) const REPORT_SCHEMA: &str = "guard-mcp-relay-server-report-result.v1";
/// No session reported the server's catalog yet.
pub(crate) const SERVER_UNKNOWN: &str = "mcp_relay_session_server_unknown";
/// The server offers a tool whose calls the proxy decides.
pub(crate) const SERVER_PROXY_TOOLS: &str = "mcp_relay_session_server_proxy_tools";
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
    /// The tool definitions of the server's whole catalog.
    pub(crate) tools: Vec<Value>,
}

/// Each reported server and whether it offers a tool the proxy decides.
#[derive(Debug, Default)]
pub(crate) struct RelayServers {
    servers: Mutex<HashMap<String, bool>>,
}

impl RelayServers {
    /// Record a server; a mark is never cleared.
    pub(crate) fn record(&self, server: &RelayServerV1, proxy_tools: bool) -> bool {
        let Some(key) = key(server) else {
            return false;
        };
        let Ok(mut servers) = self.servers.lock() else {
            return false;
        };
        if let Some(marked) = servers.get_mut(&key) {
            *marked |= proxy_tools;
            return true;
        }
        if servers.len() >= MAX_SERVERS {
            return false;
        }
        servers.insert(key, proxy_tools);
        true
    }

    /// `Ok` when a session of `server` can run under the relay.
    pub(crate) fn relayable(&self, server: &RelayServerV1) -> Result<(), &'static str> {
        let key = key(server).ok_or(SERVER_UNKNOWN)?;
        let servers = self.servers.lock().map_err(|_| SERVER_UNKNOWN)?;
        match servers.get(&key) {
            None => Err(SERVER_UNKNOWN),
            Some(true) => Err(SERVER_PROXY_TOOLS),
            Some(false) => Ok(()),
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
    let proxy_tools = request.tools.iter().any(proxy_tool);
    let recorded = servers.record(&request.server, proxy_tools);
    serde_json::to_vec(&json!({"schema": REPORT_SCHEMA, "recorded": recorded}))
        .map_err(|_| "mcp_relay_server_report_encoding_failed".to_owned())
}

/// Whether the proxy, not the resident, decides some call of `tool`: a
/// definition without a name the relay can send.
pub(crate) fn proxy_tool(tool: &Value) -> bool {
    !tool
        .get("name")
        .and_then(Value::as_str)
        .is_some_and(sendable_name)
}

/// A tool name the relay sends a call for (`decide_request`); a call to any
/// other name is never sent.
pub(crate) fn sendable_name(name: &str) -> bool {
    !name.is_empty() && name.is_ascii()
}

/// A Composio wrapper, whose identity binds the provider catalog hash
/// (`composio_names_a_wrapper`).
pub(crate) fn composio_tool(name: &str) -> bool {
    let tail = name.rsplit("__").next().unwrap_or(name);
    tail.to_ascii_lowercase().starts_with("composio_")
}

#[cfg(test)]
#[path = "mcp_relay_servers_tests.rs"]
mod tests;

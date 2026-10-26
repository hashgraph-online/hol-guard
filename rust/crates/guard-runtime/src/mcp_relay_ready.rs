//! Whether the direct lane is ready for a native MCP relay session.
//!
//! The relay asks before it reads the host's input or starts the MCP server,
//! and again while the session's first call waits for a lane that was not
//! ready yet. A lane is ready only when the resident can decide the
//! session's calls at all (`mcp_relay_decide_session.rs`): a config that
//! prompts (in either mode, observe included) or a store holding remote
//! policy sends the session to the Python proxy, and so does a server whose
//! catalog offers a tool the proxy decides (`mcp_relay_servers.rs`). A
//! server whose catalog the resident has no report of is not ready either,
//! but its session stays native and reports the catalog it relays.
//! The answer is only `ready` or `not_ready` with the lane's defer code. It
//! carries no verdict, no binding state and no key, and it never stands in
//! for a decision: each call is still admitted by `mcp_relay_decide`, which
//! repeats every check made here and refuses whatever it does not decide.

use std::path::Path;

use serde::Deserialize;
use serde_json::json;

use crate::policy_store::PolicySnapshotStore;

pub(crate) const MCP_RELAY_READY_SCHEMA: &str = "guard-mcp-relay-ready-result.v1";
const RUNTIME_SUPERSEDED: &str = "mcp_relay_runtime_superseded";
const WORKSPACE_INVALID: &str = "mcp_relay_workspace_invalid";
const EVIDENCE_UNDRAINED: &str = "mcp_relay_evidence_undrained";
const BINDING_INCOMPLETE: &str = "mcp_relay_binding_incomplete";

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct McpRelayReadyRequestV1 {
    pub(crate) guard_home: String,
    /// The workspace the session's decisions are admitted under.
    pub(crate) workspace: String,
    pub(crate) harness: String,
    /// The server the session runs.
    pub(crate) server: crate::mcp_relay_servers::RelayServerV1,
}

pub(crate) fn evaluate(
    request: &McpRelayReadyRequestV1,
    policy_store: &PolicySnapshotStore,
) -> Result<Vec<u8>, String> {
    let body = match readiness(request, policy_store) {
        Ok(()) => json!({"schema": MCP_RELAY_READY_SCHEMA, "ready": true}),
        Err(reason) => json!({"schema": MCP_RELAY_READY_SCHEMA, "ready": false, "reason": reason}),
    };
    serde_json::to_vec(&body).map_err(|_| "mcp_relay_ready_result_encoding_failed".to_owned())
}

fn readiness(
    request: &McpRelayReadyRequestV1,
    policy_store: &PolicySnapshotStore,
) -> Result<(), &'static str> {
    if !crate::hook_direct::runtime_current() {
        return Err(RUNTIME_SUPERSEDED);
    }
    let workspace = settled_directory(&request.workspace)?;
    let (_snapshot, binding) = policy_store
        .admit_direct_hook_or_subdirectory(&workspace)
        .map_err(|defer| defer.code())?;
    if binding.evidence_drain != Some(true) {
        return Err(EVIDENCE_UNDRAINED);
    }
    if binding.exact_action_control_digest.is_none() {
        return Err(BINDING_INCOMPLETE);
    }
    if request.server.harness != request.harness {
        return Err(crate::mcp_relay_servers::SERVER_UNKNOWN);
    }
    crate::mcp_relay_decide::session_decidable(&binding, &request.guard_home, &request.harness)?;
    policy_store.mcp_relay_servers().relayable(&request.server)
}

/// `Path.resolve(strict=True)` of a directory, as the lane settles it.
fn settled_directory(candidate: &str) -> Result<String, &'static str> {
    let resolved = std::fs::canonicalize(Path::new(candidate)).map_err(|_| WORKSPACE_INVALID)?;
    if !resolved.is_dir() {
        return Err(WORKSPACE_INVALID);
    }
    resolved
        .into_os_string()
        .into_string()
        .map_err(|_| WORKSPACE_INVALID)
}

#[cfg(all(test, unix))]
#[path = "mcp_relay_ready_tests.rs"]
mod tests;

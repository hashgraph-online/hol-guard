//! Which package-lane defers hand the call's server to the proxy.
//!
//! A package call the relay could not answer is refused, and its server is
//! recorded so later sessions of it go to the proxy, which decides such calls
//! (`mcp_relay_servers.rs`).

use super::{Answer, McpRelayDecideRequestV1};
use crate::policy_store::PolicySnapshotStore;

/// Every defer the package lane answers with. The gate's workspace check is
/// not one of them: it fires before an intent is known, for a call that may
/// carry no package request at all.
pub(super) const PACKAGE_DEFER_PREFIX: &str = "mcp_relay_package";

/// Whether `reason` sends the call's server to the proxy.
pub(super) fn hands_server_off(reason: &str) -> bool {
    reason.starts_with(PACKAGE_DEFER_PREFIX)
}

/// Record the server of a decide the package lane deferred for the proxy.
pub(super) fn after_decide(
    answer: &Result<Answer, &'static str>,
    request: &McpRelayDecideRequestV1,
    policy_store: &PolicySnapshotStore,
) {
    if matches!(answer, Err(reason) if hands_server_off(reason)) {
        mark_package_server(request, policy_store);
    }
}

/// Hand later sessions of a server whose call went to the package policy to
/// the proxy, which decides such calls (`mcp_relay_servers.rs`).
pub(super) fn mark_package_server(
    request: &McpRelayDecideRequestV1,
    policy_store: &PolicySnapshotStore,
) {
    let build = &request.build;
    let Some(identity) = build.server_identity.as_ref() else {
        return;
    };
    let server = crate::mcp_relay_servers::RelayServerV1 {
        harness: build.harness.clone(),
        server_name: build.server_name.clone(),
        source_scope: build.source_scope.clone(),
        config_path: build.config_path.clone(),
        server_id: build.server_id.clone(),
        identity_hash: identity.identity_hash.clone(),
    };
    policy_store.mcp_relay_servers().record(&server, true);
}

#[cfg(test)]
#[path = "mcp_relay_decide_package_server_tests.rs"]
mod tests;

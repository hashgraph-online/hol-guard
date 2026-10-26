//! Accessors for services owned by one resident policy store.
use super::PolicySnapshotStore;

impl PolicySnapshotStore {
    /// Evidence of direct hook answers, waiting for the daemon to drain it.
    pub(crate) fn direct_evidence(&self) -> &crate::hook_direct_evidence::DirectEvidenceQueue {
        &self.direct_evidence
    }

    /// Relayed forwards' evidence, waiting for the relay to commit it.
    pub(crate) fn mcp_relay_pending(&self) -> &crate::mcp_relay_pending::PendingRelayEvidence {
        &self.mcp_relay_pending
    }

    /// Relayed decisions' saved-approval claims, waiting for the relay.
    pub(crate) fn mcp_relay_claims(
        &self,
    ) -> &crate::mcp_relay_claims::HeldClaims<crate::mcp_relay_decide::HeldClaim> {
        &self.mcp_relay_claims
    }

    /// The MCP servers whose relay sessions run under the proxy.
    pub(crate) fn mcp_relay_servers(&self) -> &crate::mcp_relay_servers::RelayServers {
        &self.mcp_relay_servers
    }
}

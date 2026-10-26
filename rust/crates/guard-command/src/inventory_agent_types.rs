//! `inventory_agent_types` mirror: the `AgentTypeApi` seam.

use crate::inventory_contract::AgentTypeApi;

/// `_AGENT_INVENTORY_TYPES` — the identities a snapshot may carry.
pub static AGENT_INVENTORY_TYPES: &[&str] = &[
    "hermes",
    "openclaw",
    "codex",
    "claude-code",
    "cursor",
    "antigravity",
    "gemini",
    "opencode",
    "kimi",
    "grok",
    "pi",
    "omp",
    "zcode",
    "paseo",
    "devin",
    "copilot",
    "cline",
];

/// `agent_type(value)`.
///
/// The match is exact — no trimming and no case folding — and anything else
/// normalizes to `codex`, which is what the Python loop does.
pub fn agent_type(value: &str) -> &'static str {
    AGENT_INVENTORY_TYPES
        .iter()
        .copied()
        .find(|candidate| *candidate == value)
        .unwrap_or("codex")
}

/// The native `AgentTypeApi` seam for `InventoryDeps`.
#[derive(Debug, Clone, Copy, Default)]
pub struct NativeAgentTypes;

impl AgentTypeApi for NativeAgentTypes {
    fn _agent_type(&self, agent_id: &str) -> String {
        agent_type(agent_id).to_string()
    }
}

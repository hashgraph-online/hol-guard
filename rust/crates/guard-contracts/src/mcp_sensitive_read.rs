//! Queries of the `mcp_proxy_decide` op that own the stdio proxy's
//! sensitive-file-read decision: the current action, the exact-context
//! approval token, the saved-approval reuse composition and the response the
//! caller renders when the read is not forwarded.
//!
//! Python gathers facts (configuration values, store rows, claim outcomes)
//! and performs the effects between queries. Every verdict, token and message
//! below is computed by the resident.

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Configuration facts the stdio proxy reads from `GuardConfig`. `None` on the
/// query means the proxy holds no valid configuration at all.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct McpSensitiveReadConfigV1 {
    /// Override and default of the harness view of the configuration.
    #[serde(default)]
    pub view_override: Option<String>,
    pub view_default_action: String,
    /// `resolve_risk_action(view, "local_secret_read")`; empty or absent means
    /// the conservative `require-reapproval`.
    #[serde(default)]
    pub risk_action: Option<String>,
    /// Override and default of the unmodified configuration (bound into the token).
    #[serde(default)]
    pub artifact_override: Value,
    pub default_action: Value,
    #[serde(default)]
    pub managed_locked_settings: Vec<String>,
    #[serde(default)]
    pub managed_policy_hash: Value,
    #[serde(default)]
    pub managed_policy_status: Value,
    #[serde(default)]
    pub mode: Value,
    #[serde(default)]
    pub protection_posture: Value,
    pub protection_posture_explicit: bool,
    #[serde(default)]
    pub security_level: Value,
    #[serde(default)]
    pub harness_posture: Option<String>,
    #[serde(default)]
    pub sandbox_analysis: Value,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct McpSensitiveReadContextQueryV1 {
    #[serde(default)]
    pub config: Option<McpSensitiveReadConfigV1>,
    /// Identity component: artifact, launch identity, environment hash, workspace.
    pub identity: Value,
    /// The artifact content hash text (never parsed).
    pub content: String,
    pub capabilities: Value,
    pub extension_control_digest: String,
}

/// Which composition of a saved approval with the recomputed action to evaluate.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum McpSensitiveReadStageV1 {
    /// The first lookup of the saved approval for the current context.
    Initial,
    /// The atomic claim of a reusable approval failed.
    ClaimFailed,
    /// A claim succeeded and the context was rebuilt; compare against the claim.
    Postclaim,
    /// A claim succeeded but the current configuration could not be refreshed.
    RefreshFailed,
}

/// The policy-store lookup the caller performed for one context hash.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct McpSensitiveReadLookupV1 {
    pub decision_present: bool,
    #[serde(default)]
    pub decision_action: Value,
    #[serde(default)]
    pub decision_artifact_hash: Value,
    pub ignored_integrity: bool,
    #[serde(default)]
    pub diagnosed_reason: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct McpSensitiveReadReuseQueryV1 {
    pub stage: McpSensitiveReadStageV1,
    pub current_action: String,
    pub artifact_hash: String,
    /// `None` when the proxy has no policy store.
    #[serde(default)]
    pub lookup: Option<McpSensitiveReadLookupV1>,
    #[serde(default)]
    pub claimed_allow_hash: Option<String>,
    pub tool_name: String,
    pub path_class: String,
    pub asks_for_approval: bool,
    pub approval_center_present: bool,
    pub store_present: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct McpSensitiveReadHintQueryV1 {
    pub policy_action: String,
    pub message: String,
    pub approval_summary: String,
    pub review_url: String,
}

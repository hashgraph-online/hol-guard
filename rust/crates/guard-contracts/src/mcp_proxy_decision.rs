//! `McpProxyDecision` — wire contract for the resident op that owns the
//! authoritative decisions of the MCP proxy (catalog state machine, tool-call
//! routing, execution-boundary revalidation and package composition).
//!
//! Python frames the stream, gathers facts from its collaborators and renders
//! responses; every verdict below is computed by the resident. Facts that only
//! a collaborator can supply (a native prompt answer, an inline approval, a
//! claim-store check) are requested lazily through the `need` protocol: the
//! resident replies `{"need": <name>}` and the caller repeats the identical
//! request with that fact added. Unsupplied facts are never assumed.

use serde::{Deserialize, Serialize};
use serde_json::Value;

pub const MCP_PROXY_DECISION_REQUEST_SCHEMA: &str = "guard-mcp-proxy-decision-request.v1";
pub const MCP_PROXY_DECISION_RESULT_SCHEMA: &str = "guard-mcp-proxy-decision-result.v1";
pub const MCP_PROXY_DECISION_FEATURE: &str = "mcp-proxy-decision-v1";
/// Largest request the op accepts (a `tools/list` page rides inside it).
pub const MCP_PROXY_DECISION_MAX_BYTES: usize = 5 * 1024 * 1024;

/// The decision-relevant facts of one `ToolCallDecision`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct McpToolFactsV1 {
    pub action: String,
    pub source: String,
    #[serde(default)]
    pub current_action: Option<String>,
    #[serde(default)]
    pub saved_action: Option<String>,
    #[serde(default)]
    pub approval_reuse_status: Option<String>,
    #[serde(default)]
    pub approval_reuse_reason_code: Option<String>,
    pub has_pending: bool,
}

/// The decision-relevant facts of one package policy resolution.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct McpPackageFactsV1 {
    pub saved_policy_blocks: bool,
    #[serde(default)]
    pub current_action: Option<String>,
    pub policy_action: String,
    pub has_pending: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum McpCatalogCursorV1 {
    None,
    String { value: String },
    Other,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct McpCatalogStateV1 {
    pub state: String,
    pub generation: i64,
    pub inflight: bool,
    #[serde(default)]
    pub inflight_cursor: Option<String>,
    #[serde(default)]
    pub expected_cursor: Option<String>,
    #[serde(default)]
    pub catalog_names: Vec<String>,
    #[serde(default)]
    pub pending_names: Option<Vec<String>>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum McpCatalogEventV1 {
    Begin {
        cursor: McpCatalogCursorV1,
        advance_root_generation: bool,
    },
    Capture {
        cursor: McpCatalogCursorV1,
        #[serde(default)]
        request_generation: Option<i64>,
        response: Value,
    },
    Fail {
        request_generation: i64,
    },
    Invalidate,
    Reset,
    Poison,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct McpCatalogEventQueryV1 {
    pub state: McpCatalogStateV1,
    pub event: McpCatalogEventV1,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct McpSavedAllowGateQueryV1 {
    pub catalog_state: String,
    pub decision: McpToolFactsV1,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct McpBoundaryFailureQueryV1 {
    pub phase: String,
    pub fresh: McpToolFactsV1,
}

/// Identity of a re-resolved artifact against the one that was claimed.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct McpToolContextV1 {
    pub artifact_id: String,
    pub expected_artifact_id: String,
    pub artifact_hash: String,
    pub expected_artifact_hash: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct McpToolPostclaimQueryV1 {
    pub fresh: McpToolFactsV1,
    pub artifact_id: String,
    pub expected_artifact_id: String,
    pub artifact_hash: String,
    pub expected_artifact_hash: String,
    pub claim_authorizes_review: bool,
    /// Supplied after the resident answered `need = fresh_claim_allows_reapproval`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fresh_claim_allows_reapproval: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct McpPackagePostclaimFactsV1 {
    pub facts: McpPackageFactsV1,
    pub artifact_id: String,
    pub expected_artifact_id: String,
    pub digest: String,
    pub expected_digest: String,
    pub tool_claim_authorizes_review: bool,
    pub package_claim_authorizes_review: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct McpPackagePostclaimQueryV1 {
    pub tool: McpToolFactsV1,
    pub tool_context: McpToolContextV1,
    pub package_artifact_present: bool,
    /// Supplied after the resident answered `need = postclaim_package`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub package: Option<McpPackagePostclaimFactsV1>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct McpPackagePrecheckQueryV1 {
    pub mode: String,
    pub saved_policy_blocks: bool,
    pub policy_action: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct McpPackageComposeQueryV1 {
    pub mode: String,
    pub tool: McpToolFactsV1,
    pub package: McpPackageFactsV1,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum McpInlineApprovalV1 {
    Allow,
    Denied,
    Fallthrough,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct McpRouteToolCallQueryV1 {
    pub mode: String,
    pub package_present: bool,
    pub asks_for_approval: bool,
    pub inline_available: bool,
    pub tool_name: String,
    pub decision: McpToolFactsV1,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub package_saved_policy_blocks: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub native_prompt_allows: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub inline_approval: Option<McpInlineApprovalV1>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct McpObserveToolForwardQueryV1 {
    pub fresh: McpToolFactsV1,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum McpEvidenceItemKindV1 {
    ClaimFailed,
    ConfigRefreshFailed,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct McpEvidenceItemQueryV1 {
    pub kind: McpEvidenceItemKindV1,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "check", rename_all = "snake_case")]
pub enum McpProxyQueryV1 {
    CatalogEvent(McpCatalogEventQueryV1),
    SavedAllowGate(McpSavedAllowGateQueryV1),
    BoundaryFailure(McpBoundaryFailureQueryV1),
    ToolPostclaim(McpToolPostclaimQueryV1),
    PackagePostclaim(McpPackagePostclaimQueryV1),
    PackagePrecheck(McpPackagePrecheckQueryV1),
    PackageCompose(McpPackageComposeQueryV1),
    RouteToolCall(McpRouteToolCallQueryV1),
    ObserveToolForward(McpObserveToolForwardQueryV1),
    EvidenceItem(McpEvidenceItemQueryV1),
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct McpProxyDecisionRequestV1 {
    pub schema: String,
    #[serde(default)]
    pub request_id: String,
    pub query: McpProxyQueryV1,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct McpProxyDecisionResultV1 {
    pub schema: String,
    pub request_id: String,
    pub request_sha256: String,
    pub status: String,
    pub code: String,
    pub payload: Value,
}

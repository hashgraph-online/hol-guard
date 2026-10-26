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

use crate::mcp_sensitive_read::{
    McpSensitiveReadContextQueryV1, McpSensitiveReadHintQueryV1, McpSensitiveReadReuseQueryV1,
};
use crate::mcp_tool_evidence::McpToolRiskInputV1;

pub const MCP_PROXY_DECISION_REQUEST_SCHEMA: &str = "guard-mcp-proxy-decision-request.v1";
pub const MCP_PROXY_DECISION_RESULT_SCHEMA: &str = "guard-mcp-proxy-decision-result.v1";
pub const MCP_PROXY_DECISION_FEATURE: &str = "mcp-proxy-decision-v1";
/// The resident verifies the downloaded archive files of an archive binding itself.
pub const MCP_PROXY_ARCHIVE_VERIFY_FEATURE: &str = "mcp-proxy-archive-verify-v1";

/// The resident also classifies the answer to an inline approval prompt.
/// An older resident rejects that query as an unknown check, so a caller
/// asks for this capability before sending it.
pub const MCP_PROXY_INLINE_APPROVAL_REPLY_FEATURE: &str = "mcp-proxy-inline-approval-reply-v1";

/// The resident also answers whether an evaluation demands an archive binding
/// at all. An older resident rejects that query as an unknown check, so a
/// caller asks for this capability before sending it.
pub const MCP_PROXY_ARCHIVE_BINDING_REQUIRED_FEATURE: &str =
    "mcp-proxy-archive-binding-required-v1";

/// The resident spells the sensitive read's artifact content hash itself, from
/// the artifact fields the context query now carries. An older resident
/// rejects those fields as unknown, so a caller asks for this capability
/// before sending them.
pub const MCP_SENSITIVE_READ_ARTIFACT_FEATURE: &str = "mcp-sensitive-read-artifact-v1";

/// The resident also writes the text and payload a stopped package-lane call
/// answers with. An older resident rejects that query as an unknown check, so
/// a caller asks for this capability before sending it.
pub const MCP_PROXY_PACKAGE_ANSWER_FEATURE: &str = "mcp-proxy-package-answer-v1";
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

/// One archive the package evaluation downloaded, as it recorded it.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct McpExternalArchiveDownloadV1 {
    pub source_url: String,
    pub path: String,
    pub size: u64,
    pub sha256: String,
}

/// Rebind a `tools/call` (or a launch argv) to the local copies of its
/// external archives. The resident re-verifies every download before binding.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct McpExternalArchiveBindQueryV1 {
    /// The request `params` (or argv array) exactly as received.
    pub params: Value,
    /// The downloads to verify, in the order their replacements apply.
    pub downloads: Vec<McpExternalArchiveDownloadV1>,
    /// Whether the package evaluation demands a binding at all.
    pub requires_binding: bool,
}

/// Classify the answer a client gave to one inline approval prompt.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct McpInlineApprovalReplyQueryV1 {
    /// The answer reduced to its payload: an `elicitation/create` result, or
    /// the cancel the proxy substitutes for an error, a closed stream or a
    /// prompt that timed out.
    pub payload: Value,
    /// The tool the prompt was raised for, named in the block it produces.
    pub tool_name: String,
    /// The server that offered the tool, named alongside it.
    pub server_name: String,
}

/// Whether a package evaluation only permits a request bound to the external
/// archives it verified.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct McpExternalArchiveBindingRequiredQueryV1 {
    /// The package evaluation, exactly as the evaluator produced it.
    pub evaluation: Value,
}

/// Project the reasons of a package evaluation into risk signals.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct McpPackageReasonSignalsQueryV1 {
    pub reasons: Vec<Value>,
}

/// Everything the proxy shows and binds for one `tools/call`: masked
/// arguments and params, the launch target, the browser intent and the risk
/// evidence, in one round trip.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct McpCallProjectionQueryV1 {
    pub tool_name: String,
    /// The request `params` exactly as received.
    pub params: Value,
    /// The call's artifact and arguments; `null` when the proxy has no
    /// artifact yet, which skips the browser intent and risk evidence.
    pub risk: Option<McpToolRiskInputV1>,
}

/// Which stopped answer a package-lane call is given.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum McpPackageAnswerKindV1 {
    /// The tool call is already blocked by authenticated saved policy.
    StoredToolBlock,
    /// The tool policy is terminal (`block` or `sandbox-required`).
    TerminalTool,
    /// The package request is already blocked by stored policy.
    StoredPackageBlock,
    /// The package policy is terminal (`block` or `sandbox-required`).
    TerminalPackage,
    /// The package request is queued for approval.
    QueuePackage,
}

/// Render the answer a stopped package-lane call is given: its message, its
/// payload, the event label and the receipt signals.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct McpPackageAnswerQueryV1 {
    pub kind: McpPackageAnswerKindV1,
    pub tool_name: String,
    pub server_name: String,
    /// The composed policy action; required by the terminal and queued kinds.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy_action: Option<String>,
    /// Whether a stored tool block stopped a package tool call.
    #[serde(default)]
    pub package_request: bool,
    /// The tool decision's receipt signals, echoed by the tool kinds.
    #[serde(default)]
    pub signals: Vec<String>,
    /// The package evaluation exactly as the evaluator produced it; required
    /// by the package kinds.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub evaluation: Option<Value>,
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
    SensitiveReadContext(Box<McpSensitiveReadContextQueryV1>),
    SensitiveReadReuse(McpSensitiveReadReuseQueryV1),
    SensitiveReadHint(McpSensitiveReadHintQueryV1),
    ExternalArchiveBind(McpExternalArchiveBindQueryV1),
    ExternalArchiveBindingRequired(McpExternalArchiveBindingRequiredQueryV1),
    PackageReasonSignals(McpPackageReasonSignalsQueryV1),
    InlineApprovalReply(McpInlineApprovalReplyQueryV1),
    CallProjection(McpCallProjectionQueryV1),
    PackageAnswer(McpPackageAnswerQueryV1),
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

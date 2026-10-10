//! `McpToolPolicyDecide` - wire contract for the resident op that owns the
//! non-package MCP tool-call policy composition.
//!
//! The op is stateless and observation driven. Every request carries the full
//! subject plus the effect results gathered so far; the resident re-runs the
//! deterministic flow and either returns the final decision or names the next
//! effect it needs (`status: "need"`). Python only executes effects (SQLite
//! reads, the claim transaction, authority refresh) and echoes their results
//! back. It never recomputes a verdict.

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

use crate::{BrowserMcpArtifactV1, McpToolArgumentsV1};

/// Schema discriminator for the request.
pub const MCP_TOOL_POLICY_DECIDE_REQUEST_SCHEMA: &str = "guard-mcp-tool-policy-decide-request.v1";
/// Schema discriminator for the result.
pub const MCP_TOOL_POLICY_DECIDE_RESULT_SCHEMA: &str = "guard-mcp-tool-policy-decide-result.v1";
/// Capability advertised by the runtime when this operation is available.
pub const MCP_TOOL_POLICY_DECIDE_FEATURE: &str = "mcp-tool-policy-decide-v1";
/// Largest canonical request serialization the op will accept.
pub const MCP_TOOL_POLICY_DECIDE_MAX_BYTES: usize = 8 * 1024 * 1024;
/// Most effect observations one request may carry.
pub const MCP_TOOL_POLICY_DECIDE_MAX_OBSERVATIONS: usize = 96;

/// One tool call: everything the policy composition reads, in DTO form.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct McpToolPolicySubjectV1 {
    /// The raw `_tool_call_configuration` fields.
    pub config: Map<String, Value>,
    pub workspace: Option<String>,
    pub artifact: BrowserMcpArtifactV1,
    pub artifact_type: String,
    pub artifact_id: String,
    pub harness: String,
    pub publisher: Option<String>,
    pub artifact_hash: String,
    pub arguments: McpToolArgumentsV1,
}

/// An effect the resident asked for and the result Python observed.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct McpToolPolicyObservationV1 {
    pub need: Value,
    pub result: Value,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct McpToolPolicyDecideRequestV1 {
    pub schema: String,
    pub request_id: String,
    /// Whether this call may consume a retained or single-use saved approval.
    pub claim_saved_approval: bool,
    pub subject: McpToolPolicySubjectV1,
    pub observations: Vec<McpToolPolicyObservationV1>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct McpToolPolicyDecideResultV1 {
    pub schema: String,
    pub request_id: String,
    /// `sha256:` digest of the canonical request, binding the reply to it.
    pub request_sha256: String,
    /// `ok` (payload is the decision), `need` (payload is the next effect), or
    /// `error` (fail closed).
    pub status: String,
    /// `ok`, `need`, or a `native_mcp_tool_policy_decide_*` failure code.
    pub code: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub payload: Option<Value>,
}

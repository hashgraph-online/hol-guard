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

use crate::{
    BrowserMcpArtifactV1, ContributedMcpLayerV1, LocalMcpServerMaterialV1, McpInlineApprovalV1,
    McpToolArgumentsV1,
};

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

/// Non-authoritative inputs for the this-device grant and catalog-contribution
/// decision. When present, the resident reads the store and decides in-process
/// instead of asking the caller for an `extension_decision` observation.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct McpExtensionInputV1 {
    /// Absolute path of `guard.db`; must sit directly under `guard_home`.
    pub store_path: String,
    pub guard_home: String,
    pub harness: String,
    pub tool_name: String,
    pub server: LocalMcpServerMaterialV1,
    #[serde(default)]
    pub connection_identity_hash: Option<String>,
    #[serde(default)]
    pub tool_authority_hash: Option<String>,
    #[serde(default)]
    pub launcher_path: Option<String>,
    #[serde(default)]
    pub launcher_home: Option<String>,
    /// The caller could not build the grant inputs; the call is held for review.
    #[serde(default)]
    pub local_unavailable: bool,
    #[serde(default)]
    pub server_identity: Option<Map<String, Value>>,
    #[serde(default)]
    pub artifact_transport: Option<Value>,
    #[serde(default)]
    pub server_name: Option<Value>,
    #[serde(default)]
    pub contributed_tool_name: Option<Value>,
    pub layers: Vec<ContributedMcpLayerV1>,
    /// The caller could not read the extension-control layers; the contributed
    /// decision has no answer and the call is held for review.
    #[serde(default)]
    pub layers_unavailable: bool,
}

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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub extension: Option<McpExtensionInputV1>,
}

/// An effect the resident asked for and the result Python observed.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct McpToolPolicyObservationV1 {
    pub need: Value,
    pub result: Value,
}

/// Route inputs the resident folds into the `ok` payload so the caller does not
/// need separate saved-allow-gate and route-selection round trips. The payload
/// carries `proxy: {gate, route}`; a route that still needs a caller-supplied
/// fact is repeated by the caller through `mcp_proxy_decide`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct McpToolPolicyProxyInputV1 {
    pub catalog_state: String,
    pub mode: String,
    pub package_present: bool,
    pub asks_for_approval: bool,
    pub inline_available: bool,
    pub tool_name: String,
    /// The inline prompt's answer, when the caller has already raised it.
    /// Left out, an inline-capable route asks for the `inline_approval` fact
    /// as before, so an existing caller's payload is unchanged.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub inline_approval: Option<McpInlineApprovalV1>,
}

/// Evidence for the saved-policy lookup, so the resident reads the store in
/// the same call instead of naming a `policy_lookup` effect.
///
/// The keyring-facing integrity material and the integrity state are
/// caller-shipped exactly as for the `policy_decision_lookup` op; the resident
/// owns everything else: the per-call request fields, the portable-workspace
/// composition and the most-restrictive choice over the subject's candidate ids.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct McpPolicyLookupInputV1 {
    pub store_path: String,
    pub guard_home: String,
    /// Canonical lookup timestamp, shared by every candidate probe.
    pub now: String,
    /// Git-derived portable workspace, when the workspace has one.
    #[serde(default)]
    pub portable_workspace: Option<String>,
    #[serde(default)]
    pub integrity_state: Option<Value>,
    #[serde(default)]
    pub integrity_key_b64: Option<String>,
    #[serde(default)]
    pub integrity_key_id: Option<String>,
    #[serde(default)]
    pub local_once_integrity_key_b64: Option<String>,
    #[serde(default)]
    pub local_once_integrity_key_id: Option<String>,
    #[serde(default)]
    pub policy_bundle_decision_identities: Option<Vec<Vec<Value>>>,
    /// The caller could not establish integrity authority for this home; every
    /// probe is an empty degraded lookup carrying this trust status.
    #[serde(default)]
    pub degraded_trust_status: Option<Value>,
    /// The store holds no saved policy or local-once rows, so a miss has
    /// nothing to diagnose and needs no `reuse_diagnostic` effect.
    #[serde(default)]
    pub diagnostic_empty: bool,
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proxy: Option<McpToolPolicyProxyInputV1>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lookup: Option<McpPolicyLookupInputV1>,
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

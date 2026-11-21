//! `GithubWorkflowPrepare` — wire contract for the resident GitHub workflow
//! descriptor/verification op.
//!
//! `describe` mode collects the live `git`/`gh` context for one hook command and
//! returns the privacy-safe approval record plus the exact command identity.
//! `verify` mode re-derives a persisted record's command binding natively.
//! `lineage` mode decides whether a persisted approval request, the Guard
//! operation it resolved and that operation's session are one unbroken
//! workflow lineage; the host reads those three rows and ships them.

use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;

pub const GITHUB_WORKFLOW_PREPARE_REQUEST_SCHEMA: &str = "guard-github-workflow-prepare-request.v1";
pub const GITHUB_WORKFLOW_PREPARE_RESULT_SCHEMA: &str = "guard-github-workflow-prepare-result.v1";
pub const GITHUB_WORKFLOW_PREPARE_FEATURE: &str = "github-workflow-prepare-v1";

/// Largest canonical request serialization the op accepts (the effective
/// environment is part of the request).
pub const GITHUB_WORKFLOW_PREPARE_MAX_BYTES: usize = 1024 * 1024;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct GithubWorkflowPrepareRequestV1 {
    pub schema: String,
    pub request_id: String,
    /// `describe`, `verify` or `lineage`.
    pub mode: String,
    /// The hook command `describe` prepares and `verify` re-derives. `lineage`
    /// reads the command out of the operation's metadata instead and sends an
    /// empty string here.
    pub command_text: String,
    /// `describe`: workspace root the hook runs in.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub workspace: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub config_path: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub configuration: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sandbox: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub environment: Option<BTreeMap<String, String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy_version: Option<String>,
    /// `verify`: the persisted approval record to re-derive.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub record: Option<Value>,
    /// `lineage`: the persisted approval request row.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub approval_request: Option<Value>,
    /// `lineage`: the Guard operation the request resolved.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub operation: Option<Value>,
    /// `lineage`: the Guard session the operation names.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session: Option<Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct GithubWorkflowPrepareResultV1 {
    pub schema: String,
    pub request_id: String,
    /// SHA-256 of the canonical request, binding the result to its request.
    pub request_sha256: String,
    /// `ok` or `error`.
    pub status: String,
    /// `ok`, or one of the `native_github_workflow_prepare_*` failure codes.
    pub code: String,
    /// `describe`: the exact command identity of the prepared operation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub command_identity: Option<String>,
    /// `describe`: the approval record (absent when the command is not an
    /// exactly bindable GitHub workflow operation).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub record: Option<Value>,
    /// `verify`: whether the persisted command still matches the record.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub verified: Option<bool>,
    /// `lineage`: the validated identities — `request_id`, `operation_id`,
    /// `session_id` and the approval `record`. A broken lineage leaves this
    /// absent and sets `code` to `none`; which condition broke it stays in
    /// the runtime, since the messages quote workspace paths and identifiers.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lineage: Option<Value>,
}

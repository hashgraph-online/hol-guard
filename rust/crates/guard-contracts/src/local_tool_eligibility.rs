//! Local tool grant eligibility contract.
//!
//! The resident decides whether one shell command is a read-only local tool
//! invocation whose verified launch identity may carry a reusable grant. The
//! caller sends only the command, its directories and launch environment; it
//! never supplies identity material or a verdict.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Schema discriminator for the request.
pub const LOCAL_TOOL_ELIGIBILITY_REQUEST_SCHEMA: &str = "guard-local-tool-eligibility-request.v1";
/// Schema discriminator for the result.
pub const LOCAL_TOOL_ELIGIBILITY_RESULT_SCHEMA: &str = "guard-local-tool-eligibility-result.v1";
/// Capability advertised by the runtime when `local_tool_eligibility` is available.
pub const LOCAL_TOOL_ELIGIBILITY_FEATURE: &str = "local-tool-eligibility-v1";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct LocalToolEligibilityRequestV1 {
    pub schema: String,
    pub request_id: String,
    pub command: String,
    /// Directory the command runs in.
    pub cwd: String,
    /// The hook's home directory, when the hook supplied one.
    #[serde(default)]
    pub home_dir: Option<String>,
    /// The requesting user's home, for secret-path classification.
    #[serde(default)]
    pub user_home: Option<String>,
    /// The launch environment executables resolve against.
    pub launch_env: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct LocalToolEligibilityResultV1 {
    pub schema: String,
    pub request_id: String,
    /// `sha256:` digest of the canonical request, binding the reply to it.
    pub request_sha256: String,
    /// `ok`.
    pub status: String,
    /// `ok`.
    pub code: String,
    /// `null` when ineligible, else `{tool_name, tool_identity_hash,
    /// capability, read_only_reason, trust_basis, indefinite_allowed}`.
    #[serde(default)]
    pub payload: Value,
}

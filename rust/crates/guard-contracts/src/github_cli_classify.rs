//! `GithubCliClassify` — wire contract for the resident GitHub CLI capability
//! classification op.
//!
//! The op is pure (no IO, no SQLite): the request carries the GitHub CLI
//! argument vector (without the leading `gh`), and the result carries the
//! `GitHubCommandAssessment` the native command model computed.

use serde::{Deserialize, Serialize};

/// Schema discriminator for the request.
pub const GITHUB_CLI_CLASSIFY_REQUEST_SCHEMA: &str = "guard-github-cli-classify-request.v1";
/// Schema discriminator for the result.
pub const GITHUB_CLI_CLASSIFY_RESULT_SCHEMA: &str = "guard-github-cli-classify-result.v1";
/// Capability advertised by the runtime when this operation is available.
pub const GITHUB_CLI_CLASSIFY_FEATURE: &str = "github-cli-classify-v1";

/// Largest canonical request serialization the op will accept.
pub const GITHUB_CLI_CLASSIFY_MAX_BYTES: usize = 256 * 1024;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct GithubCliClassifyRequestV1 {
    pub schema: String,
    /// Optional caller correlation id; echoed back in the result.
    #[serde(default)]
    pub request_id: String,
    /// GitHub CLI arguments, excluding the leading `gh` executable token.
    pub args: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct GithubCliAssessmentV1 {
    /// Strongest capability (`read_local`, ..., `unknown`).
    pub capability: String,
    pub reason_code: String,
    pub detail: String,
    /// Unique capabilities in canonical order; `capability` is the strongest.
    pub capabilities: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct GithubCliClassifyResultV1 {
    pub schema: String,
    pub request_id: String,
    /// SHA-256 of the canonical request, binding the result to its request.
    pub request_sha256: String,
    /// `ok` or `error`.
    pub status: String,
    /// `ok`, or one of the `native_github_cli_classify_*` failure codes.
    pub code: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub assessment: Option<GithubCliAssessmentV1>,
    /// The single unambiguous static Markdown body file of a `gh pr create`
    /// proposal, when the argument vector is exactly that shape.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pr_body_file_operand: Option<String>,
}

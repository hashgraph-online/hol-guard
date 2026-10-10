//! `CodexToolOutput` — wire contract for the resident op that reviews Codex
//! tool-output commands: read-only source inspection, secret-like source
//! names, git pathspec identities, local-content reads and focused pytest.
//!
//! Python sends the command text and observed facts (process working
//! directory, home, account home, groups, a bounded environment snapshot and
//! the `git` executable it resolved); Rust owns every verdict. Python must send
//! every field explicitly (nulls included) so the request digest it binds
//! matches the resident's.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// Schema discriminator for the request.
pub const CODEX_TOOL_OUTPUT_REQUEST_SCHEMA: &str = "guard-codex-tool-output-request.v1";
/// Schema discriminator for the result.
pub const CODEX_TOOL_OUTPUT_RESULT_SCHEMA: &str = "guard-codex-tool-output-result.v1";
/// Capability advertised by the runtime when this operation is available.
pub const CODEX_TOOL_OUTPUT_FEATURE: &str = "codex-tool-output-v1";
/// Largest request the op accepts.
pub const CODEX_TOOL_OUTPUT_MAX_BYTES: usize = 256 * 1024;

/// One command reviewed with a working directory and an optional home.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct CodexCommandScopeV1 {
    pub command: String,
    pub cwd: Option<String>,
    pub home_dir: Option<String>,
}

/// Several commands from one post-tool payload.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct CodexCommandsScopeV1 {
    pub commands: Vec<String>,
    pub cwd: Option<String>,
    pub home_dir: Option<String>,
}

/// One command reviewed for secret-like source names.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct CodexSecretNameScopeV1 {
    pub command: String,
    pub cwd: Option<String>,
    pub home_dir: Option<String>,
    /// Apply the shell execution-context policy (tool-output variant).
    pub exec_context: bool,
}

/// One command with a working directory only.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct CodexCommandCwdV1 {
    pub command: String,
    pub cwd: Option<String>,
}

/// One command text.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct CodexCommandTextV1 {
    pub command: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum CodexToolOutputActionV1 {
    /// A read-only source search, view, chain or pipeline.
    ReadOnlyInspection(CodexCommandScopeV1),
    /// Every post-tool command is a read-only inspection or git metadata read.
    PostToolReadOnly(CodexCommandsScopeV1),
    /// A command targets a secret-like source file name.
    SecretLikeSourceName(CodexSecretNameScopeV1),
    /// The `git diff` pathspec selection identity (`value`).
    GitPathspecIdentity(CodexCommandCwdV1),
    /// The context-free tail of the local-content-read review.
    LocalContentTail(CodexCommandCwdV1),
    /// An environment dump piped onward.
    ReadsEnvironmentPipeline(CodexCommandTextV1),
    /// A focused pytest verification command.
    FocusedPytest(CodexCommandTextV1),
    /// A read-only git metadata command.
    GitMetadata(CodexCommandCwdV1),
}

/// Observed caller facts.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct CodexToolOutputFactsV1 {
    /// `os.getcwd()` of the caller.
    pub process_cwd: String,
    /// `Path.home()` of the caller.
    pub home: String,
    /// The passwd-database home of the current account, when resolvable.
    pub account_home: Option<String>,
    /// Observed process group ids (primary and supplementary).
    pub groups: Vec<u32>,
    /// Bounded snapshot of the process environment the review reads.
    pub environment: BTreeMap<String, String>,
    /// `shutil.which("git")` of the caller.
    pub git_executable: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct CodexToolOutputRequestV1 {
    pub schema: String,
    #[serde(default)]
    pub request_id: String,
    pub action: CodexToolOutputActionV1,
    pub facts: CodexToolOutputFactsV1,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct CodexToolOutputResultV1 {
    pub schema: String,
    pub request_id: String,
    /// SHA-256 of the canonical request, binding the result to its request.
    pub request_sha256: String,
    /// `ok` or `error`.
    pub status: String,
    /// `ok`, or a `native_codex_tool_output_*` failure code.
    pub code: String,
    /// The verdict. Always false when `status` is `error`.
    pub allowed: bool,
    /// The identity string for `git_pathspec_identity`, when one exists.
    pub value: Option<String>,
}

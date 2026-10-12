//! `GitExecutionSafety` — wire contract for the resident op that decides
//! whether a Git invocation can execute configured helpers, hooks or
//! transports.
//!
//! The decision is authority-bearing: callers treat `allowed` as the proof
//! that a Git inspection or routine may be classified as non-executing.
//! Callers send observed facts (cwd, home, a bounded environment snapshot,
//! the account home directory); Rust owns every verdict.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// Schema discriminator for the request.
pub const GIT_EXECUTION_SAFETY_REQUEST_SCHEMA: &str = "guard-git-execution-safety-request.v1";
/// Schema discriminator for the result.
pub const GIT_EXECUTION_SAFETY_RESULT_SCHEMA: &str = "guard-git-execution-safety-result.v1";
/// Capability advertised by the runtime when this operation is available.
pub const GIT_EXECUTION_SAFETY_FEATURE: &str = "git-execution-safety-v1";
/// Largest request the op accepts.
pub const GIT_EXECUTION_SAFETY_MAX_BYTES: usize = 128 * 1024;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum GitExecutionSafetyCheckV1 {
    /// `git_path` is a Git executable outside user-controlled roots.
    BinaryTrusted,
    /// Resolve `git` from the snapshot `PATH` and require trust.
    ResolveBinary,
    /// No Git configuration-routing variable is set.
    ConfigEnvironmentClean,
    /// `arguments` is a `git status` with only read-only flags.
    StatusArguments,
    /// `git status` cannot run a pager or fsmonitor helper.
    StatusConfig,
    /// Object queries cannot lazily fetch missing objects.
    ObjectQuery,
    /// `git fetch origin` cannot route execution.
    FetchOrigin,
    /// `git push origin <branch>` cannot route execution.
    PushOrigin,
    /// `git worktree add ... <reference>` cannot run checkout code.
    WorktreeAdd,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct GitExecutionSafetyRequestV1 {
    pub schema: String,
    #[serde(default)]
    pub request_id: String,
    pub check: GitExecutionSafetyCheckV1,
    /// Execution directory the Git command would run in.
    pub cwd: String,
    /// The caller's home directory (`Path.home()`).
    pub home: String,
    /// The passwd-database home of the current account, when resolvable.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub account_home: Option<String>,
    /// Observed process group ids (primary and supplementary) of the caller.
    #[serde(default)]
    pub groups: Vec<u32>,
    /// Bounded snapshot of the Git-relevant process environment.
    #[serde(default)]
    pub environment: BTreeMap<String, String>,
    /// Already-resolved Git executable the caller will run.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub git_binary: Option<String>,
    /// Executable path for `binary_trusted`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub git_path: Option<String>,
    /// Arguments for `status_arguments`.
    #[serde(default)]
    pub arguments: Vec<String>,
    /// Branch for `push_origin`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub branch: Option<String>,
    /// Ref for `worktree_add`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reference: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct GitExecutionSafetyResultV1 {
    pub schema: String,
    pub request_id: String,
    /// SHA-256 of the canonical request, binding the result to its request.
    pub request_sha256: String,
    /// `ok` or `error`.
    pub status: String,
    /// `ok`, or a `native_git_execution_safety_*` failure code.
    pub code: String,
    /// The verdict. Always false when `status` is `error`.
    pub allowed: bool,
    /// The trusted Git executable for `resolve_binary` when allowed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resolved_path: Option<String>,
}

//! `CompoundGitInspection` — wire contract for the resident op that decides
//! whether a modeled shell command is a deterministic, bounded Git routine.
//!
//! The decision is authority-bearing: callers treat `allowed` as the proof
//! that a Git chain may be classified as a low-risk inspection. Callers send
//! the modeled shell segments and observed facts (home, account home, groups,
//! a bounded environment snapshot); Rust owns every verdict.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// Schema discriminator for the request.
pub const COMPOUND_GIT_INSPECTION_REQUEST_SCHEMA: &str = "guard-compound-git-inspection-request.v1";
/// Schema discriminator for the result.
pub const COMPOUND_GIT_INSPECTION_RESULT_SCHEMA: &str = "guard-compound-git-inspection-result.v1";
/// Capability advertised by the runtime when this operation is available.
pub const COMPOUND_GIT_INSPECTION_FEATURE: &str = "compound-git-inspection-v1";
/// Largest request the op accepts.
pub const COMPOUND_GIT_INSPECTION_MAX_BYTES: usize = 256 * 1024;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum CompoundGitCheckV1 {
    /// A leading literal `cd` followed by bounded Git, echo and head/tail
    /// segments joined by `&&` and `|`.
    Compound,
    /// One bounded Git refresh or inspection segment.
    Segment,
    /// One current-branch push to a verified GitHub origin.
    PushSegment,
    /// One standalone Git read or configured-origin ref refresh.
    Standalone,
    /// An exact, output-free `git cat-file -e <object>` query.
    ObjectExistenceQuery,
    /// Canonical unquoted current-user `git -C ~/<path>` operand extraction.
    HomeGitCPath,
    /// A safe repository-relative path.
    RepositoryPath,
    /// Every pathspec after `--` in a staged diff is a safe repository path
    /// or a safe `:!`/`:^` exclusion (one request for the whole list).
    CachedDiffPathspecs,
    /// `git diff`/`show`/`blame` cannot run an external diff or textconv.
    ShowConfig,
    /// Git log-family output cannot invoke an executable pager.
    LogConfig,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct CompoundGitSegmentV1 {
    #[serde(default)]
    pub tokens: Vec<String>,
    #[serde(default)]
    pub control_before: Vec<String>,
    #[serde(default)]
    pub control_after: Vec<String>,
    /// Absolute effective working directory of the segment, when modeled.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub effective_cwd: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub directory_operation: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct CompoundGitInspectionRequestV1 {
    pub schema: String,
    #[serde(default)]
    pub request_id: String,
    pub check: CompoundGitCheckV1,
    /// Modeled shell segments for segment-based checks.
    #[serde(default)]
    pub segments: Vec<CompoundGitSegmentV1>,
    /// Whether the shell model was complete.
    #[serde(default)]
    pub complete: bool,
    /// Command text for `object_existence_query` and `home_git_c_path`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub command_text: Option<String>,
    /// Path operand for `repository_path`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub value: Option<String>,
    /// Pathspecs for `cached_diff_pathspecs`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub values: Vec<String>,
    /// Absolute execution directory for `object_existence_query`/`log_config`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cwd: Option<String>,
    /// Trusted home directory a `~/` Git `-C` operand may resolve under.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub home_dir: Option<String>,
    /// `-C` operand for `show_config`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub repository_path: Option<String>,
    /// Pager key for `log_config` (`pager.log` when absent).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pager_key: Option<String>,
    /// Already-resolved Git executable for `log_config`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub git_binary: Option<String>,
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
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct CompoundGitInspectionResultV1 {
    pub schema: String,
    pub request_id: String,
    /// SHA-256 of the canonical request, binding the result to its request.
    pub request_sha256: String,
    /// `ok` or `error`.
    pub status: String,
    /// `ok`, or a `native_compound_git_inspection_*` failure code.
    pub code: String,
    /// The verdict. Always false when `status` is `error`.
    pub allowed: bool,
    /// The extracted path for `home_git_c_path` when allowed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub value: Option<String>,
}

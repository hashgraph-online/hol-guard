//! Canonical native request-context contract.
//!
//! One resident round trip admits a request and builds its authoritative
//! context: owner, budget and policy generation admission, the shell working
//! directory model (workspace, cwd, symlink and descriptor identities), and
//! the runtime launch identity of the executable. Callers send only claims
//! (paths, argv, a policy snapshot, an owner id); every hash, identity and
//! allow bit in the reply is derived by the resident from the real filesystem.
//! A hash a caller computed itself is never accepted as execution authority.

use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;

pub const REQUEST_CONTEXT_REQUEST_SCHEMA: &str = "guard-request-context-request.v1";
pub const REQUEST_CONTEXT_RESULT_SCHEMA: &str = "guard-request-context-result.v1";
/// Domain tag bound into the canonical context digest.
pub const REQUEST_CONTEXT_SCHEMA: &str = "guard-request-context.v1";
pub const REQUEST_CONTEXT_FEATURE: &str = "request-context-v1";
/// Upper bound on the caller-declared remaining time budget.
pub const MAX_REQUEST_CONTEXT_BUDGET_MS: u64 = 60_000;
pub const MAX_REQUEST_CONTEXT_PATH_BYTES: usize = 32 * 1024;
pub const MAX_REQUEST_CONTEXT_SCRIPT_BYTES: usize = 1024 * 1024;
pub const MAX_REQUEST_CONTEXT_ARGV: usize = 4096;
pub const MAX_REQUEST_CONTEXT_SEGMENTS: usize = 4096;
/// Path proofs one modeled segment may carry (its own and its directory stack's).
pub const MAX_REQUEST_CONTEXT_SEGMENT_PROOFS: usize = 4096;
/// Path proofs summed over every segment of one context.
pub const MAX_REQUEST_CONTEXT_TOTAL_PROOFS: usize = 64 * 1024;

/// Entry point that asked for the context.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RequestContextSourceV1 {
    Hook,
    DirectCommand,
    GuardRun,
    Package,
    Mcp,
}

impl RequestContextSourceV1 {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Hook => "hook",
            Self::DirectCommand => "direct_command",
            Self::GuardRun => "guard_run",
            Self::Package => "package",
            Self::Mcp => "mcp",
        }
    }
}

/// Policy identity claim: the snapshot the caller evaluated against and the
/// generation it believes is current. The resident checks they agree.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct RequestContextPolicyV1 {
    pub generation: u64,
    pub snapshot: Value,
}

/// Executable launch claim; identities are rebuilt natively.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct RequestContextExecutableV1 {
    pub command: Option<Value>,
    #[serde(default)]
    pub args: Vec<Value>,
    #[serde(default)]
    pub structured_command: bool,
    #[serde(default)]
    pub direct_executable: bool,
    #[serde(default)]
    pub search_path: Option<String>,
    /// Intentionally scoped runtime credentials stay in the launch
    /// environment; only their binding digest leaves the resident.
    #[serde(default)]
    pub launch_env: Option<BTreeMap<String, String>>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct RequestContextBuildV1 {
    #[serde(default)]
    pub policy: Option<RequestContextPolicyV1>,
    /// Workspace root; defaults to the effective cwd.
    #[serde(default)]
    pub workspace: Option<String>,
    /// Caller-declared cwd. Absent means the caller's process cwd.
    #[serde(default)]
    pub cwd: Option<String>,
    /// The caller's process cwd, used when `cwd` is absent.
    #[serde(default)]
    pub fallback_cwd: Option<String>,
    #[serde(default)]
    pub home_dir: Option<String>,
    /// Shell script or command text to model.
    #[serde(default)]
    pub script: Option<String>,
    #[serde(default)]
    pub target: Option<String>,
    #[serde(default)]
    pub executable: Option<RequestContextExecutableV1>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ShellPathIdentityV1 {
    pub device: u64,
    pub inode: u64,
    pub mode: u32,
    pub change_time_ns: i64,
    pub creation_time_ns: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ShellPathProofV1 {
    pub lexical_path: String,
    pub resolved_path: String,
    pub identity: ShellPathIdentityV1,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ShellSegmentV1 {
    pub tokens: Vec<String>,
    pub segment_index: u64,
    pub control_before: Vec<String>,
    pub control_after: Vec<String>,
    pub effective_cwd: Option<String>,
    pub cwd_identity: Option<ShellPathIdentityV1>,
    pub cwd_path_proofs: Vec<ShellPathProofV1>,
    pub cwd_source: String,
    pub directory_stack: Vec<String>,
    pub complete: bool,
    pub reason_code: Option<String>,
    pub directory_operation: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ShellContextV1 {
    pub command_text: String,
    pub initial_cwd: Option<String>,
    pub workspace_root: Option<String>,
    pub workspace_identity: Option<ShellPathIdentityV1>,
    pub segments: Vec<ShellSegmentV1>,
    pub complete: bool,
    pub reason_code: Option<String>,
    pub directory_change_present: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "kind", content = "body", rename_all = "snake_case")]
pub enum RequestContextKindV1 {
    /// Admit the request and build the whole canonical context.
    Build(RequestContextBuildV1),
    /// Re-read the filesystem and prove one modeled segment is unchanged.
    /// The supplied context is a claim; the filesystem is the authority.
    ValidateSegment {
        context: ShellContextV1,
        segment_index: u64,
    },
    /// Recompute the canonical context (and optional segment) hash.
    Hash {
        context: ShellContextV1,
        #[serde(default)]
        segment_index: Option<u64>,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct RequestContextRequestV1 {
    pub schema: String,
    pub request_id: String,
    /// Absolute guard home, used to route the request to its resident.
    pub guard_home: String,
    pub source: RequestContextSourceV1,
    /// Remaining time budget in milliseconds; the resident fails closed once
    /// its own elapsed time reaches it.
    pub budget_ms: u64,
    /// Effective uid the caller runs as; must match the resident (unix).
    #[serde(default)]
    pub owner_uid: Option<u32>,
    pub action: RequestContextKindV1,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct RequestContextResultV1 {
    pub schema: String,
    pub request_id: String,
    pub request_sha256: String,
    pub status: String,
    pub code: String,
    pub payload: Option<Value>,
}

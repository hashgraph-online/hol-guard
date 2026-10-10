//! Skill-directory identity contract.
//!
//! The resident walks a skill directory itself and returns either a complete
//! canonical tree digest or a typed, non-reusable incomplete state. Callers
//! supply only paths and resource ceilings; they never supply or recompute a
//! digest. The same operation also performs bounded discovery of primary skill
//! documents, so omitted-scope gaps arrive with their own incomplete identity.

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Schema discriminator for the request.
pub const SKILL_DIRECTORY_IDENTITY_REQUEST_SCHEMA: &str =
    "guard-skill-directory-identity-request.v1";
/// Schema discriminator for the result.
pub const SKILL_DIRECTORY_IDENTITY_RESULT_SCHEMA: &str = "guard-skill-directory-identity-result.v1";
/// Capability advertised by the runtime when this operation is available.
pub const SKILL_DIRECTORY_IDENTITY_FEATURE: &str = "skill-directory-identity-v1";
/// Schema tag bound into every identity digest and incomplete-state hash.
pub const SKILL_DIRECTORY_IDENTITY_SCHEMA: &str = "guard.skill-directory-identity.v1";

/// Typed reason an identity is incomplete. Serialized names are the wire and
/// metadata spellings.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SkillDirectoryFailureV1 {
    RootMissing,
    RootNotDirectory,
    PrimaryMissing,
    PrimarySymlinkUnsupported,
    InvalidRelativePath,
    InvalidPathEncoding,
    DuplicatePath,
    CaseCollision,
    UnreadableEntry,
    SpecialFile,
    SymlinkBroken,
    SymlinkLoop,
    SymlinkEscape,
    SymlinkDirectoryUnsupported,
    UnsupportedReparsePoint,
    MaxDepthExceeded,
    MaxEntriesExceeded,
    MaxFileBytesExceeded,
    MaxTotalBytesExceeded,
    TreeChangedDuringHash,
}

impl SkillDirectoryFailureV1 {
    /// Wire spelling, used inside digest material.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::RootMissing => "root_missing",
            Self::RootNotDirectory => "root_not_directory",
            Self::PrimaryMissing => "primary_missing",
            Self::PrimarySymlinkUnsupported => "primary_symlink_unsupported",
            Self::InvalidRelativePath => "invalid_relative_path",
            Self::InvalidPathEncoding => "invalid_path_encoding",
            Self::DuplicatePath => "duplicate_path",
            Self::CaseCollision => "case_collision",
            Self::UnreadableEntry => "unreadable_entry",
            Self::SpecialFile => "special_file",
            Self::SymlinkBroken => "symlink_broken",
            Self::SymlinkLoop => "symlink_loop",
            Self::SymlinkEscape => "symlink_escape",
            Self::SymlinkDirectoryUnsupported => "symlink_directory_unsupported",
            Self::UnsupportedReparsePoint => "unsupported_reparse_point",
            Self::MaxDepthExceeded => "max_depth_exceeded",
            Self::MaxEntriesExceeded => "max_entries_exceeded",
            Self::MaxFileBytesExceeded => "max_file_bytes_exceeded",
            Self::MaxTotalBytesExceeded => "max_total_bytes_exceeded",
            Self::TreeChangedDuringHash => "tree_changed_during_hash",
        }
    }
}

/// Resource ceilings for one inspection or discovery.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SkillDirectoryLimitsV1 {
    pub max_depth: u64,
    pub max_entries: u64,
    pub max_file_bytes: u64,
    pub max_total_bytes: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum SkillDirectoryCommandV1 {
    /// Hash the directory that holds `skill_document`.
    Inspect {
        /// Absolute path of the primary skill document.
        skill_document: String,
        /// Absolute path of the scope the skill root must stay inside.
        scope_root: String,
        limits: SkillDirectoryLimitsV1,
    },
    /// Find primary skill documents below `skill_root`.
    Discover {
        /// Absolute path of the skill grouping root.
        skill_root: String,
        limits: SkillDirectoryLimitsV1,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct SkillDirectoryIdentityRequestV1 {
    pub schema: String,
    pub request_id: String,
    /// Absolute path of the guard home that owns the resident.
    pub guard_home: String,
    pub command: SkillDirectoryCommandV1,
}

/// Identity of one skill directory. `incomplete_state_hash` is present exactly
/// when `status` is `incomplete`; `directory_hash` exactly when `complete`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SkillDirectoryIdentityV1 {
    pub schema_version: String,
    pub status: String,
    pub directory_hash: Option<String>,
    pub primary_content_hash: Option<String>,
    pub entry_count: u64,
    pub total_bytes: u64,
    pub failure_reason: Option<SkillDirectoryFailureV1>,
    pub incomplete_state_hash: Option<String>,
}

/// One omitted-scope gap found during discovery.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SkillDiscoveryIssueV1 {
    /// Hex of the raw bytes of the `/`-joined path below the root, or of `.`.
    pub relative_path_hex: String,
    pub failure_reason: SkillDirectoryFailureV1,
    pub issue_id: String,
    pub identity: SkillDirectoryIdentityV1,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SkillDiscoveryV1 {
    /// Hex of the raw bytes of each document path below the root, sorted.
    pub documents_hex: Vec<String>,
    pub issues: Vec<SkillDiscoveryIssueV1>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct SkillDirectoryIdentityResultV1 {
    pub schema: String,
    pub request_id: String,
    /// `sha256:` digest of the canonical request, binding the reply to it.
    pub request_sha256: String,
    /// `ok` or `error`.
    pub status: String,
    /// `ok`, or a `native_skill_directory_identity_*` failure code.
    pub code: String,
    /// A `SkillDirectoryIdentityV1` for `inspect`, or a `SkillDiscoveryV1` for
    /// `discover`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub payload: Option<Value>,
}

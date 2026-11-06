//! Bounded native archive-inspection request/response contract.
//!
//! The Python adapter constructs this request, hands it to
//! `hol-guard-runtime archive-inspect --stdin`, and projects the typed result
//! back to the package evaluator. The contract carries no authority beyond
//! the digest-bound local blob the caller already downloaded.

use serde::{Deserialize, Serialize};

/// Schema discriminator for the stdin request.
pub const ARCHIVE_INSPECTION_REQUEST_SCHEMA: &str = "guard-archive-inspection.v1";
/// Schema discriminator for the stdout result.
pub const ARCHIVE_INSPECTION_RESULT_SCHEMA: &str = "guard-archive-inspection-result.v1";
/// Capability advertised by the runtime when this operation is available.
pub const ARCHIVE_INSPECTION_FEATURE: &str = "archive-inspection-v1";

/// Upper bounds the runtime enforces on caller-supplied caps. Anything above
/// these ceilings is rejected as an invalid policy request.
pub const ARCHIVE_CAP_ARCHIVE_BYTES: u64 = 64 * 1024 * 1024;
pub const ARCHIVE_CAP_FILES: u64 = 10_000;
pub const ARCHIVE_CAP_EXPANDED_BYTES: u64 = 256 * 1024 * 1024;
pub const ARCHIVE_CAP_MEMBER_BYTES: u64 = 64 * 1024 * 1024;
pub const ARCHIVE_CAP_PACKAGE_JSON_BYTES: u64 = 8 * 1024 * 1024;
pub const ARCHIVE_CAP_MEMORY_BYTES: u64 = 2 * 1024 * 1024 * 1024;
pub const ARCHIVE_CAP_DECOMPRESSION_RATIO: f64 = 10_000.0;
pub const ARCHIVE_CAP_NESTED_ARCHIVES: u64 = 64;
pub const ARCHIVE_CAP_PATH_DEPTH: u64 = 256;
/// Longest inspection budget the runtime will accept.
pub const ARCHIVE_CAP_TIMEOUT_MS: u64 = 60_000;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ArchiveInspectionCapsV1 {
    pub max_archive_bytes: u64,
    pub max_files: u64,
    pub max_expanded_bytes: u64,
    pub max_member_bytes: u64,
    pub max_package_json_bytes: u64,
    pub max_memory_bytes: u64,
    pub max_decompression_ratio: f64,
    pub max_nested_archives: u64,
    pub max_path_depth: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ArchiveInspectionRequestV1 {
    pub schema: String,
    pub request_id: String,
    /// Caller-side path to the downloaded blob. The runtime canonicalizes and
    /// revalidates it; the file must be regular, single-linked, and read-only.
    pub archive_path: String,
    /// Canonical Guard-home directory the caller is inspecting under. The
    /// worker itself takes `archive-inspect.lock` inside it so admission is
    /// owned natively: any client — adapter or direct — contends on the same
    /// kernel lease and a saturated slot is a bounded `overloaded` result,
    /// never a queue.
    pub state_dir: String,
    /// Lowercase hex SHA-256 the caller bound to the blob at download time.
    pub expected_sha256: String,
    pub timeout_ms: u64,
    pub caps: ArchiveInspectionCapsV1,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ArchiveInspectionCountersV1 {
    pub members: u64,
    pub expanded_bytes: u64,
    pub elapsed_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ArchiveInspectionResultV1 {
    pub schema: String,
    pub request_id: String,
    /// SHA-256 of the raw request bytes, binding the result to its request.
    pub request_sha256: String,
    /// `clean`, `blocked`, or `incomplete`.
    pub status: String,
    pub code: String,
    pub message: String,
    /// `low`, `medium`, `high`, or `critical`.
    pub severity: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sha256: Option<String>,
    /// SHA-256 of the runtime binary that produced this result. The caller
    /// already resolved the binary identity before spawning; echoing it binds
    /// the typed result to that attested binary instead of whatever wrote to
    /// the pipe.
    pub runtime_sha256: String,
    pub counters: ArchiveInspectionCountersV1,
}

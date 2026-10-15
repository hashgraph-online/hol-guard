//! Private resident boundary for approved external archive acquisition.
//!
//! URLs and trust roots travel only over the owner-bound resident channel.
//! The retained policy service supplies trust material; native code owns URL,
//! DNS, peer, TLS, redirect, header, deadline, size and blob enforcement.

use serde::{Deserialize, Serialize};

pub const ARCHIVE_ACQUISITION_FEATURE: &str = "archive-acquisition-v1";
pub const ARCHIVE_ACQUISITION_REQUEST_SCHEMA: &str = "hol-guard.archive-acquisition-request.v1";
pub const ARCHIVE_ACQUISITION_RESULT_SCHEMA: &str = "hol-guard.archive-acquisition-result.v1";
pub const ARCHIVE_ACQUISITION_MAX_REQUEST_BYTES: usize = 2 * 1024 * 1024;
pub const ARCHIVE_ACQUISITION_MAX_URL_BYTES: usize = 32 * 1024;
pub const ARCHIVE_ACQUISITION_MAX_ROOTS: usize = 1024;
pub const ARCHIVE_ACQUISITION_MAX_CERT_BYTES: usize = 16 * 1024;
pub const ARCHIVE_ACQUISITION_MAX_BYTES: u64 = 6 * 1024 * 1024;
pub const ARCHIVE_ACQUISITION_MAX_TIMEOUT_MS: u64 = 8_000;

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ArchiveAcquisitionRequestV1 {
    pub schema: String,
    pub request_id: String,
    pub guard_home: String,
    pub query: ArchiveAcquisitionQueryV1,
}

impl std::fmt::Debug for ArchiveAcquisitionRequestV1 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ArchiveAcquisitionRequestV1")
            .field("schema", &self.schema)
            .field("action", &self.query.action)
            .finish_non_exhaustive()
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ArchiveAcquisitionActionV1 {
    Destination,
    Download,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ArchiveAcquisitionQueryV1 {
    pub action: ArchiveAcquisitionActionV1,
    pub source_url: String,
    pub max_bytes: i64,
    pub max_redirects: i64,
    pub timeout_ms: i64,
    /// Same-host expiry includes time spent waiting for a resident worker.
    pub expires_at_unix_ms: u64,
    pub temp_dir: Option<String>,
    /// DER roots encoded as hexadecimal, including platform and managed roots.
    /// Empty or malformed trust material can never authorize a TLS connection.
    pub trust_roots_der_hex: Vec<String>,
    pub allow_public_registries: bool,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ArchiveAcquisitionResultV1 {
    pub schema: String,
    pub request_id: String,
    pub request_sha256: String,
    pub status: String,
    pub code: String,
    pub payload: Option<serde_json::Value>,
}

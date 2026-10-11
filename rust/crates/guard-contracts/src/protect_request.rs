//! `ProtectRequest` — wire contract for the resident install-time protect op.
//!
//! The request carries the wrapped install or registration command and,
//! optionally, the Guard store whose cached advisories the verdict consults.
//! The op parses the command into its install targets, reads the advisory
//! cache read-only, and returns the parsed request plus the local verdict.
//! Matched advisories come back as the raw cache rows so the caller rebuilds
//! them byte-for-byte from the stored JSON.

use serde::{Deserialize, Serialize};

/// Schema discriminator for the request.
pub const PROTECT_REQUEST_REQUEST_SCHEMA: &str = "guard-protect-request-request.v1";
/// Schema discriminator for the result.
pub const PROTECT_REQUEST_RESULT_SCHEMA: &str = "guard-protect-request-result.v1";
/// Capability advertised by the runtime when this operation is available.
pub const PROTECT_REQUEST_FEATURE: &str = "protect-request-v1";

/// Largest canonical request serialization the op will accept.
pub const PROTECT_REQUEST_MAX_BYTES: usize = 256 * 1024;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ProtectRequestRequestV1 {
    pub schema: String,
    /// Optional caller correlation id; echoed back in the result.
    #[serde(default)]
    pub request_id: String,
    pub guard_home: String,
    /// The Guard store (`<guard_home>/guard.db`) whose `publisher_cache` rows
    /// are matched; `None` parses the command without consulting advisories.
    #[serde(default)]
    pub store_path: Option<String>,
    /// The wrapped command, executable first.
    pub command: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ProtectTargetV1 {
    pub artifact_id: String,
    pub artifact_name: String,
    pub artifact_type: String,
    pub ecosystem: String,
    pub package_name: Option<String>,
    pub package_url: Option<String>,
    pub raw_spec: Option<String>,
    pub version: Option<String>,
    pub source_url: Option<String>,
    pub harness: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ProtectParsedRequestV1 {
    pub command: Vec<String>,
    pub install_kind: String,
    pub executor: String,
    pub package_manager: Option<String>,
    pub harness: Option<String>,
    pub targets: Vec<ProtectTargetV1>,
}

/// One matched `publisher_cache` row, exactly as stored.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ProtectCachedAdvisoryV1 {
    pub cache_key: String,
    pub updated_at: String,
    pub payload_json: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ProtectVerdictV1 {
    /// `allow`, `review` or `block`.
    pub action: String,
    pub reason: String,
    pub risk_signals: Vec<String>,
    /// Matched advisories, strongest severity first, then cache order.
    pub matched_advisories: Vec<ProtectCachedAdvisoryV1>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ProtectRequestResultV1 {
    pub schema: String,
    pub request_id: String,
    /// SHA-256 of the canonical request, binding the result to its request.
    pub request_sha256: String,
    /// `ok` or `error`.
    pub status: String,
    /// `ok`, or one of the `native_protect_request_*` failure codes.
    pub code: String,
    /// For `native_protect_request_invalid_url`, the URL parser's message.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub request: Option<ProtectParsedRequestV1>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub verdict: Option<ProtectVerdictV1>,
}

//! `ApprovalReuseDiagnostic` — wire contract for the resident op that explains
//! a saved-allow miss. It reads the near-match rows through bounded indexed
//! probes and returns `(reason, stored_hash)`; it never grants anything.
//!
//! The op is need/reply. When near-match rows exist whose integrity must be
//! verified, the first reply is `{"need": "integrity_evidence", ...}` naming
//! the evidence still missing; the caller procures it from the OS-keyring-facing
//! store and repeats the identical request with `evidence` populated.

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Schema discriminator for the request.
pub const APPROVAL_REUSE_DIAGNOSTIC_REQUEST_SCHEMA: &str =
    "guard-approval-reuse-diagnostic-request.v1";
/// Schema discriminator for the result.
pub const APPROVAL_REUSE_DIAGNOSTIC_RESULT_SCHEMA: &str =
    "guard-approval-reuse-diagnostic-result.v1";
/// Capability advertised by the runtime when this operation is available.
pub const APPROVAL_REUSE_DIAGNOSTIC_FEATURE: &str = "approval-reuse-diagnostic-v1";

/// Integrity evidence procured by the caller; each part is shipped only when
/// the resident named it in a `need` reply.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ApprovalReuseDiagnosticEvidenceV1 {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub integrity_state: Option<Value>,
    /// Policy-integrity HMAC key bytes (base64url, no padding).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub integrity_key_b64: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub integrity_key_id: Option<String>,
    /// Local-once approval HMAC key bytes (base64url, no padding).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub local_once_integrity_key_b64: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub local_once_integrity_key_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ApprovalReuseDiagnosticRequestV1 {
    pub schema: String,
    #[serde(default)]
    pub request_id: String,
    /// Absolute path to the guard store SQLite database.
    pub store_path: String,
    /// Absolute path to the resolved guard home.
    pub guard_home: String,
    pub harness: String,
    pub artifact_id: String,
    #[serde(default)]
    pub artifact_hash: Option<String>,
    #[serde(default)]
    pub workspace: Option<String>,
    #[serde(default)]
    pub publisher: Option<String>,
    /// Evaluation timestamp; the caller canonicalizes it before shipping.
    pub now: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub evidence: Option<ApprovalReuseDiagnosticEvidenceV1>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ApprovalReuseDiagnosticResultV1 {
    pub schema: String,
    pub request_id: String,
    /// SHA-256 of the canonical request, binding the result to its request.
    pub request_sha256: String,
    /// `ok` or `error`.
    pub status: String,
    /// `ok`, or one of the `native_approval_reuse_diagnostic_*` failure codes.
    pub code: String,
    /// `{"reason": str|null, "stored_hash": str|null}` or
    /// `{"need": "integrity_evidence", "policy": bool, "local_once": bool}`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub payload: Option<Value>,
}

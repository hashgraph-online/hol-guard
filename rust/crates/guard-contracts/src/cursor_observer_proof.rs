//! `CursorObserverProof` - wire contract for the resident op that verifies the
//! attestation proof a managed Cursor after-observer hook presents.
//!
//! The resident reads the owner-private attestation key from the Guard home
//! itself; the key never crosses the wire. Verification fails closed: a
//! missing key, an unreadable key, a blank proof or any mismatch is `valid:
//! false`.

use serde::{Deserialize, Serialize};

/// Schema discriminator for the request.
pub const CURSOR_OBSERVER_PROOF_REQUEST_SCHEMA: &str = "guard-cursor-observer-proof-request.v1";
/// Schema discriminator for the result.
pub const CURSOR_OBSERVER_PROOF_RESULT_SCHEMA: &str = "guard-cursor-observer-proof-result.v1";
/// Capability advertised by the runtime when this operation is available.
pub const CURSOR_OBSERVER_PROOF_FEATURE: &str = "cursor-observer-proof-v1";
/// Largest canonical request serialization the op will accept.
pub const CURSOR_OBSERVER_PROOF_MAX_BYTES: usize = 1024 * 1024;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct CursorObserverProofRequestV1 {
    pub schema: String,
    #[serde(default)]
    pub request_id: String,
    pub guard_home: String,
    pub conversation_id: String,
    /// The command as the observer hook saw it; the resident normalizes it.
    pub command: String,
    pub approval_binding: String,
    /// `afterShellExecution` or `afterMCPExecution`.
    pub observer_event: String,
    /// The proof the hook presented.
    pub proof: String,
    /// When true, `pending_proof` must be present, non-blank and equal to
    /// `proof` before the attestation is checked.
    #[serde(default)]
    pub require_pending_match: bool,
    #[serde(default)]
    pub pending_proof: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct CursorObserverProofResultV1 {
    pub schema: String,
    pub request_id: String,
    /// SHA-256 of the canonical request, binding the result to its request.
    pub request_sha256: String,
    /// `ok` or `error`.
    pub status: String,
    /// `ok`, or one of the `native_cursor_observer_proof_*` failure codes.
    pub code: String,
    /// `{"valid": bool}`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub payload: Option<serde_json::Value>,
}

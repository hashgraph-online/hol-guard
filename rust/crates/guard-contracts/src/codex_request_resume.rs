//! `CodexRequestResume` - wire contract for the resident op that owns the
//! Codex browser-approval resume record.
//!
//! The caller names the approval request, the call (`seed`, `status`,
//! `retry` or `defer`) and its clock. The resident reads the approval, operation and
//! resume rows from `guard.db`, decides the next resume state, sends the
//! continuation to the Codex thread for a retry and records the outcome.

use serde::{Deserialize, Serialize};

/// Schema discriminator for the request.
pub const CODEX_REQUEST_RESUME_REQUEST_SCHEMA: &str = "guard-codex-request-resume-request.v1";
/// Schema discriminator for the result.
pub const CODEX_REQUEST_RESUME_RESULT_SCHEMA: &str = "guard-codex-request-resume-result.v1";
/// Capability advertised by the runtime when this operation is available.
pub const CODEX_REQUEST_RESUME_FEATURE: &str = "codex-request-resume-v1";
/// Largest canonical request serialization the op will accept.
pub const CODEX_REQUEST_RESUME_MAX_BYTES: usize = 64 * 1024;
/// Longest continuation wait one retry may ask for.
pub const CODEX_REQUEST_RESUME_MAX_TIMEOUT_MS: u64 = 60_000;
/// Longest SQLite busy wait one store transaction may ask for.
pub const CODEX_REQUEST_RESUME_MAX_BUSY_TIMEOUT_MS: u64 = 10_000;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct CodexRequestResumeRequestV1 {
    pub schema: String,
    #[serde(default)]
    pub request_id: String,
    /// The approval request whose resume record is read or advanced.
    pub approval_request_id: String,
    /// `seed` writes the record from the queued operation, `status` seeds a
    /// missing record and reads it, `retry` sends the continuation
    /// and `defer` hands the decision to a Codex hook that is still waiting.
    pub call: String,
    /// The resolution handed to a waiting hook; only read by `defer`.
    #[serde(default)]
    pub action: Option<String>,
    /// Send again although a continuation was already sent.
    #[serde(default)]
    pub force: bool,
    /// The caller's clock, written to every timestamp column.
    pub now: String,
    /// `guard.db`, which must sit directly under `guard_home`.
    pub store_path: String,
    pub guard_home: String,
    /// SQLite busy wait for each store transaction.
    pub busy_timeout_ms: u64,
    /// The caller's home directory: expands `~` and bounds trusted sockets.
    #[serde(default)]
    pub home_dir: Option<String>,
    /// The caller's temporary directory, also a trusted socket location.
    #[serde(default)]
    pub temp_dir: Option<String>,
    /// The caller's working directory, for a relative socket path.
    #[serde(default)]
    pub cwd: Option<String>,
    /// How long a retry waits for Codex to accept the continuation.
    pub timeout_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct CodexRequestResumeResultV1 {
    pub schema: String,
    pub request_id: String,
    /// SHA-256 of the canonical request, binding the result to its request.
    pub request_sha256: String,
    /// `ok` or `error`.
    pub status: String,
    /// `ok`, or one of the `native_codex_request_resume_*` failure codes.
    pub code: String,
    /// `{"resume": <record or null>}`, or `{"error": "not_found" |
    /// "not_resolved" | "resume_not_supported"}` when a retry cannot run.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub payload: Option<serde_json::Value>,
}

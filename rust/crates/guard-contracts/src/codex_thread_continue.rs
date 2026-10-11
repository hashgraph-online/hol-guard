//! `CodexThreadContinue` - wire contract for the resident op that sends a
//! resolved approval's continuation prompt to the Codex thread that queued it.
//!
//! The caller looks up the stored Codex operation and ships its metadata
//! unchanged. The resident picks the thread, turn, socket and command fields,
//! checks the local socket, speaks the app-server WebSocket protocol and
//! reports what happened.

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Schema discriminator for the request.
pub const CODEX_THREAD_CONTINUE_REQUEST_SCHEMA: &str = "guard-codex-thread-continue-request.v1";
/// Schema discriminator for the result.
pub const CODEX_THREAD_CONTINUE_RESULT_SCHEMA: &str = "guard-codex-thread-continue-result.v1";
/// Capability advertised by the runtime when this operation is available.
pub const CODEX_THREAD_CONTINUE_FEATURE: &str = "codex-thread-continue-v1";
/// Largest canonical request serialization the op will accept.
pub const CODEX_THREAD_CONTINUE_MAX_BYTES: usize = 1024 * 1024;
/// Longest continuation wait one call may ask for.
pub const CODEX_THREAD_CONTINUE_MAX_TIMEOUT_MS: u64 = 60_000;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct CodexThreadContinueRequestV1 {
    pub schema: String,
    #[serde(default)]
    pub request_id: String,
    /// The approval request whose resolution is being reported to Codex.
    pub approval_request_id: String,
    /// `allow`, or any other resolution, which is reported as a block.
    pub action: String,
    /// The stored Codex operation metadata, unchanged.
    pub metadata: Value,
    /// The caller's home directory: expands `~` and bounds trusted sockets.
    #[serde(default)]
    pub home_dir: Option<String>,
    /// The caller's temporary directory, also a trusted socket location.
    #[serde(default)]
    pub temp_dir: Option<String>,
    /// The caller's working directory, for a relative socket path.
    #[serde(default)]
    pub cwd: Option<String>,
    /// How long to wait for Codex to accept the continuation.
    pub timeout_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct CodexThreadContinueResultV1 {
    pub schema: String,
    pub request_id: String,
    /// SHA-256 of the canonical request, binding the result to its request.
    pub request_sha256: String,
    /// `ok` or `error`.
    pub status: String,
    /// `ok`, or one of the `native_codex_thread_continue_*` failure codes.
    pub code: String,
    /// `{"result": <continuation result or null>}`; null when the metadata
    /// names no Codex thread.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub payload: Option<Value>,
}

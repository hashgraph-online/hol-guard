//! `HookAuthorityState` - wire contract for the resident op that owns the
//! signed Claude and Cursor hook authority state kept in `sync_state`.
//!
//! The state is a set of locally signed JSON rows: Claude permission notices
//! and pending permissions (with a per-session index), Cursor pending shell
//! approvals (with a per-conversation index) and Cursor native shell
//! allowances. The resident reads, verifies, expires, rewrites and deletes
//! them against the guard store; every integrity failure leaves an audit row
//! in `guard_events`. The integrity key material and the clock are shipped by
//! the Python transport.
//!
//! A row's name belongs to the resident. A Cursor row is named by the
//! conversation and the command it holds, and a Claude pending permission by
//! its artifact, so the key a row is written under and the key it is read back
//! under have one definition. A request may instead echo a key the resident
//! issued earlier — out of a pending index, or out of an op's own reply — and
//! that key is acted on as given.
//!
//! Each request names one `op` and carries only the fields that op reads;
//! unused fields are omitted. A store that cannot be opened or a request the
//! resident cannot understand is an `error` reply, never a partial success.

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Schema discriminator for the request.
pub const HOOK_AUTHORITY_STATE_REQUEST_SCHEMA: &str = "guard-hook-authority-state-request.v1";
/// Schema discriminator for the result.
pub const HOOK_AUTHORITY_STATE_RESULT_SCHEMA: &str = "guard-hook-authority-state-result.v1";
/// Capability advertised by the runtime when this operation is available.
pub const HOOK_AUTHORITY_STATE_FEATURE: &str = "hook-authority-state-v1";
/// Capability for the single-transaction Cursor lookup and removal and the
/// Claude session discard ops.
pub const HOOK_AUTHORITY_STATE_SESSION_OPS_FEATURE: &str = "hook-authority-state-session-ops-v1";
/// Largest canonical request serialization the op will accept.
pub const HOOK_AUTHORITY_STATE_MAX_BYTES: usize = 512 * 1024;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
#[serde(deny_unknown_fields)]
pub struct HookAuthorityStateRequestV1 {
    pub schema: String,
    #[serde(default)]
    pub request_id: String,
    /// Absolute path to the guard store SQLite database.
    pub store_path: String,
    /// Absolute path to the resolved guard home.
    pub guard_home: String,
    /// One of the `claude_*` / `cursor_*` operations or `state_is_fresh`.
    pub op: String,
    /// Wall-clock timestamp (`datetime.isoformat()`), used for signing,
    /// freshness and the audit rows.
    pub now: String,
    /// Policy-integrity HMAC key bytes (base64url, no padding).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub integrity_key_b64: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub integrity_key_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub conversation_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tool_name: Option<String>,
    /// The unsigned state body: the Claude notice or the Cursor pending state.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub payload: Option<Value>,
    /// A pending row's key, as the resident issued it — read out of a session
    /// or conversation index — and acted on as given. `cursor_remove_pending`
    /// accepts `command` and the Claude pending ops take `artifact_id` instead;
    /// for those the resident derives the key itself.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pending_key: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pending_keys: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expected_artifact_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expected_artifact_hash: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expected_command: Option<String>,
    /// The artifact a Claude pending permission belongs to. It names the row:
    /// the resident derives the pending state key from it, and reads it back as
    /// the artifact the row has to carry.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub artifact_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub artifact_hash: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub artifact_name: Option<String>,
    /// The Cursor shell command the row belongs to (or the Claude command
    /// binding). The Cursor ops derive their `sync_state` key from it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub command: Option<String>,
    /// A `sync_state` key the resident itself issued, acted on as given in
    /// place of the one `command` would name.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub state_key: Option<String>,
    /// The key a Cursor pending row has to carry to be believed. Derived from
    /// `command` unless the caller echoes a resident-issued key here.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expected_key: Option<String>,
    /// `state_is_fresh` only: the stored `saved_at`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub saved_at: Option<String>,
    /// `state_is_fresh` only: the age limit in seconds.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_age_seconds: Option<i64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct HookAuthorityStateResultV1 {
    pub schema: String,
    pub request_id: String,
    /// SHA-256 of the canonical request, binding the result to its request.
    pub request_sha256: String,
    /// `ok` or `error`.
    pub status: String,
    /// `ok`, or one of the `native_hook_authority_state_*` failure codes.
    pub code: String,
    /// The per-operation result object.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub payload: Option<Value>,
}

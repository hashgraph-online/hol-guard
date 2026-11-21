//! `GuardStore` — wire contract for the resident op that owns request-path
//! persistence over `guard.db` (Review event outbox delivery today).
//!
//! One op, one method name per store operation. Each call opens the store at
//! `store_path`, applies the same busy-timeout/WAL pragmas as the Python
//! connection, runs the method inside a single SQLite transaction, finalizes
//! trigger-written outbox payload hashes, commits, and reports the outbox
//! generation when rows changed so the caller can wake process-local waiters.

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

/// Schema discriminator for the request.
pub const GUARD_STORE_REQUEST_SCHEMA: &str = "guard-store-request.v1";
/// Schema discriminator for the result.
pub const GUARD_STORE_RESULT_SCHEMA: &str = "guard-store-result.v1";
/// Capability advertised by the runtime when this operation is available.
pub const GUARD_STORE_FEATURE: &str = "guard-store-v1";
/// Largest canonical request the op accepts.
pub const GUARD_STORE_MAX_REQUEST_BYTES: usize = 4 * 1024 * 1024;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct GuardStoreRequestV1 {
    pub schema: String,
    /// Caller correlation id; echoed in the result.
    pub request_id: String,
    /// Absolute path to the guard store SQLite database.
    pub store_path: String,
    /// Absolute path to the guard home that owns the store.
    pub guard_home: String,
    /// Store operation name (`review_event_outbox_status`, ...).
    pub method: String,
    /// OAuth source the store instance is bound to (`GuardStore.guard_source`).
    pub source: String,
    /// SQLite busy timeout in milliseconds (the Python connect timeout).
    pub busy_timeout_ms: u64,
    /// Method arguments; the shape is owned by the method.
    #[serde(default)]
    pub args: Map<String, Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct GuardStoreResultV1 {
    pub schema: String,
    pub request_id: String,
    /// SHA-256 over the canonical request, binding the result to its request.
    pub request_sha256: String,
    /// `ok` or `error`.
    pub status: String,
    /// `ok`, or one of the `native_guard_store_*` failure codes.
    pub code: String,
    /// Method result on success; `{ "message": ... }` for value errors.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub payload: Option<Value>,
    /// Durable outbox generation after a committed mutation, else absent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub outbox_generation: Option<i64>,
}

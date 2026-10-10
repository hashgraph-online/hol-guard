//! `DaemonHandler` — wire contract for the resident daemon handler-policy op.
//!
//! The daemon's HTTP framing and store access stay in Python. Which request
//! bodies and query strings a handler accepts, the status and body of every
//! rejection, and the normalized values a handler may act on are decided by
//! the resident. Every query is pure; a transport failure is "no decision" and
//! the caller must fail closed.

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Schema discriminator for the request.
pub const DAEMON_HANDLER_REQUEST_SCHEMA: &str = "guard-daemon-handler-request.v1";
/// Schema discriminator for the result.
pub const DAEMON_HANDLER_RESULT_SCHEMA: &str = "guard-daemon-handler-result.v1";
/// Capability advertised by the runtime when this operation is available.
pub const DAEMON_HANDLER_FEATURE: &str = "daemon-handler-v1";
/// Largest canonical request serialization the op will accept. The daemon
/// admits request bodies of 1,000,000 bytes and the canonical form escapes
/// non-ASCII text to as much as three times its UTF-8 size.
pub const DAEMON_HANDLER_MAX_BYTES: usize = 4 * 1024 * 1024;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct DaemonHandlerRequestV1 {
    pub schema: String,
    pub request_id: String,
    pub query: DaemonHandlerQueryV1,
}

/// One request-body field as the transport saw it. Text keeps its raw
/// (unstripped) value so the resident applies the stripping rule itself.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "state", rename_all = "snake_case", deny_unknown_fields)]
pub enum DaemonFieldV1 {
    /// Missing or JSON `null`.
    Absent,
    Text {
        value: String,
    },
    Bool {
        value: bool,
    },
    /// A list: its length and the string items in order.
    List {
        len: usize,
        strings: Vec<String>,
    },
    /// Any other JSON type.
    Other,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum DaemonHandlerQueryV1 {
    /// `POST /v1/policy/decisions`.
    PolicyUpsert {
        harness: DaemonFieldV1,
        scope: DaemonFieldV1,
        action: DaemonFieldV1,
        artifact_id: DaemonFieldV1,
        workspace: DaemonFieldV1,
        publisher: DaemonFieldV1,
        reason: DaemonFieldV1,
    },
    /// `POST /v1/policy/clear`.
    PolicyClear {
        harness: DaemonFieldV1,
        source: DaemonFieldV1,
        scope: DaemonFieldV1,
        artifact_id: DaemonFieldV1,
        artifact_hash: DaemonFieldV1,
        workspace: DaemonFieldV1,
        publisher: DaemonFieldV1,
        all: DaemonFieldV1,
        artifact_id_is_null: DaemonFieldV1,
        artifact_hash_is_null: DaemonFieldV1,
    },
    /// `POST /v1/requests/clear`.
    RequestsClear {
        status: DaemonFieldV1,
        harness: DaemonFieldV1,
    },
    /// `POST /v1/requests/bulk-allow-once`.
    BulkAllow { request_ids: DaemonFieldV1 },
    /// `GET /v1/requests` query string.
    RequestsList { query: String },
    /// `POST /v1/harnesses/<harness>/<action>` preamble.
    HarnessAction {
        action: String,
        dry_run: DaemonFieldV1,
    },
    /// The `cursor` integer of an events query string.
    EventsCursor { query: String },
}

/// The handler's decision. `kind` echoes the query kind; `outcome` is
/// `reject` (write `status` and `body`, stop) or `proceed` (act on `fields`).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct DaemonHandlerPayloadV1 {
    pub kind: String,
    pub outcome: String,
    pub status: u16,
    pub body: Value,
    pub fields: Value,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct DaemonHandlerResultV1 {
    pub schema: String,
    pub request_id: String,
    /// SHA-256 of the canonical request, binding the result to its request.
    pub request_sha256: String,
    /// `ok` or `error`.
    pub status: String,
    /// `ok`, or one of the `native_daemon_handler_*` failure codes.
    pub code: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub payload: Option<DaemonHandlerPayloadV1>,
}

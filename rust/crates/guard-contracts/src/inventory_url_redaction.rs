//! `InventoryUrlRedaction` — wire contract for the resident op that redacts an
//! inventory export's URLs, header names, endpoint host classes, command
//! strings and paths.
//!
//! The answers share one request because an exported artifact asks for several
//! of them about the same endpoint, and because a snapshot redacts many
//! endpoints in a row. A caller sends the tasks it has and reads the answers
//! back in the order it sent them. The feature string stays `v1`: the op has
//! not shipped in a release, so the grammar grew in place rather than leaving
//! a version nothing ever spoke.
//!
//! A command or path task carries the home, workspace and working directories
//! the answer is relative to. The resident resolves a relative path against
//! its own process directory, which is not the caller's, so the caller names
//! all three rather than letting the answer depend on where the resident runs.
//!
//! Every field is always present on the wire. A request field that could be
//! omitted would digest differently on each side of the call and the reply
//! would never bind to the request that asked for it.

use serde::{Deserialize, Serialize};

/// Resident feature advertising this op.
pub const INVENTORY_URL_REDACTION_FEATURE: &str = "inventory-url-redaction-v1";

/// Canonical request budget.
pub const INVENTORY_URL_REDACTION_MAX_REQUEST_BYTES: usize = 4 * 1024 * 1024;

/// Upper bound on the tasks one request may carry.
pub const INVENTORY_URL_REDACTION_MAX_TASKS: usize = 4096;

/// Request schema identifier.
pub const INVENTORY_URL_REDACTION_REQUEST_SCHEMA: &str = "guard-inventory-url-redaction-request.v1";

/// Result schema identifier.
pub const INVENTORY_URL_REDACTION_RESULT_SCHEMA: &str = "guard-inventory-url-redaction-result.v1";

/// One redaction the caller wants answered.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum InventoryUrlTaskV1 {
    /// `redact_url(value)` — the exported form of one URL.
    #[serde(rename_all = "snake_case")]
    RedactUrl {
        /// The URL as the scanner recorded it.
        value: String,
    },
    /// `redact_headers(headers)` — presence per header name, never a value.
    ///
    /// Only the names travel. A header value never leaves the machine, not
    /// even to be classified, so sending one would be the disclosure the
    /// redaction exists to prevent.
    #[serde(rename_all = "snake_case")]
    RedactHeaders {
        /// The header names, in the order the mapping yielded them.
        header_names: Vec<String>,
    },
    /// `classify_endpoint_host(value)` — where an endpoint points, decided
    /// without a network request.
    #[serde(rename_all = "snake_case")]
    ClassifyEndpointHost {
        /// The endpoint URL, or null when the artifact recorded none.
        value: Option<String>,
    },
    /// `_redact_command_value(value, home_dir, workspace_dir)` — the exported
    /// form of one command string: its URLs, its absolute paths and its
    /// credential arguments.
    #[serde(rename_all = "snake_case")]
    RedactCommandValue {
        /// The command as the scanner recorded it.
        value: String,
        /// The home directory the export labels as `{home}`.
        home_dir: String,
        /// The workspace labelled `{workspace}`, or null when none is known.
        workspace_dir: Option<String>,
        /// The directory a relative path in `value` resolves against.
        cwd: String,
    },
    /// `_redact_known_path(value, home_dir, workspace_dir)` — the exported
    /// form of one path.
    #[serde(rename_all = "snake_case")]
    RedactKnownPath {
        /// The path as the scanner recorded it.
        value: String,
        /// The home directory the export labels as `{home}`.
        home_dir: String,
        /// The workspace labelled `{workspace}`, or null when none is known.
        workspace_dir: Option<String>,
        /// The directory a relative path resolves against.
        cwd: String,
    },
}

/// Request carrying the tasks of one redaction pass.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct InventoryUrlRedactionRequestV1 {
    /// Must equal [`INVENTORY_URL_REDACTION_REQUEST_SCHEMA`].
    pub schema: String,
    /// Caller-chosen identifier the reply echoes.
    pub request_id: String,
    /// The tasks, answered in this order.
    pub tasks: Vec<InventoryUrlTaskV1>,
}

/// One answer, in the shape the task it answers asks for.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum InventoryUrlAnswerV1 {
    /// The redacted URL.
    #[serde(rename_all = "snake_case")]
    RedactUrl {
        /// The URL with userinfo dropped and sensitive query values rewritten.
        value: String,
    },
    /// The lowercased header names and their presence markers, in order.
    #[serde(rename_all = "snake_case")]
    RedactHeaders {
        /// `[name, presence]` pairs; a mapping would lose the sent order.
        headers: Vec<(String, String)>,
    },
    /// The endpoint host class.
    #[serde(rename_all = "snake_case")]
    ClassifyEndpointHost {
        /// One of `none`, `local_loopback`, `local_private`, `remote_public`.
        host_class: String,
    },
    /// The redacted command string.
    #[serde(rename_all = "snake_case")]
    RedactCommandValue {
        /// The command with its URLs, paths and credential arguments redacted.
        value: String,
    },
    /// The redacted path.
    #[serde(rename_all = "snake_case")]
    RedactKnownPath {
        /// The path under its `{home}` or `{workspace}` label, else its name.
        value: String,
    },
}

/// Reply carrying one answer per task.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct InventoryUrlRedactionResultV1 {
    /// Always [`INVENTORY_URL_REDACTION_RESULT_SCHEMA`].
    pub schema: String,
    /// Echo of the request's identifier.
    pub request_id: String,
    /// Digest of the canonical request this reply answers.
    pub request_sha256: String,
    /// `ok` for a reply the caller may read.
    pub status: String,
    /// `ok` for a reply the caller may read.
    pub code: String,
    /// One answer per task, in the order the tasks were sent.
    pub answers: Vec<InventoryUrlAnswerV1>,
}

//! `RetryLineageCapture` — wire contract for the resident op that captures a
//! hook's provider retry lineage.
//!
//! The lineage is local diagnostic metadata, never a capability: it records
//! which provider session, thread, tool call, turn or invocation a hook belongs
//! to so a later retry can be correlated with the first attempt. The caller
//! sends the hook payload's top-level scalars, the runtime workspace and the
//! action envelope; the resident decides which aliases count, whether they
//! agree, and what the digests are.
//!
//! Every field is always present on the wire. A request field that could be
//! omitted would digest differently on each side of the call and the reply
//! would never bind to the request that asked for it.

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

/// Resident feature advertising this op.
pub const RETRY_LINEAGE_CAPTURE_FEATURE: &str = "retry-lineage-capture-v1";

/// Canonical request budget. The action envelope dominates; anything larger
/// carries no lineage rather than a partial one.
pub const RETRY_LINEAGE_CAPTURE_MAX_REQUEST_BYTES: usize = 4 * 1024 * 1024;

/// Request schema identifier.
pub const RETRY_LINEAGE_CAPTURE_REQUEST_SCHEMA: &str = "guard-retry-lineage-capture-request.v1";

/// Result schema identifier.
pub const RETRY_LINEAGE_CAPTURE_RESULT_SCHEMA: &str = "guard-retry-lineage-capture-result.v1";

/// Request to capture one hook's retry lineage.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct RetryLineageCaptureRequestV1 {
    /// Must equal [`RETRY_LINEAGE_CAPTURE_REQUEST_SCHEMA`].
    pub schema: String,
    /// Caller-chosen identifier the reply echoes.
    pub request_id: String,
    /// The harness the hook ran for.
    pub harness: String,
    /// The hook payload's top-level members. Only string identifiers can
    /// count, so a caller may send any other value as `false`: it is refused
    /// exactly as the original value would be.
    pub payload: Map<String, Value>,
    /// The runtime workspace, or null. A payload workspace that disagrees
    /// with it refuses the lineage.
    pub workspace: Option<String>,
    /// The hook's action envelope, or null; digested as `action_sha256`.
    pub action_envelope: Option<Map<String, Value>>,
}

/// Reply carrying the captured lineage, or null when the payload names no
/// provider identifier or names an ambiguous or malformed one.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct RetryLineageCaptureResultV1 {
    /// Always [`RETRY_LINEAGE_CAPTURE_RESULT_SCHEMA`].
    pub schema: String,
    /// Echo of the request's identifier.
    pub request_id: String,
    /// Digest of the canonical request this reply answers.
    pub request_sha256: String,
    /// `ok` for a reply the caller may read.
    pub status: String,
    /// `ok` for a reply the caller may read.
    pub code: String,
    /// The lineage record, or null.
    pub lineage: Option<Map<String, Value>>,
}

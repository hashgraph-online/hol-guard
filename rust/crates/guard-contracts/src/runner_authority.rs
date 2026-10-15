//! `RunnerAuthority` — wire contract for the resident op that owns the
//! `guard run` authority transforms: runtime-detector authority and context,
//! saved-approval claim partitioning and failure projection, the pre/post-claim
//! launch-authority signature, trusted request overrides, receipt-evidence
//! merging and the policy-bundle shadow comparison.
//!
//! The op is pure (no IO, no SQLite). Python ships typed inputs and applies
//! the returned patch; it never recomputes an action, a reason or a signature.
//! A resident that cannot answer yields a typed `error` result which callers
//! must treat as a refusal to launch (fail closed), never as an allow.

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Schema discriminator for the request.
pub const RUNNER_AUTHORITY_REQUEST_SCHEMA: &str = "guard-runner-authority-request.v1";
/// Schema discriminator for the result.
pub const RUNNER_AUTHORITY_RESULT_SCHEMA: &str = "guard-runner-authority-result.v1";
/// Capability advertised by the runtime when this operation is available.
pub const RUNNER_AUTHORITY_FEATURE: &str = "runner-authority-v1";

/// Largest canonical request serialization the op will accept. Artifact
/// results are compact patches, but the resident's 2 MiB response bound still
/// applies; a result past it is a typed
/// `native_runner_authority_response_too_large` error. An evaluation past
/// either bound fails closed.
pub const RUNNER_AUTHORITY_MAX_BYTES: usize = 4 * 1024 * 1024;

/// Every field is required (no serde defaults) so the canonical request digest
/// Python binds results to is exactly the request Rust parsed.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct RunnerAuthorityRequestV1 {
    pub schema: String,
    /// Caller correlation id; echoed back in the result.
    pub request_id: String,
    /// Resolved guard home the request is scoped to.
    pub guard_home: String,
    /// Which authority transform to run.
    pub kind: String,
    /// Kind-specific arguments.
    pub args: Value,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct RunnerAuthorityResultV1 {
    pub schema: String,
    pub request_id: String,
    /// SHA-256 of the canonical request, binding the result to its request.
    pub request_sha256: String,
    /// `ok` or `error`.
    pub status: String,
    /// `ok`, or one of the `native_runner_authority_*` failure codes.
    pub code: String,
    /// Kind-specific result payload.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub payload: Option<Value>,
}

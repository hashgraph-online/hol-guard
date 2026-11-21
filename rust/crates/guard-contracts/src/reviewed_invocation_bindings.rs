//! `ReviewedInvocationBindingsValidate` - wire contract for binding an
//! extension's reviewed literal invocations to the operations that own them.
//!
//! An extension author submits safe variants: exact argument vectors a
//! reviewed operation may run. Review has to decide, for each one, whether it
//! uses only options the discovery found and whether the command grammar
//! assigns it to the operation that claims it. Python decided that with
//! matchers of its own, so a vector could be bound at review time by one
//! grammar and matched at run time by another.
//!
//! The op is pure: it reads the discovery in the request and never opens the
//! store, the catalog or an extension file.

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Schema discriminator for the request.
pub const REVIEWED_INVOCATION_BINDINGS_REQUEST_SCHEMA: &str =
    "guard-reviewed-invocation-bindings-request.v1";
/// Schema discriminator for the result.
pub const REVIEWED_INVOCATION_BINDINGS_RESULT_SCHEMA: &str =
    "guard-reviewed-invocation-bindings-result.v1";
/// Capability advertised by the runtime when this operation is available.
pub const REVIEWED_INVOCATION_BINDINGS_FEATURE: &str = "reviewed-invocation-bindings-v1";
/// Largest canonical request serialization the op will accept. It stays below
/// `MAX_NATIVE_REQUEST_BYTES` so the resident envelope still fits one frame.
pub const REVIEWED_INVOCATION_BINDINGS_MAX_BYTES: usize = 6 * 1024 * 1024 - 64 * 1024;
/// Most operations one discovery may carry. Every reviewed row is matched
/// against all of them, so this bounds the work one call can ask for.
pub const REVIEWED_INVOCATION_BINDINGS_MAX_OPERATIONS: usize = 4096;
/// Most reviewed rows one call may bind.
pub const REVIEWED_INVOCATION_BINDINGS_MAX_ROWS: usize = 4096;
/// Longest the grammar may spend on one request before it gives up.
pub const REVIEWED_INVOCATION_BINDINGS_DEADLINE_MILLIS: u64 = 5_000;

/// One operation the discovery found, with the option vocabulary review may
/// accept for it.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ReviewedOperationV1 {
    pub operation_id: String,
    #[serde(default)]
    pub path: Vec<String>,
    #[serde(default)]
    pub flags: Vec<String>,
    #[serde(default)]
    pub options_with_values: Vec<String>,
}

/// One reviewed literal vector and the operation that claims it.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ReviewedInvocationV1 {
    pub operation_id: String,
    #[serde(default)]
    pub argv: Vec<String>,
}

/// Every reviewed row an extension carries, checked in one call while the
/// extension is reviewed.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ReviewedInvocationBindingsRequestV1 {
    pub schema: String,
    #[serde(default)]
    pub request_id: String,
    /// The executable the discovery describes.
    pub executable: String,
    pub operations: Vec<ReviewedOperationV1>,
    pub rows: Vec<ReviewedInvocationV1>,
    /// Operations the extension blocks outright. A reviewed vector any of them
    /// also matches is refused.
    #[serde(default)]
    pub blocked_operation_ids: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ReviewedInvocationBindingsResultV1 {
    pub schema: String,
    pub request_id: String,
    /// SHA-256 of the canonical request, binding the result to its request.
    pub request_sha256: String,
    /// `ok` or `error`.
    pub status: String,
    /// `ok`, or one of the `native_reviewed_invocation_*` codes.
    pub code: String,
    /// `{"refused": null}` when the grammar binds every row to the operation
    /// that claimed it, or `{"refused": {"index": i, "code": "..."}}` for the
    /// first row it does not. A row an author can fix is an answer, not a
    /// runtime failure, so it rides an `ok` reply.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub payload: Option<Value>,
}

//! `CommandPackRecord` - wire contract for the resident op that verifies or
//! opens an authenticated command-pack record.
//!
//! The policy publisher re-reads the active pack record about once a second.
//! Each read used to start a one-shot `pack-lifecycle` process per record it
//! authenticated, and per active-security answer it needed. The resident
//! answers the same requests in process, so an idle publisher starts no
//! runtime at all.

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Schema discriminator for the request.
pub const COMMAND_PACK_RECORD_REQUEST_SCHEMA: &str = "guard-command-pack-record-request.v1";
/// Schema discriminator for the result.
pub const COMMAND_PACK_RECORD_RESULT_SCHEMA: &str = "guard-command-pack-record-result.v1";
/// Capability advertised by the runtime when this operation is available.
pub const COMMAND_PACK_RECORD_FEATURE: &str = "command-pack-record-v1";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct CommandPackRecordRequestV1 {
    pub schema: String,
    #[serde(default)]
    pub request_id: String,
    /// The Guard home whose pack cache an `open` reads.
    pub guard_home: String,
    /// The store the record was read from.
    pub store_path: String,
    /// The `pack-lifecycle` request, exactly as the one-shot reads it: `kind`
    /// `record` with `operation` `verify` or `open`, or `kind`
    /// `active-security` with an operation that answers from the request
    /// alone, and its fields.
    pub record: Value,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct CommandPackRecordResultV1 {
    pub schema: String,
    pub request_id: String,
    /// SHA-256 of the canonical request, binding the result to its request.
    pub request_sha256: String,
    /// `ok` or `error`.
    pub status: String,
    /// `ok`, or one of the `native_command_pack_record_*` codes.
    pub code: String,
    /// The one-shot's answer: the authenticated value, or a `fault` naming
    /// why the record was refused.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub payload: Option<Value>,
}

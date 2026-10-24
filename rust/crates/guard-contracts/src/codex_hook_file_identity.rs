//! `CodexHookFileIdentity` - wire contract for the resident op that decides
//! whether a packaged file on disk is still the file an authenticated Codex
//! hook manifest describes.
//!
//! The manifest states what the file was when Guard installed it. Whether the
//! live file still matches is what lets the hook run, so the answer is spelled
//! in one place rather than beside every caller that asks. A caller ships the
//! manifest's identity unchanged, together with the few spellings only the
//! asking interpreter knows - the canonical form of the path and whether the
//! path sits under that interpreter's own package roots - and the resident
//! reads the file.

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Schema discriminator for the request.
pub const CODEX_HOOK_FILE_IDENTITY_REQUEST_SCHEMA: &str =
    "guard-codex-hook-file-identity-request.v1";
/// Schema discriminator for the result.
pub const CODEX_HOOK_FILE_IDENTITY_RESULT_SCHEMA: &str = "guard-codex-hook-file-identity-result.v1";
/// Capability advertised by the runtime when this operation is available.
pub const CODEX_HOOK_FILE_IDENTITY_FEATURE: &str = "codex-hook-file-identity-v1";
/// Largest canonical request serialization the op will accept.
pub const CODEX_HOOK_FILE_IDENTITY_MAX_BYTES: usize = 512 * 1024;
/// Most identities one request may carry. A repair walks the files one
/// manifest names; a request above this is refused so the caller asks again
/// with the batch it holds rather than growing the request unbounded.
pub const CODEX_HOOK_FILE_IDENTITY_MAX_QUESTIONS: usize = 64;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct CodexHookFileIdentityQuestionV1 {
    /// The manifest's identity, exactly as it was authenticated. It travels as
    /// the value it is: whether it has the shape of an identity at all is part
    /// of the answer, so a caller that normalized it first would be answering
    /// that question itself.
    pub identity: Value,
    /// The canonical spelling of the identity's `path` for the asking
    /// interpreter, or `null` where that interpreter cannot spell it. A
    /// manifest records the path the interpreter that wrote it canonicalized,
    /// so the same interpreter spells the comparison.
    #[serde(default)]
    pub canonical_path: Option<String>,
    /// Whether the identity's `path` sits under a package root belonging to
    /// the asking interpreter. Only that interpreter knows its own install
    /// layout, and the answer widens the group-write exception below.
    #[serde(default)]
    pub installed_python_package_file: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct CodexHookFileIdentityRequestV1 {
    pub schema: String,
    #[serde(default)]
    pub request_id: String,
    /// Whether the asking process runs where a file carries POSIX ownership and
    /// permission bits - everywhere but Windows. The ownership and permission
    /// rules below exist only there, and carrying the platform as a field
    /// rather than reading it from the build keeps both answers reachable from
    /// either host's tests.
    pub posix: bool,
    /// The uid the asking process runs as, or `null` where it has none. A file
    /// owned by anyone but this user or root is not one Guard installed.
    #[serde(default)]
    pub current_uid: Option<u32>,
    /// The identities to answer, in the caller's order.
    pub questions: Vec<CodexHookFileIdentityQuestionV1>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct CodexHookFileIdentityResultV1 {
    pub schema: String,
    pub request_id: String,
    /// SHA-256 of the canonical request, binding the result to its request.
    pub request_sha256: String,
    /// `ok` or `error`.
    pub status: String,
    /// `ok`, or one of the `native_codex_hook_file_identity_*` codes.
    pub code: String,
    /// `{"answers": [...]}`: one answer per question, in the request's order.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub payload: Option<Value>,
}

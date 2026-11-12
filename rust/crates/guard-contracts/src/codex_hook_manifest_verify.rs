//! `CodexHookManifestVerify` - wire contract for the resident op that decides
//! whether an authenticated Codex hook manifest still describes the live
//! installation: its header, the config target, the interpreter, every
//! packaged file, the launch identities and the hook registrations in the
//! Codex config.
//!
//! The caller authenticates the manifest first; the key never leaves it. It
//! then ships the manifest as authenticated, the live `[hooks]` table, the
//! installation it expects, and the few spellings only the asking interpreter
//! can produce: canonical paths, which paths sit under its own package roots,
//! and how it splits each handler's command line. The resident reads every
//! file the answer turns on and answers with the integrity state status and
//! doctor report.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Schema discriminator for the request.
pub const CODEX_HOOK_MANIFEST_VERIFY_REQUEST_SCHEMA: &str =
    "guard-codex-hook-manifest-verify-request.v1";
/// Schema discriminator for the result.
pub const CODEX_HOOK_MANIFEST_VERIFY_RESULT_SCHEMA: &str =
    "guard-codex-hook-manifest-verify-result.v1";
/// Capability advertised by the runtime when this operation is available.
pub const CODEX_HOOK_MANIFEST_VERIFY_FEATURE: &str = "codex-hook-manifest-verify-v1";
/// Largest canonical request serialization the op will accept. A manifest
/// names a few dozen files and four events; the live hooks table is the
/// user's own config and is sent only for the four managed events.
pub const CODEX_HOOK_MANIFEST_VERIFY_MAX_BYTES: usize = 2 * 1024 * 1024;

/// A failure the caller met before there was a manifest to verify: the
/// manifest could not be authenticated, or reading it failed.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct CodexHookManifestFailureV1 {
    pub reason: String,
    pub message: String,
}

/// The installation the caller expects the manifest to describe, spelled by
/// the asking interpreter.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct CodexHookManifestExpectedV1 {
    /// The Codex config file as the caller names it; the resident reads it.
    pub config_path: String,
    /// Its canonical spelling, which the manifest's `config.target` records.
    pub config_target: String,
    /// The Guard home, user home, runtime Guard home and workspace the
    /// manifest must be bound to, canonically spelled.
    pub context: Value,
    pub package_version: String,
    /// The interpreter invocation path this installation launches hooks with.
    pub interpreter_path: String,
    /// Packaged-file role to canonical path.
    pub packaged_paths: BTreeMap<String, String>,
    pub fallback_argv: Vec<String>,
    pub daemon_start_argv: Vec<String>,
    /// The event bindings this Guard version registers, in order.
    pub event_bindings: Vec<Value>,
}

/// Whether a POSIX group is private to one file owner, as the caller proved
/// it from the account database.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct CodexHookPrivateGroupAnswerV1 {
    pub owner_uid: u32,
    pub group_gid: u32,
    pub private: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct CodexHookManifestVerifyRequestV1 {
    pub schema: String,
    #[serde(default)]
    pub request_id: String,
    /// Whether the asking process runs where files carry POSIX ownership and
    /// permission bits.
    pub posix: bool,
    /// The uid the asking process runs as, or `null` where it has none.
    #[serde(default)]
    pub current_uid: Option<u32>,
    /// Set when there is no manifest to verify; the answer reports it.
    #[serde(default)]
    pub failure: Option<CodexHookManifestFailureV1>,
    /// The authenticated manifest, exactly as it was authenticated.
    #[serde(default)]
    pub manifest: Option<Value>,
    /// The live `[hooks]` table: each managed event's group list, with a
    /// group JSON cannot carry sent as `null`. `null` when the table is not a
    /// table at all.
    #[serde(default)]
    pub hooks: Option<Value>,
    #[serde(default)]
    pub expected: Option<CodexHookManifestExpectedV1>,
    /// Path spelling to its canonical form, for every path the manifest names.
    #[serde(default)]
    pub canonical_paths: BTreeMap<String, String>,
    /// Manifest paths that sit under the asking interpreter's package roots.
    #[serde(default)]
    pub installed_python_package_files: Vec<String>,
    /// Handler command line to the argv the asking interpreter splits it
    /// into, or `null` where it refuses to.
    #[serde(default)]
    pub command_argvs: BTreeMap<String, Option<Vec<String>>>,
    /// Answers to the private-group questions an earlier reply asked.
    #[serde(default)]
    pub private_groups: Vec<CodexHookPrivateGroupAnswerV1>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct CodexHookManifestVerifyResultV1 {
    pub schema: String,
    pub request_id: String,
    /// SHA-256 of the canonical request, binding the result to its request.
    pub request_sha256: String,
    /// `ok` or `error`.
    pub status: String,
    /// `ok`, or one of the `native_codex_hook_manifest_verify_*` codes.
    pub code: String,
    /// `{"state": {...}, "private_group_questions": [...]}`. While questions
    /// remain, the state is provisional and the caller asks again with their
    /// answers.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub payload: Option<Value>,
}

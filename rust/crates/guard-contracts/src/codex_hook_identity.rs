//! `CodexHookIdentity` - wire contract for the resident op that derives a
//! Codex hook's canonical identity.
//!
//! A hook written as TOML and the same hook written as JSON are the same hook,
//! and a hook that moved from one matcher group to another is still the one
//! the user approved. Both facts rest on a digest taken over a canonical form
//! of the definition rather than over its bytes, so the digest has to be
//! derived the same way every time, by one implementation.
//!
//! The callers ask about a handler, a whole matcher group, or the conflict
//! keys that keep two differing definitions of one slot from collapsing; a
//! fourth question asks only how a command tokenizes. They ride together
//! because an adapter walks every group of every source in one pass and a
//! round trip per handler would put the resident on that whole walk.
//!
//! An `inventory` entry asks for the whole walk instead: every event, group
//! and handler one source configures, each handler with its identity and the
//! ownership the caller's bindings give it, and every shape the walk refuses.
//!
//! ## Scalars JSON cannot carry
//!
//! A TOML source yields dates, times and datetimes, and a float may be
//! infinite or NaN. None of those survive a JSON request, so the caller
//! replaces each with a random token string and sends `scalar_tokens`
//! alongside, mapping that token to the canonical form the scalar takes. The
//! caller picks a token only after checking that it appears nowhere in the
//! payload it is about to send, so nothing a configuration file can contain
//! is read as a token.

use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;

/// Schema discriminator for the request.
pub const CODEX_HOOK_IDENTITY_REQUEST_SCHEMA: &str = "guard-codex-hook-identity-request.v1";
/// Schema discriminator for the result.
pub const CODEX_HOOK_IDENTITY_RESULT_SCHEMA: &str = "guard-codex-hook-identity-result.v1";
/// Capability advertised by the runtime when this operation is available.
pub const CODEX_HOOK_IDENTITY_FEATURE: &str = "codex-hook-identity-v1";
/// Capability advertised when the op also answers `inventory` entries.
pub const CODEX_HOOK_INVENTORY_FEATURE: &str = "codex-hook-identity-v2";
/// Largest canonical request serialization the op will accept.
pub const CODEX_HOOK_IDENTITY_MAX_BYTES: usize = 4 * 1024 * 1024;
/// Most questions one request may carry.
pub const CODEX_HOOK_IDENTITY_MAX_ENTRIES: usize = 512;

/// One question about one hook definition.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct CodexHookIdentityEntryV1 {
    /// `handler`, `group`, `conflict`, `argv` or `inventory`.
    pub kind: String,
    /// The scope the source was read from, part of every digest but `argv`.
    #[serde(default)]
    pub source_scope: String,
    /// Whether the source enables hooks at all, part of every digest but `argv`.
    #[serde(default)]
    pub source_hooks_enabled: bool,
    /// The event the group is listed under, part of every digest but `argv`.
    #[serde(default)]
    pub event_name: String,
    /// The matcher group, as the source wrote it. Required for every kind but
    /// `argv`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub group: Option<Value>,
    /// The handler inside that group. Required for `handler`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub handler: Option<Value>,
    /// The command text to tokenize. Required for `argv`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub command: Option<String>,
    /// `json` or `toml`, the format the source was read from. Required for
    /// `inventory`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_format: Option<String>,
    /// An `inventory` source's hook events as `[name, groups]` pairs, in the
    /// order the source lists them. Absent when the source's `hooks` value is
    /// present but is not a table.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub events: Option<Vec<(String, Value)>>,
    /// Handlers an authenticated install manifest owns, as
    /// `{"event", "group": {"matcher"}, "handler"}` bindings.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub authenticated_bindings: Vec<Value>,
    /// Handlers a previous Guard install wrote, adopted exactly as written.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub legacy_bindings: Vec<Value>,
    /// Handlers bound to the command this install records for itself.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub self_bindings: Vec<Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct CodexHookIdentityRequestV1 {
    pub schema: String,
    #[serde(default)]
    pub request_id: String,
    /// Stand-ins for scalars a JSON request cannot carry, keyed by the token
    /// string that replaced them in `entries`.
    #[serde(default)]
    pub scalar_tokens: BTreeMap<String, Value>,
    /// The questions, in the caller's order.
    pub entries: Vec<CodexHookIdentityEntryV1>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct CodexHookIdentityResultV1 {
    pub schema: String,
    pub request_id: String,
    /// SHA-256 of the canonical request, binding the result to its request.
    pub request_sha256: String,
    /// `ok` or `error`.
    pub status: String,
    /// `ok`, or one of the `native_codex_hook_identity_*` codes.
    pub code: String,
    /// `{"identities": [...]}`, one answer per entry in the request's order.
    /// A `handler` or `group` entry answers `{"digest": "<hex>"}`, a
    /// `conflict` entry `{"digests": ["<hex>", ...]}`, an `argv` entry
    /// `{"argv": ["..."]}` or `{"argv": null}`, and an `inventory` entry
    /// `{"records": [...], "issues": [...]}`, or `{"records": null}` when a
    /// handler holds text no identity can be derived over.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub payload: Option<Value>,
}

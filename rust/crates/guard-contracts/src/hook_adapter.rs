//! `HookAdapter` — wire contract for the resident per-harness hook payload
//! adapter op.
//!
//! Python hands the raw harness hook payload (plus the host facts Rust must not
//! read itself: home, cwd, `PATH`) and the resident returns the prepared
//! payload, the typed action envelope, or one of the pure text views the hook
//! pipeline derives from a command. Payload values travel in an
//! order-preserving tagged form (`["d", key, value, ...]` for objects,
//! `["l", item, ...]` for lists, raw scalars) because the envelope depends on
//! payload key order. Python sends every field explicitly (nulls included) so
//! the request digest it binds matches the resident's.

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Schema discriminator for the request.
pub const HOOK_ADAPTER_REQUEST_SCHEMA: &str = "guard-hook-adapter-request.v1";
/// Schema discriminator for the result.
pub const HOOK_ADAPTER_RESULT_SCHEMA: &str = "guard-hook-adapter-result.v1";
/// Capability advertised by the runtime when this operation is available.
pub const HOOK_ADAPTER_FEATURE: &str = "hook-adapter-v1";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct HookAdapterRequestV1 {
    pub schema: String,
    pub request_id: String,
    pub query: HookAdapterQueryV1,
}

/// Host facts the resident cannot observe for the calling process.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct HookAdapterHostV1 {
    /// `os.path.expanduser("~")`, or `null` when unresolvable.
    pub tilde_home: Option<String>,
    /// `str(Path.home())`, or `null` when unresolvable.
    pub default_home: Option<String>,
    /// `os.getcwd()`, or `null` when unresolvable.
    pub cwd: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum HookAdapterQueryV1 {
    /// Harness-specific payload preparation (alias and shape repair).
    PreparePayload {
        harness: String,
        payload: Value,
        devin_project_dir: Option<String>,
    },
    /// The typed, redacted action envelope for one hook payload.
    ActionEnvelope(Box<ActionEnvelopeQueryV1>),
    /// Redacted command text (secrets and absolute-path mentions).
    CommandDetail {
        text: String,
        home_dir: Option<String>,
        host: HookAdapterHostV1,
    },
    /// The command text a tool payload carries, or `null`.
    CommandText { tool_name: Value, tool_input: Value },
    /// The home-relative, path-safe label for a workspace.
    WorkspaceLabel {
        workspace: String,
        home_dir: Option<String>,
        host: HookAdapterHostV1,
    },
    /// Target paths named by an apply-patch tool input.
    ApplyPatchPaths { tool_input: Value },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ActionEnvelopeQueryV1 {
    pub harness: String,
    pub event_name: String,
    pub payload: Value,
    pub workspace: Option<String>,
    pub home_dir: Option<String>,
    pub devin_project_dir: Option<String>,
    /// Caller `PATH`, bound into package-intent resolution.
    pub path_env: Option<String>,
    pub host: HookAdapterHostV1,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct HookAdapterResultV1 {
    pub schema: String,
    pub request_id: String,
    /// `sha256:` digest of the canonical request, binding the reply to it.
    pub request_sha256: String,
    /// `ok` or `error`.
    pub status: String,
    /// `ok`, or a `native_hook_adapter_*` failure code.
    pub code: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub payload: Option<Value>,
}

//! Local CLI grant decision contract.
//!
//! The resident reads grant rows from `guard.db` and decides whether a
//! command is covered by a this-device allow or block. Callers supply only the
//! verified identity material, the action being refined, and the command id
//! they resolved from the command model. Grant state, command catalog
//! presence, per-command states, the observation surface, and the identity
//! comparison are all read and decided natively.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::LocalCliIdentitySourceV1;

/// Schema discriminator for the request.
pub const LOCAL_CLI_GRANT_REQUEST_SCHEMA: &str = "guard-local-cli-grant-request.v1";
/// Schema discriminator for the result.
pub const LOCAL_CLI_GRANT_RESULT_SCHEMA: &str = "guard-local-cli-grant-result.v1";
/// Capability advertised by the runtime when this operation is available.
pub const LOCAL_CLI_GRANT_FEATURE: &str = "local-cli-grant-v1";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct LocalCliGrantRequestV1 {
    pub schema: String,
    pub request_id: String,
    /// Absolute path of `guard.db`; must sit directly under `guard_home`.
    pub store_path: String,
    /// Absolute path of the guard home that owns the store.
    pub guard_home: String,
    /// Action the grant would refine. Only `allow`, `review`,
    /// `require-reapproval` and `warn` can be refined.
    pub current_action: String,
    /// Verified launch material. The resident derives the identity itself.
    pub source: LocalCliIdentitySourceV1,
    /// Command id the caller resolved from the command model. Non-authoritative:
    /// the resident only uses it to select a stored per-command state, and a
    /// missing id is treated as the catch-all `other` command.
    #[serde(default)]
    pub command_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct LocalCliGrantResultV1 {
    pub schema: String,
    pub request_id: String,
    /// `sha256:` digest of the canonical request, binding the reply to it.
    pub request_sha256: String,
    /// `ok` or `error`.
    pub status: String,
    /// `ok`, or a `native_local_cli_grant_*` failure code.
    pub code: String,
    /// `{state, cli_id, identity_hash, capabilities}` on success. `state` is
    /// `allowed`, `blocked`, or `none`. `capabilities` is the sorted list of
    /// grant capabilities switched on for an allowed `surface='cli'`
    /// connector (`loopback-network`, `state-dir-read`, `state-dir-write`);
    /// it is empty for every other answer, and an absent row is off.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub payload: Option<Value>,
}

/// Schema discriminator for the hook-time local CLI request.
pub const LOCAL_CLI_HOOK_REQUEST_SCHEMA: &str = "guard-local-cli-hook-request.v1";
/// Schema discriminator for the hook-time local CLI result.
pub const LOCAL_CLI_HOOK_RESULT_SCHEMA: &str = "guard-local-cli-hook-result.v1";
/// Capability advertised by the runtime when `local_cli_hook` is available.
pub const LOCAL_CLI_HOOK_FEATURE: &str = "local-cli-hook-v1";

/// One shell `PreToolUse`: record the unlisted CLIs the command launches,
/// then refine `current_action` by this-device grants. The resident derives
/// every identity, reads and writes `guard.db`, and decides; the caller sends
/// only the command, its launch context and the action being refined.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct LocalCliHookRequestV1 {
    pub schema: String,
    pub request_id: String,
    /// Absolute path of `guard.db`; must sit directly under `guard_home`.
    pub store_path: String,
    /// Absolute path of the guard home that owns the store.
    pub guard_home: String,
    /// OAuth source the store instance is bound to (`GuardStore.guard_source`).
    pub source: String,
    /// SQLite busy timeout in milliseconds for the observation writes.
    pub busy_timeout_ms: u64,
    pub command: String,
    pub cwd: String,
    #[serde(default)]
    pub home_dir: Option<String>,
    /// The caller's home, which launch derivation resolves `~` against.
    pub user_home: String,
    /// The caller's environment, which launch derivation resolves against.
    pub env: BTreeMap<String, String>,
    /// Action the grant would refine.
    pub current_action: String,
    /// The reason code of `current_action`, when the caller has one. Only
    /// `native_workspace_containment_executable_outside_roots` changes how a
    /// review is refined; it is omitted from the digest material when absent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub current_reason_code: Option<String>,
    /// Whether grants may refine the action; observation runs either way.
    pub grant_allowed: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct LocalCliHookResultV1 {
    pub schema: String,
    pub request_id: String,
    /// `sha256:` digest of the canonical request, binding the reply to it.
    pub request_sha256: String,
    /// `ok` or `error`.
    pub status: String,
    /// `ok`, or a `native_local_cli_hook_*` failure code.
    pub code: String,
    /// `{action}` on success.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub payload: Option<Value>,
}

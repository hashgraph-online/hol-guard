//! Local CLI grant decision contract.
//!
//! The resident reads grant rows from `guard.db` and decides whether a
//! command is covered by a this-device allow or block. Callers supply only the
//! verified identity material, the action being refined, and the command id
//! they resolved from the command model. Grant state, command catalog
//! presence, per-command states, the observation surface, and the identity
//! comparison are all read and decided natively.

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
    /// `{state, cli_id, identity_hash}` on success. `state` is `allowed`,
    /// `blocked`, or `none`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub payload: Option<Value>,
}

//! Connector setup context contract.
//!
//! A connector Guard held for review because it did not recognise it keeps a
//! little context about why: the first cause that blocked it and the scrubbed
//! wording of its latest review. The caller names the observed identity and
//! passes already composed review text; the resident scrubs and caps that text
//! again, records it on the observation, and answers with what the user can
//! already rely on in the same namespace and the setup choice Guard would
//! recommend. The operation never writes a grant or a capability.

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Schema discriminator for the request.
pub const CONNECTOR_SETUP_CONTEXT_REQUEST_SCHEMA: &str = "guard-connector-setup-context-request.v1";
/// Schema discriminator for the result.
pub const CONNECTOR_SETUP_CONTEXT_RESULT_SCHEMA: &str = "guard-connector-setup-context-result.v1";
/// Capability advertised by the runtime when this operation is available.
pub const CONNECTOR_SETUP_CONTEXT_FEATURE: &str = "connector-setup-context-v1";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ConnectorSetupContextRequestV1 {
    pub schema: String,
    pub request_id: String,
    /// Absolute path of `guard.db`; must sit directly under `guard_home`.
    pub store_path: String,
    /// Absolute path of the guard home that owns the store.
    pub guard_home: String,
    /// OAuth source the store instance is bound to (`GuardStore.guard_source`).
    pub source: String,
    /// SQLite busy timeout in milliseconds for the context write.
    pub busy_timeout_ms: u64,
    /// Observed connector, as recorded by the hook that saw it.
    pub cli_id: String,
    pub identity_hash: String,
    /// What blocked the connector first: `exec_outside_roots`,
    /// `connect_loopback`, `read_home_state`, `write_home_state` or
    /// `unrecognised_tool`. Kept only while the observation has none.
    #[serde(default)]
    pub first_blocked_cause: Option<String>,
    /// Review wording composed by Guard, never argv operands or tool arguments.
    #[serde(default)]
    pub trigger_summary: Option<String>,
    #[serde(default)]
    pub why_now: Option<String>,
    #[serde(default)]
    pub harness: Option<String>,
    #[serde(default)]
    pub workspace_label: Option<String>,
    /// When the context was seen, as the caller's UTC timestamp.
    pub observed_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ConnectorSetupContextResultV1 {
    pub schema: String,
    pub request_id: String,
    /// `sha256:` digest of the canonical request, binding the reply to it.
    pub request_sha256: String,
    /// `ok` or `error`.
    pub status: String,
    /// `ok`, or a `native_connector_setup_context_*` failure code.
    pub code: String,
    /// On success: `{cli_id, identity_hash, surface, first_blocked_cause,
    /// resolution_state, allowed_alternatives, card_recommendation}`.
    /// `resolution_state` is derived from the grant (`unset`, `allowed` or
    /// `blocked`) and never stored. `card_recommendation.preselected` is
    /// always `false`: a recommendation is shown, never applied.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub payload: Option<Value>,
}

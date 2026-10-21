//! Wire types for the resident's `native_permission_persist_plan` query.
//!
//! A Claude-native approval becomes a saved policy in two steps. The resident
//! decides what is saved: the stored hash a later lookup matches, the policy
//! action, the audit events and whether the inventory row counts as approved.
//! The Python transport then performs the store writes the plan names, in the
//! order it names them, and decides nothing.

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

/// Advertised when the resident answers `native_permission_persist_plan`; a
/// resident that predates it rejects the query, so a caller asks for this
/// first and persists nothing without it.
pub const HOOK_DECISION_NATIVE_PERMISSION_PERSIST_FEATURE: &str =
    "hook-decision-native-permission-persist-plan-v1";

/// Facts for one native approval. Every optional field is sent explicitly so
/// the request digest the reply binds to covers the whole question.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct NativePermissionPersistInputsV1 {
    pub artifact_id: String,
    pub artifact_hash: String,
    pub artifact_type: Option<String>,
    pub config_path: Option<String>,
    pub source_scope: Option<String>,
    /// The artifact's raw command text as the metadata carried it; only a
    /// string takes part in the exact-match context.
    pub raw_command_text: Option<Value>,
    /// The artifact's wrapper chain as the metadata carried it; only an array
    /// takes part in the exact-match context, and only its string items.
    pub wrapper_chain: Option<Value>,
    /// The native prompt's own answer (`allow` saves an allow, anything else a
    /// block).
    pub action: String,
    pub reason: String,
    pub source: String,
    /// The action the current policy already settled on, when the caller is
    /// the post-tool hook; `None` when the user's answer is saved outright.
    pub authoritative_action: Option<String>,
    /// `os.path.expanduser("~")` on the host, when resolvable; the only part
    /// of the host environment a `~` config path depends on.
    pub tilde_home: Option<String>,
}

/// One audit event of the plan.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct NativePermissionEventV1 {
    pub name: String,
    pub payload: Map<String, Value>,
    /// Written before the policy row (and so not at all when the policy write
    /// is refused) rather than after it.
    pub before_policy: bool,
}

/// What to persist. `stored_artifact_hash` and `policy_action` are present
/// together or not at all: without them no policy row is written.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct NativePermissionPersistPlanV1 {
    pub stored_artifact_hash: Option<String>,
    /// `allow` or `block`.
    pub policy_action: Option<String>,
    pub events: Vec<NativePermissionEventV1>,
    /// Whether the inventory row is recorded as approved.
    pub inventory_approved: bool,
}

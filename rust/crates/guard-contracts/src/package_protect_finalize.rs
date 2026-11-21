//! `PackageProtectFinalize` — wire contract for the resident op owning the
//! decision tail of `local_supply_chain._final_package_protect_authority`:
//! everything after the pre-spawn authority rebuild, so the launch path makes
//! one resident round trip instead of a chain of reuse, token, rewrite and
//! stored-policy calls.
//!
//! The caller keeps the config and authority callbacks, the saved-approval
//! claim and the rebuild itself, and sends their outcome plus the stored-policy
//! facts it hydrated. The reply is a patch over `evaluation`.

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Capability advertised when the package-protect finalize op exists.
pub const PACKAGE_PROTECT_FINALIZE_FEATURE: &str = "package-protect-finalize-v1";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct PackageProtectFinalizeRequestV1 {
    pub schema: String,
    pub request_id: String,
    pub guard_home: String,
    /// `policy_action`, `reasons` and `packages` of the evaluation the tail
    /// starts from: the initial evaluation when the rebuild found no package
    /// intent, the failed claim's evaluation, or the rebuilt evaluation.
    pub evaluation: Value,
    /// The rebuilt authority's current action; absent when the rebuild found
    /// no package intent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub current_action: Option<String>,
    pub initial_artifact_id: String,
    pub initial_artifact_hash: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub current_artifact_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub current_artifact_hash: Option<String>,
    pub observe_mode: bool,
    /// The saved-approval claim ran and its evaluation was not permitted.
    pub claim_failed: bool,
    pub saved_approval_claimed: bool,
    /// Disposition the successful claim reported (`consumed` or `retained`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub claim_disposition: Option<String>,
    /// Read-only stored-policy facts for the rebuilt artifact: the
    /// `PackagePolicyResolveRequestV1` fields other than the transport fields,
    /// `evaluation`, `current_action` and the claim fields. Absent when the
    /// tail cannot consult saved policy.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stored_policy: Option<Value>,
}

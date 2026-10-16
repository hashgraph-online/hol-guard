//! `PolicyDecisionLookup` — wire contract for the resident op that performs
//! `resolve_policy_decision_lookup` natively: open `store_path`, run the
//! bounded/non-consuming or consuming multi-scope probe plan, apply scoped
//! exact-match + eligibility rules, verify row integrity against caller-shipped
//! material/state, claim one-shot local-once approvals, emit `guard_events`,
//! and return the selected `lookup_result` payload.
//!
//! The integrity material and integrity state are caller-shipped evidence:
//! Python still owns the OS-keyring-facing secret procurement and the
//! `_refresh_policy_integrity_state` write path (generation advance / secret
//! minting mutate the secret store and `sync_state`). Rust consumes the
//! resolved `integrity_state` snapshot + raw `integrity_key`/`key_id` to verify
//! candidate rows and to classify `TrustStatus`. Remote policy sources skip
//! local integrity verification on both sides.

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Schema discriminator for the request.
pub const POLICY_DECISION_LOOKUP_REQUEST_SCHEMA: &str = "guard-policy-decision-lookup-request.v1";
/// Schema discriminator for the result.
pub const POLICY_DECISION_LOOKUP_RESULT_SCHEMA: &str = "guard-policy-decision-lookup-result.v1";
/// Capability advertised by the runtime when this operation is available.
pub const POLICY_DECISION_LOOKUP_FEATURE: &str = "policy-decision-lookup-v1";
/// Capability advertised when a runtime saved-decision read also composes the
/// runtime hook's `saved_reuse` verdict (`RuntimeSavedLookupV1::reuse`).
pub const RUNTIME_SAVED_REUSE_FEATURE: &str = "runtime-saved-reuse-v1";
/// Capability advertised when the resident expands a probe group's direct id
/// into its exact-command and memory-pattern candidates
/// (`PolicyLookupProbeGroupsV1::memory`). A caller that sends `memory` sends
/// unexpanded groups with it, and the probe-groups contract denies unknown
/// fields, so a runtime without this capability must not be sent either.
pub const POLICY_LOOKUP_MEMORY_FEATURE: &str = "policy-decision-lookup-memory-v1";

/// Largest canonical request serialization the op will accept.
pub const POLICY_DECISION_LOOKUP_MAX_BYTES: usize = 512 * 1024;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct PolicyDecisionLookupRequestV1 {
    pub schema: String,
    /// Optional caller correlation id; echoed back in the result.
    #[serde(default)]
    pub request_id: String,
    /// Absolute path to the guard store SQLite database.
    pub store_path: String,
    /// Absolute path to the resolved guard home (for scoped secret refs).
    pub guard_home: String,
    pub harness: String,
    #[serde(default)]
    pub artifact_id: Option<String>,
    #[serde(default)]
    pub artifact_hash: Option<String>,
    #[serde(default)]
    pub workspace: Option<String>,
    #[serde(default)]
    pub publisher: Option<String>,
    /// Lookup timestamp; `_canonical_utc_timestamp(now or _now())` resolved by
    /// the caller.
    pub now: String,
    #[serde(default)]
    pub runtime_exact_match_context: Option<String>,
    /// Mirror of the Python signature default (`consume_one_shot=True`).
    #[serde(default = "default_true")]
    pub consume_one_shot: bool,
    /// Peek only the exact local-once approval and skip the policy rows. The
    /// local-once peek of `peek_local_once_approval` callers; never consumes.
    #[serde(default, skip_serializing_if = "is_false")]
    pub local_once_only: bool,
    /// `_refresh_policy_integrity_state(...)` output captured by Python just
    /// before dispatch: `mode`/`enforcement`/`generation`/`degraded_reasons`/
    /// `backend`/`setup_available`/`key_id`/`runtime_protection`/... .
    #[serde(default)]
    pub integrity_state: Option<Value>,
    /// Resolved policy-integrity HMAC key bytes (base64url, no padding). When
    /// `None` the op still runs but local rows verify as `unknown_key`.
    #[serde(default)]
    pub integrity_key_b64: Option<String>,
    #[serde(default)]
    pub integrity_key_id: Option<String>,
    /// Local-once approval HMAC key bytes (base64url) for the one-shot
    /// peek/claim path.
    #[serde(default)]
    pub local_once_integrity_key_b64: Option<String>,
    #[serde(default)]
    pub local_once_integrity_key_id: Option<String>,
    /// Materialized policy-bundle row identities (11-tuples); `None` means the
    /// bundle source is unset → identity compare short-circuits.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy_bundle_decision_identities: Option<Vec<Vec<Value>>>,
    /// Non-consuming saved-decision read over several probe groups. Each group
    /// is one artifact hash and its candidate ids (direct, exact-command, then
    /// memory-pattern); the payload is the most restrictive group's decision.
    /// `artifact_id` names the action for the approval-reuse miss diagnostic
    /// in this mode; with `reuse`, its hash is the current approval context
    /// token the resident builds.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub probe_groups: Option<PolicyLookupProbeGroupsV1>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct PolicyLookupProbeGroupsV1 {
    /// Git-derived portable workspace, when the workspace has one.
    #[serde(default)]
    pub portable_workspace: Option<String>,
    pub groups: Vec<PolicyLookupProbeGroupV1>,
    /// Also compose the approval-reuse verdict for the current action.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reuse: Option<PolicyLookupReuseV1>,
    /// A runtime hook evaluation's saved-decision probes, composed in place of
    /// `groups` (which is then empty).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub runtime: Option<RuntimeSavedLookupV1>,
    /// Remembered-decision inputs. With them each group names only its direct
    /// id, and the resident appends that id's exact-command and memory-pattern
    /// candidates.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub memory: Option<PolicyLookupMemoryV1>,
}

/// The fields a remembered decision is fingerprinted from.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct PolicyLookupMemoryV1 {
    pub command: Option<String>,
    pub artifact_type: Option<String>,
    pub artifact_name: Option<String>,
    pub harness: Option<String>,
}

/// The saved-decision read of a runtime hook evaluation: the current and the
/// legacy-hash probes, each narrowed to a decision whose scope may apply to
/// the artifact, the legacy one kept when strictly more severe, then the
/// Claude alias probe when neither matched.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct RuntimeSavedLookupV1 {
    pub current: RuntimeSavedProbeV1,
    pub legacy: RuntimeSavedProbeV1,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub alias: Option<RuntimeSavedProbeV1>,
    /// Also compose the runtime hook's `saved_reuse` verdict on the lookup's
    /// connection; the answer is returned as `saved_reuse`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reuse: Option<RuntimeSavedReuseV1>,
}

/// The current-request inputs of a runtime hook's `saved_reuse` verdict. The
/// stored decision, its token check and the miss diagnosis come from the
/// lookup itself.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct RuntimeSavedReuseV1 {
    pub current_action: Value,
    /// The context token of a fresh Cursor native shell allowance.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cursor_native_token: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct RuntimeSavedProbeV1 {
    pub harness: String,
    pub artifact_id: String,
    pub artifact_hash: String,
    #[serde(default)]
    pub workspace: Option<String>,
    /// Git-derived portable workspace, when the workspace has one.
    #[serde(default)]
    pub portable_workspace: Option<String>,
    #[serde(default)]
    pub publisher: Option<String>,
    #[serde(default)]
    pub exact_match_context: Option<String>,
    /// The artifact carries runtime risk classes, so a broad saved scope
    /// applies only when it names this exact artifact.
    #[serde(default)]
    pub risk_scoped: bool,
    /// The remembered-decision fingerprint inputs; without them only the
    /// direct artifact id is probed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub memory: Option<RuntimeSavedMemoryV1>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct RuntimeSavedMemoryV1 {
    #[serde(default)]
    pub command: Option<String>,
    #[serde(default)]
    pub artifact_type: Option<String>,
    #[serde(default)]
    pub artifact_name: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct PolicyLookupReuseV1 {
    pub current_action: Value,
    /// Generic-hook approval-context inputs; the resident builds the current
    /// token from them and returns it as `current_token`.
    pub approval_context_inputs: Value,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct PolicyLookupProbeGroupV1 {
    /// `None` means the current approval context token (requires `reuse`).
    #[serde(default)]
    pub artifact_hash: Option<String>,
    pub candidate_artifact_ids: Vec<String>,
}

fn default_true() -> bool {
    true
}

fn is_false(value: &bool) -> bool {
    !*value
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct PolicyDecisionLookupResultV1 {
    pub schema: String,
    pub request_id: String,
    /// SHA-256 of the raw request bytes, binding the result to its request.
    pub request_sha256: String,
    /// `ok` or `error`.
    pub status: String,
    /// `ok`, or one of the `native_policy_decision_lookup_*` failure codes.
    pub code: String,
    /// The `lookup_result` dict on success.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub payload: Option<Value>,
}

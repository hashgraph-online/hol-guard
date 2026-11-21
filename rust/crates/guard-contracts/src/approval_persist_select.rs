//! `ApprovalPersistSelect` - wire contract for the resident op that answers
//! whether one approval may be saved, and whether the action it allows can
//! actually be bound to an execution.
//!
//! `ApprovalScopeSelect` decides what scope a user's answer resolves to.
//! This op decides the two things that follow from the same contract: may a
//! selection at that scope be remembered, and does the request offer any way
//! to run the action the user allowed. Both refuse the resolution outright,
//! so they belong with the contract rather than with the caller. The op is
//! pure, and the resident derives the contract itself instead of trusting
//! one the caller claims to hold.

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::ApprovalScopeItemV1;

/// Schema discriminator for the request.
pub const APPROVAL_PERSIST_SELECT_REQUEST_SCHEMA: &str = "guard-approval-persist-select-request.v1";
/// Schema discriminator for the result.
pub const APPROVAL_PERSIST_SELECT_RESULT_SCHEMA: &str = "guard-approval-persist-select-result.v1";
/// Capability advertised by the runtime when this operation is available.
pub const APPROVAL_PERSIST_SELECT_FEATURE: &str = "approval-persist-select-v1";
/// Largest canonical request serialization the op will accept.
pub const APPROVAL_PERSIST_SELECT_MAX_BYTES: usize = 4 * 1024 * 1024;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ApprovalPersistSelectRequestV1 {
    pub schema: String,
    #[serde(default)]
    pub request_id: String,
    /// The request being resolved, narrowed exactly as `ApprovalScope` takes it.
    pub item: ApprovalScopeItemV1,
    /// `allow` or `block`. Anything else is refused rather than coerced.
    pub action: String,
    /// The scope `ApprovalScopeSelect` applied, which is what a saved row
    /// would cover.
    pub applied_scope: String,
    /// Whether the client asked for the decision to be remembered. `null` is
    /// a client that expressed no preference.
    #[serde(default)]
    pub persist_policy: Option<bool>,
    /// Whether `ApprovalScopeSelect` narrowed the client's choice. A narrowed
    /// selection is never remembered, because the user did not choose it.
    /// Required: a caller that omits this gate is refused rather than read as
    /// an unnarrowed choice the user never made.
    pub scope_narrowed: bool,
    /// The contract version the client echoed back, absent for a legacy
    /// client that never read one.
    #[serde(default)]
    pub contract_version: Option<String>,
    /// The contract digest the client echoed back. Present exactly when
    /// `contract_version` is.
    #[serde(default)]
    pub contract_digest: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ApprovalPersistSelectResultV1 {
    pub schema: String,
    pub request_id: String,
    /// SHA-256 of the canonical request, binding the result to its request.
    pub request_sha256: String,
    /// `ok` or `error`.
    pub status: String,
    /// `ok`, or one of the `native_approval_persist_select_*` failure codes.
    pub code: String,
    /// `{"outcome": "selected", "persist_policy": true | null, "contract": {...}}`
    /// or `{"outcome": "refused", "reason": ..., "contract": {...}}`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub payload: Option<Value>,
}

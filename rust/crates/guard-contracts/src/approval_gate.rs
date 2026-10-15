//! `ApprovalGate` — wire contract for the resident op that runs the
//! password/TOTP approval-gate methods (`approval_gate.py` port) inside the
//! resident under one state lock.
//!
//! A single request carries `guard_home` + `method` + a free-form `params`
//! object (per-method) plus optional `approval_gate_input` /
//! `approval_gate_grant`. The resident owns `_load_state`/`_write_state` and
//! the `_ACTIVE_GRANTS` table; secrets/TOTP/Fernet never cross the wire.

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Schema discriminator for the request.
pub const APPROVAL_GATE_REQUEST_SCHEMA: &str = "guard-approval-gate-request.v1";
/// Schema discriminator for the result.
pub const APPROVAL_GATE_RESULT_SCHEMA: &str = "guard-approval-gate-result.v1";
/// Capability advertised by the runtime when this operation is available.
pub const APPROVAL_GATE_FEATURE: &str = "approval-gate-v2";

/// Largest canonical request serialization the op will accept.
pub const APPROVAL_GATE_MAX_BYTES: usize = 512 * 1024;

/// `ApprovalGateInput` wire shape (`approval_gate.py:129-142`). All optional —
/// the method decides which it consumes.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ApprovalGateInputWireV1 {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub password: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub new_password: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub confirm_password: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub totp_code: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub use_cooldown: Option<bool>,
    #[serde(default)]
    pub revoke_cooldown: bool,
    #[serde(default)]
    pub require_fresh_totp: bool,
}

/// `ApprovalGateGrant` wire shape — the 15-field frozen proof handle
/// (`approval_gate.py:142-158`), identical to `ApprovalGateGrantV1`. Tokens,
/// factor_generation and guard_home live table-side (`GrantMetadata`), never
/// on the wire.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ApprovalGateGrantWireV1 {
    pub grant_id: String,
    pub purpose: String,
    pub issued_at: String,
    pub expires_at: String,
    pub action: String,
    pub scope: String,
    pub subject: String,
    pub session_nonce: String,
    pub factor_set: Vec<String>,
    pub strict: bool,
    pub used_cooldown: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cooldown_expires_at: Option<String>,
    pub password_verified: bool,
    pub totp_verified: bool,
}

/// Methods the `ApprovalGate` op dispatches (the Python free fns it replaces).
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ApprovalGateMethodV1 {
    /// `public_config` — snapshot; no input/grant.
    PublicConfig,
    /// `recent_totp_satisfied` — predicate; no input/grant.
    RecentTotpSatisfied,
    /// `verify` — `_verify_or_raise_locked`; returns a grant.
    Verify,
    /// `validate_grant` — `_validate_grant_locked` (non-consuming).
    ValidateGrant,
    /// `update_settings` — writes settings state.
    UpdateSettings,
    /// `validate_settings_update` — dry-run.
    ValidateSettingsUpdate,
    /// `revoke_cooldown`.
    RevokeCooldown,
    /// `unlock_cooldown` — password re-verify + duration.
    UnlockCooldown,
    /// `begin_totp_enrollment`.
    BeginTotpEnrollment,
    /// `confirm_totp_enrollment`.
    ConfirmTotpEnrollment,
    /// `disable_totp`.
    DisableTotp,
    /// `require_approval_decision`.
    RequireApprovalDecision,
    /// `require_high_risk`.
    RequireHighRisk,
    /// `require_extension_control`.
    RequireExtensionControl,
    /// `consume_extension_control_grant`.
    ConsumeExtensionControlGrant,
    /// `require_local_cli_trust`.
    RequireLocalCliTrust,
    /// `consume_local_cli_trust_grant`.
    ConsumeLocalCliTrustGrant,
    /// `require_policy_clear`.
    RequirePolicyClear,
    /// `require_settings_write`.
    RequireSettingsWrite,
    /// `require_policy_write`.
    RequirePolicyWrite,
    /// `require_request_resolution`.
    RequireRequestResolution,
    /// `create_verifier` — PBKDF2 verifier dict for a new password.
    CreateVerifier,
    /// `audit_payload` — `{"approval_gate": {...}}` envelope.
    AuditPayload,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ApprovalGateRequestV1 {
    pub schema: String,
    /// Optional caller correlation id; echoed back in the result.
    #[serde(default)]
    pub request_id: String,
    /// Absolute path to the resolved guard home.
    pub guard_home: String,
    /// Which approval-gate method to run.
    pub method: ApprovalGateMethodV1,
    /// Free-form method params (settings payload, action/scope/subject/etc.).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub params: Option<Value>,
    /// `ApprovalGateInput` (password/TOTP/... for verify+enrollment methods).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub approval_gate_input: Option<ApprovalGateInputWireV1>,
    /// `ApprovalGateGrant` for validate/consume/require_* methods.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub approval_gate_grant: Option<ApprovalGateGrantWireV1>,
    /// `strict` flag for verify/require_* methods.
    #[serde(default)]
    pub strict: bool,
    /// `purpose` for require_high_risk / verify.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub purpose: Option<String>,
    /// Request timestamp (`...Z` / offset ISO); the resident-derived clock is
    /// used when absent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub now: Option<String>,
    /// `duration_seconds` for unlock_cooldown.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub duration_seconds: Option<i64>,
    /// `device_label` for begin_totp_enrollment.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub device_label: Option<String>,
    /// Caller's local OS-session signals (`sid=..`, terminal env, `ppid=..`).
    /// Only the calling process can observe its own session; the resident
    /// hashes these into the recent-TOTP binding. Required on every request:
    /// a missing field is a contract error, never a resident-side fallback.
    pub session_signals: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ApprovalGateResultV1 {
    pub schema: String,
    pub request_id: String,
    /// SHA-256 of the canonical request serialization.
    pub request_sha256: String,
    /// `ok` or `error`.
    pub status: String,
    /// `ok`, or the Python `ApprovalGateError.code` value.
    pub code: String,
    /// Python `ApprovalGateError.status` (HTTP-ish) on error.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error_status: Option<u16>,
    /// Python `ApprovalGateError` message on error (empty on success).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    /// Method result payload — config dict, grant dict, enrollment dict, or a
    /// `{"satisfied":bool}`/`{"grant":..}`/`{"skipped":true}` envelope.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub payload: Option<Value>,
}

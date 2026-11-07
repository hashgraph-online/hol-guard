//! Turning Pulse off.
//!
//! - `disable_pulse` needs a fresh, strict Pulse grant for `settings_write`
//!   that names this exact operation (`PULSE_DISABLE_ACTION`,
//!   `PULSE_DISABLE_SUBJECT`), so an approval for another settings change
//!   cannot turn Pulse off.
//! - `recover_pulse` is for a user who lost access to the YID app. It needs
//!   the approval password and the one-time recovery code shown at
//!   enrollment. Neither is ever readable by an agent: the password is a
//!   PBKDF2 verifier and the code is stored only as a SHA-256 hash.
//!
//! Both end every grant and cooldown, and bring back an authenticator that
//! Pulse paused.

#![forbid(unsafe_code)]

use std::path::Path;

use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::approval_gate_grants::{ApprovalGateErrorV1, ApprovalGateGrantV1, ApprovalGateGrants};
use crate::approval_gate_pulse::{err, factor_generation, pulse_enabled};
use crate::approval_gate_pulse_enrollment::state_io;
use crate::approval_gate_pulse_store::clear_pending_for_home;
use crate::approval_gate_settings::public_config_locked;
use crate::approval_gate_state::{
    constant_time_eq, epoch, load_state, optional_string, record_failed_attempt,
    reset_failed_attempts, write_state, ApprovalGateFactor,
};
use crate::approval_gate_verify::{
    invalidate_active_grants, raise_if_locked, rotate_authentication_state, verify_password_stage,
    ApprovalGateInputV1,
};
use crate::totp::TotpSecretStore;

/// Set while Pulse is on over an authenticator that was already set up. The
/// authenticator's secret stays stored but Guard accepts no codes from it.
pub(crate) const TOTP_PAUSED_BY_PULSE: &str = "totp_paused_by_pulse";

/// Remove Pulse's settings and secrets. An authenticator Pulse paused comes
/// back as it was, if its secret is still stored.
pub(crate) fn clear_pulse_state(guard_home: &Path, state: &mut Value) {
    // Requests made under the old factor can never verify; free their slots.
    clear_pending_for_home(guard_home);
    let mut store = TotpSecretStore::new(guard_home);
    for key in ["pulse_agent_secret_id", "pulse_binding_secret_id"] {
        if let Some(id) = optional_string(state.get(key)) {
            let _ = store.delete_secret(&id);
        }
    }
    if let Some(o) = state.as_object_mut() {
        o.retain(|k, _| !k.starts_with("pulse_"));
        if o.remove(TOTP_PAUSED_BY_PULSE) == Some(Value::Bool(true)) {
            let kept = optional_string(o.get("totp_secret_id"))
                .is_some_and(|id| store.get_secret(&id).is_some());
            if kept {
                o.insert("totp_enabled".into(), Value::Bool(true));
            } else {
                o.remove("totp_secret_id");
                o.remove("totp_last_counter");
            }
        }
    }
}

fn turn_pulse_off(
    guard_home: &Path,
    grants: &ApprovalGateGrants,
    mut state: Value,
    now: Option<&str>,
) -> Result<Value, ApprovalGateErrorV1> {
    clear_pulse_state(guard_home, &mut state);
    reset_failed_attempts(&mut state);
    rotate_authentication_state(&mut state);
    write_state(guard_home, &state, now).map_err(|_| state_io())?;
    invalidate_active_grants(grants, guard_home);
    Ok(public_config_locked(guard_home, now).to_dict())
}

/// The action a grant must name to turn Pulse off.
pub(crate) const PULSE_DISABLE_ACTION: &str = "pulse_disable";
/// The subject a grant must name to turn Pulse off.
pub(crate) const PULSE_DISABLE_SUBJECT: &str = "approval-gate:pulse";

/// `disable_pulse`. Needs a fresh, strict Pulse grant for `settings_write`
/// bound to turning Pulse off.
pub(crate) fn disable_pulse(
    guard_home: &Path,
    grants: &ApprovalGateGrants,
    grant: Option<&ApprovalGateGrantV1>,
    now: Option<&str>,
) -> Result<Value, ApprovalGateErrorV1> {
    let state = load_state(guard_home);
    if !pulse_enabled(&state) {
        return Err(err(
            "approval_gate_pulse_not_enabled",
            "Yanez Pulse is not the approval factor for this Guard.",
            409,
        ));
    }
    let Some(grant) = grant.filter(|g| g.factor_set == ["pulse"]) else {
        return Err(crate::approval_gate_pulse::pulse_required());
    };
    grants.validate_and_consume(
        &guard_home.to_string_lossy(),
        grant,
        epoch(Some(grant.expires_at.as_str())),
        Some("settings_write"),
        true,
        Some(PULSE_DISABLE_ACTION),
        None,
        Some(PULSE_DISABLE_SUBJECT),
        None,
        factor_generation(&state),
        false,
        true,
        epoch(now),
    )?;
    turn_pulse_off(guard_home, grants, state, now)
}

/// `recover_pulse`. The approval password and the one-time recovery code.
/// Failures count toward the password lockout.
pub(crate) fn recover_pulse(
    guard_home: &Path,
    grants: &ApprovalGateGrants,
    input: Option<&ApprovalGateInputV1>,
    now: Option<&str>,
) -> Result<Value, ApprovalGateErrorV1> {
    let mut state = load_state(guard_home);
    if !pulse_enabled(&state) {
        return Err(err(
            "approval_gate_pulse_not_enabled",
            "Yanez Pulse is not the approval factor for this Guard.",
            409,
        ));
    }
    raise_if_locked(&state, epoch(now))?;
    let input = input.cloned().unwrap_or_default();
    verify_password_stage(guard_home, &mut state, input.password.as_deref(), now)?;
    let stored = optional_string(state.get("pulse_recovery_hash")).unwrap_or_default();
    let offered = input
        .pulse_recovery_code
        .as_deref()
        .map(|code| hex::encode(Sha256::digest(code.trim().as_bytes())))
        .unwrap_or_default();
    if stored.is_empty() || !constant_time_eq(stored.as_bytes(), offered.as_bytes()) {
        record_failed_attempt(guard_home, &mut state, ApprovalGateFactor::Password, now);
        return Err(err(
            "approval_gate_pulse_recovery_invalid",
            "The recovery code is wrong.",
            403,
        ));
    }
    turn_pulse_off(guard_home, grants, state, now)
}

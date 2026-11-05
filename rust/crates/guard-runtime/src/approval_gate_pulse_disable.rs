//! Turning Pulse off.
//!
//! - `disable_pulse` needs a fresh, strict Pulse grant for `settings_write`.
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
use crate::approval_gate_pulse::{clear_pulse_state, err, factor_generation, pulse_enabled};
use crate::approval_gate_pulse_enrollment::state_io;
use crate::approval_gate_settings::public_config_locked;
use crate::approval_gate_state::{
    constant_time_eq, epoch, load_state, optional_string, record_failed_attempt,
    reset_failed_attempts, write_state, ApprovalGateFactor,
};
use crate::approval_gate_verify::{
    invalidate_active_grants, raise_if_locked, rotate_authentication_state, verify_password_stage,
    ApprovalGateInputV1,
};

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

/// `disable_pulse`. Needs a fresh, strict Pulse grant for `settings_write`.
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
        None,
        None,
        None,
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

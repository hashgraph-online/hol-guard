//! Who may start Pulse setup.
//!
//! `begin_pulse_enrollment` needs the current factor: the approval password,
//! plus the authenticator code when TOTP is on. The dashboard checks it first
//! on its own (`authorize_only`), which lets the same OS session start setup
//! without the factor for 15 minutes, so the user can paste the agent key and
//! try again after a refused scan. The authorization lives only in memory and
//! ends when it expires, when the factor generation changes, or when Pulse is
//! enrolled.

#![forbid(unsafe_code)]

use std::collections::HashMap;
use std::path::Path;
use std::sync::{Mutex, OnceLock};

use serde_json::{json, Value};

use crate::approval_gate_grants::ApprovalGateErrorV1;
use crate::approval_gate_pulse::{err, factor_generation};
use crate::approval_gate_state::{
    constant_time_eq, optional_string, record_failed_attempt, ApprovalGateFactor,
};
use crate::approval_gate_verify::{
    current_totp_session_binding, verify_password_stage, ApprovalGateInputV1,
};
use crate::totp::{verify_totp_code, TotpSecretStore, APPROVAL_GATE_TOTP_SKEW_STEPS};

/// How long a confirmed password lets the same session start Pulse setup.
pub(crate) const SETUP_AUTHORIZATION_SECONDS: i64 = 900;

/// A confirmed current factor, held in memory only. It lets the session that
/// confirmed it start Pulse setup until it expires, Pulse is enrolled, or the
/// password or authenticator changes.
pub(crate) struct SetupAuthorization {
    session_binding: String,
    factor_generation: i64,
    expires_at: i64,
}

pub(crate) fn setup_authorizations() -> &'static Mutex<HashMap<String, SetupAuthorization>> {
    static AUTHORIZATIONS: OnceLock<Mutex<HashMap<String, SetupAuthorization>>> = OnceLock::new();
    AUTHORIZATIONS.get_or_init(|| Mutex::new(HashMap::new()))
}

pub(crate) fn authorize_setup(guard_home: &Path, state: &Value, now_epoch: i64) -> i64 {
    let expires_at = now_epoch + SETUP_AUTHORIZATION_SECONDS;
    if let Ok(mut table) = setup_authorizations().lock() {
        table.insert(
            guard_home.to_string_lossy().into_owned(),
            SetupAuthorization {
                session_binding: current_totp_session_binding(),
                factor_generation: factor_generation(state),
                expires_at,
            },
        );
    }
    expires_at
}

pub(crate) fn setup_authorized(guard_home: &Path, state: &Value, now_epoch: i64) -> bool {
    let Ok(mut table) = setup_authorizations().lock() else {
        return false;
    };
    let key = guard_home.to_string_lossy().into_owned();
    let Some(auth) = table.get(&key) else {
        return false;
    };
    // Expired or outdated: drop it. Another session asking must not cancel it.
    if now_epoch > auth.expires_at || auth.factor_generation != factor_generation(state) {
        table.remove(&key);
        return false;
    }
    constant_time_eq(
        auth.session_binding.as_bytes(),
        current_totp_session_binding().as_bytes(),
    )
}

pub(crate) fn end_setup_authorization(guard_home: &Path) {
    if let Ok(mut table) = setup_authorizations().lock() {
        table.remove(guard_home.to_string_lossy().as_ref());
    }
}

pub(crate) fn totp_enabled(state: &Value) -> bool {
    state.get("totp_enabled") == Some(&Value::Bool(true))
}

/// Check the factor the gate uses today: the password, and the
/// authenticator code too when TOTP is on.
pub(crate) fn verify_current_factor(
    guard_home: &Path,
    state: &mut Value,
    input: &ApprovalGateInputV1,
    now: Option<&str>,
    now_epoch: f64,
) -> Result<(), ApprovalGateErrorV1> {
    verify_password_stage(guard_home, state, input.password.as_deref(), now)?;
    if !totp_enabled(state) {
        return Ok(());
    }
    let code = input
        .totp_code
        .as_deref()
        .ok_or_else(|| err("approval_gate_totp_required", "TOTP code is required.", 403))?;
    let secret = optional_string(state.get("totp_secret_id"))
        .and_then(|id| TotpSecretStore::new(guard_home).get_secret(&id))
        .ok_or_else(|| {
            err(
                "approval_gate_recovery_required",
                "Approval gate TOTP secret is unavailable.",
                423,
            )
        })?;
    let last = crate::approval_gate_state::optional_int(state.get("totp_last_counter"));
    match verify_totp_code(
        &secret,
        code,
        now_epoch,
        APPROVAL_GATE_TOTP_SKEW_STEPS,
        last,
        false,
    ) {
        Some(counter) => {
            if let Some(o) = state.as_object_mut() {
                o.insert("totp_last_counter".into(), json!(counter));
            }
            Ok(())
        }
        None => {
            record_failed_attempt(guard_home, state, ApprovalGateFactor::Totp, now);
            Err(err(
                "approval_gate_totp_invalid",
                "That authenticator code is wrong. Open your authenticator app and enter the current six-digit code.",
                403,
            ))
        }
    }
}

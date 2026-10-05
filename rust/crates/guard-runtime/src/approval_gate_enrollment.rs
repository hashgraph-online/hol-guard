//! Port of the TOTP enrollment lifecycle from
//! `src/codex_plugin_scanner/guard/approval_gate.py`.
//!
//! `_begin_totp_enrollment_locked` (:367-403), `_confirm_totp_enrollment_locked`
//! (:420-474), `_disable_totp_locked` (:490-549). Each writes state +
//! invalidates grants itself (per source). `_raise_if_locked` (:1144-1147)
//! shared.

#![forbid(unsafe_code)]

use std::path::Path;

use serde_json::Value;

use crate::approval_gate_grants::{ApprovalGateErrorV1, ApprovalGateGrants};
use crate::approval_gate_settings::public_config_locked;
use crate::approval_gate_state::ApprovalGatePublicConfig;
use crate::approval_gate_state::{
    enabled, epoch, is_future, iso_from_epoch, load_state, optional_int, optional_string,
    record_failed_attempt, reset_failed_attempts, verifier, verify_password, write_state,
    ApprovalGateFactor,
};
use crate::approval_gate_verify::{
    invalidate_active_grants, rotate_authentication_state, token_urlsafe, ApprovalGateInputV1,
};
use crate::totp::{
    build_otpauth_uri, generate_totp_secret, verify_totp_code, TotpSecretStore,
    APPROVAL_GATE_TOTP_PENDING_TTL_SECONDS, APPROVAL_GATE_TOTP_SKEW_STEPS,
};

fn err(code: &str, message: &str, status: u16) -> ApprovalGateErrorV1 {
    ApprovalGateErrorV1 {
        code: code.to_owned(),
        message: message.to_owned(),
        status,
    }
}

fn totp_enabled(state: &Value) -> bool {
    state.get("totp_enabled") == Some(&Value::Bool(true))
}

/// `_raise_if_locked` (:1144-1147).
fn raise_if_locked(state: &Value, now_epoch: f64) -> Result<(), ApprovalGateErrorV1> {
    if is_future(
        optional_string(state.get("locked_until")).as_deref(),
        now_epoch,
    ) {
        return Err(err(
            "approval_gate_locked",
            "Approval gate is temporarily locked.",
            423,
        ));
    }
    Ok(())
}

/// `_verify_password_stage` (:1155-1175) — local copy operating on `&mut Value`.
fn verify_password_stage(
    guard_home: &Path,
    state: &mut Value,
    password: Option<&str>,
    now: Option<&str>,
) -> Result<(), ApprovalGateErrorV1> {
    if verifier(state).is_none() {
        return Err(err(
            "approval_gate_recovery_required",
            "Approval gate is enabled but no verifier is configured.",
            423,
        ));
    }
    let password = match password {
        Some(p) => p,
        None => {
            let code = if totp_enabled(state) {
                "approval_gate_password_required"
            } else {
                "approval_gate_required"
            };
            return Err(err(code, "Approval password is required.", 403));
        }
    };
    if !verify_password(password, verifier(state)) {
        record_failed_attempt(guard_home, state, ApprovalGateFactor::Password, now);
        return Err(err(
            "approval_gate_invalid_password",
            "Approval password is invalid.",
            403,
        ));
    }
    Ok(())
}

/// `_begin_totp_enrollment_locked` (:367-403). Returns `pending`/`manual_key`/
/// `expires_at`/`otpauth_uri` dict.
pub(crate) fn begin_totp_enrollment_locked(
    guard_home: &Path,
    grants: &ApprovalGateGrants,
    approval_gate_input: Option<&ApprovalGateInputV1>,
    device_label: &str,
    now: Option<&str>,
) -> Result<Value, ApprovalGateErrorV1> {
    let mut state = load_state(guard_home);
    if !enabled(&state) {
        return Err(err(
            "approval_gate_required",
            "Approval password is required.",
            403,
        ));
    }
    if totp_enabled(&state) {
        return Err(err(
            "approval_gate_totp_enabled",
            "TOTP is already enabled.",
            400,
        ));
    }
    let now_epoch = epoch(now);
    raise_if_locked(&state, now_epoch)?;
    let gate_input = approval_gate_input.cloned().unwrap_or_default();
    verify_password_stage(guard_home, &mut state, gate_input.password.as_deref(), now)?;
    let mut store = TotpSecretStore::new(guard_home);
    store.ensure_ready().map_err(|_| {
        err(
            "approval_gate_recovery_required",
            "TOTP store unavailable.",
            423,
        )
    })?;
    let pending_secret_id =
        optional_string(state.get("totp_pending_secret_id")).unwrap_or_default();
    if !pending_secret_id.is_empty() {
        let _ = store.delete_secret(&pending_secret_id);
    }
    let secret = generate_totp_secret().ok_or_else(|| {
        err(
            "approval_gate_recovery_required",
            "Could not generate TOTP secret.",
            423,
        )
    })?;
    let next_secret_id = token_urlsafe(12);
    store.set_secret(&next_secret_id, &secret).map_err(|_| {
        err(
            "approval_gate_recovery_required",
            "Could not store TOTP secret.",
            423,
        )
    })?;
    let expires_at = iso_from_epoch(now_epoch + APPROVAL_GATE_TOTP_PENDING_TTL_SECONDS as f64);
    let was_totp_enabled = totp_enabled(&state);
    {
        let o = state.as_object_mut().unwrap();
        o.insert(
            "totp_pending_secret_id".into(),
            Value::String(next_secret_id),
        );
        o.insert(
            "totp_pending_expires_at".into(),
            Value::String(expires_at.clone()),
        );
        o.insert("totp_enabled".into(), Value::Bool(was_totp_enabled));
        o.remove("cooldown_expires_at");
    }
    reset_failed_attempts(&mut state);
    rotate_authentication_state(&mut state);
    write_state(guard_home, &state, now).map_err(|_| {
        err(
            "approval_gate_state_io",
            "Could not persist approval gate state.",
            500,
        )
    })?;
    invalidate_active_grants(grants, guard_home);
    let otpauth_uri = build_otpauth_uri(&secret, device_label);
    Ok(serde_json::json!({
        "pending": true,
        "manual_key": secret,
        "expires_at": expires_at,
        "otpauth_uri": otpauth_uri,
    }))
}

/// `_confirm_totp_enrollment_locked` (:420-474).
pub(crate) fn confirm_totp_enrollment_locked(
    guard_home: &Path,
    grants: &ApprovalGateGrants,
    approval_gate_input: Option<&ApprovalGateInputV1>,
    now: Option<&str>,
) -> Result<ApprovalGatePublicConfig, ApprovalGateErrorV1> {
    let mut state = load_state(guard_home);
    if !enabled(&state) {
        return Err(err(
            "approval_gate_required",
            "Approval password is required.",
            403,
        ));
    }
    let pending_secret_id = optional_string(state.get("totp_pending_secret_id"));
    let pending_expires_at = optional_string(state.get("totp_pending_expires_at"));
    let now_epoch = epoch(now);
    raise_if_locked(&state, now_epoch)?;
    let gate_input = approval_gate_input.cloned().unwrap_or_default();
    verify_password_stage(guard_home, &mut state, gate_input.password.as_deref(), now)?;
    if pending_secret_id.is_none() || !is_future(pending_expires_at.as_deref(), now_epoch) {
        return Err(err(
            "approval_gate_totp_pending_required",
            "No pending TOTP enrollment is available.",
            400,
        ));
    }
    let totp_code = match gate_input.totp_code.as_deref() {
        Some(c) => c.to_owned(),
        None => {
            return Err(err(
                "approval_gate_totp_required",
                "TOTP code is required.",
                403,
            ));
        }
    };
    let pending_secret_id = pending_secret_id.unwrap();
    let mut store = TotpSecretStore::new(guard_home);
    let pending_secret = store.get_secret(&pending_secret_id).ok_or_else(|| {
        err(
            "approval_gate_recovery_required",
            "Approval gate TOTP secret is unavailable.",
            423,
        )
    })?;
    let accepted_counter = verify_totp_code(
        &pending_secret,
        &totp_code,
        now_epoch,
        APPROVAL_GATE_TOTP_SKEW_STEPS,
        None,
        false,
    );
    let accepted_counter = match accepted_counter {
        Some(c) => c,
        None => {
            record_failed_attempt(guard_home, &mut state, ApprovalGateFactor::Totp, now);
            return Err(err(
                "approval_gate_totp_invalid",
                "That authenticator code is wrong. Open your authenticator app and enter the current six-digit code.",
                403,
            ));
        }
    };
    let active_secret_id = optional_string(state.get("totp_secret_id"));
    if let Some(active) = active_secret_id {
        if active != pending_secret_id {
            let _ = store.delete_secret(&active);
        }
    }
    {
        let o = state.as_object_mut().unwrap();
        o.insert("totp_secret_id".into(), Value::String(pending_secret_id));
        o.insert("totp_enabled".into(), Value::Bool(true));
        o.insert(
            "totp_last_counter".into(),
            Value::Number(accepted_counter.into()),
        );
    }
    reset_failed_attempts(&mut state);
    {
        let o = state.as_object_mut().unwrap();
        o.remove("totp_pending_secret_id");
        o.remove("totp_pending_expires_at");
        o.remove("cooldown_expires_at");
    }
    rotate_authentication_state(&mut state);
    write_state(guard_home, &state, now).map_err(|_| {
        err(
            "approval_gate_state_io",
            "Could not persist approval gate state.",
            500,
        )
    })?;
    invalidate_active_grants(grants, guard_home);
    Ok(public_config_locked(guard_home, now))
}

/// `_disable_totp_locked` (:490-549).
pub(crate) fn disable_totp_locked(
    guard_home: &Path,
    grants: &ApprovalGateGrants,
    approval_gate_input: Option<&ApprovalGateInputV1>,
    now: Option<&str>,
) -> Result<ApprovalGatePublicConfig, ApprovalGateErrorV1> {
    let mut state = load_state(guard_home);
    if !enabled(&state) {
        return Err(err(
            "approval_gate_required",
            "Approval password is required.",
            403,
        ));
    }
    let now_epoch = epoch(now);
    raise_if_locked(&state, now_epoch)?;
    let gate_input = approval_gate_input.cloned().unwrap_or_default();
    let secret_id = optional_string(state.get("totp_secret_id"));
    if secret_id.is_none() {
        if totp_enabled(&state) {
            return Err(err(
                "approval_gate_recovery_required",
                "Approval gate TOTP secret is unavailable.",
                423,
            ));
        }
        state
            .as_object_mut()
            .unwrap()
            .insert("totp_enabled".into(), Value::Bool(false));
        write_state(guard_home, &state, now).map_err(|_| {
            err(
                "approval_gate_state_io",
                "Could not persist approval gate state.",
                500,
            )
        })?;
        return Ok(public_config_locked(guard_home, now));
    }
    let totp_code = match gate_input.totp_code.as_deref() {
        Some(c) => c.to_owned(),
        None => {
            return Err(err(
                "approval_gate_totp_required",
                "TOTP code is required.",
                403,
            ));
        }
    };
    let secret_id = secret_id.unwrap();
    let mut store = TotpSecretStore::new(guard_home);
    let secret = store.get_secret(&secret_id).ok_or_else(|| {
        err(
            "approval_gate_recovery_required",
            "Approval gate TOTP secret is unavailable.",
            423,
        )
    })?;
    let accepted_counter = verify_totp_code(
        &secret,
        &totp_code,
        now_epoch,
        APPROVAL_GATE_TOTP_SKEW_STEPS,
        optional_int(state.get("totp_last_counter")),
        false,
    );
    if accepted_counter.is_none() {
        record_failed_attempt(guard_home, &mut state, ApprovalGateFactor::Totp, now);
        return Err(err(
            "approval_gate_totp_invalid",
            "That authenticator code is wrong. Open your authenticator app and enter the current six-digit code.",
            403,
        ));
    }
    reset_failed_attempts(&mut state);
    let pending_secret_id = optional_string(state.get("totp_pending_secret_id"));
    {
        let o = state.as_object_mut().unwrap();
        o.insert("totp_enabled".into(), Value::Bool(false));
        o.remove("totp_secret_id");
        o.remove("totp_last_counter");
        o.remove("totp_pending_secret_id");
        o.remove("totp_pending_expires_at");
    }
    let _ = store.delete_secret(&secret_id);
    if let Some(p) = pending_secret_id {
        let _ = store.delete_secret(&p);
    }
    rotate_authentication_state(&mut state);
    write_state(guard_home, &state, now).map_err(|_| {
        err(
            "approval_gate_state_io",
            "Could not persist approval gate state.",
            500,
        )
    })?;
    invalidate_active_grants(grants, guard_home);
    Ok(public_config_locked(guard_home, now))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn home(tag: &str) -> std::path::PathBuf {
        let h = std::env::temp_dir().join(format!(
            "gate-enr-{tag}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&h).unwrap();
        h
    }
    const NOW: &str = "2026-10-02T00:00:00+00:00";
    #[allow(dead_code)]
    const SECRET: &str = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";

    fn enabled_with_verifier(h: &Path) {
        let mut st = load_state(h);
        let o = st.as_object_mut().unwrap();
        o.insert("enabled".into(), json!(true));
        o.insert("fail_closed".into(), json!(false));
        o.insert(
            "verifier".into(),
            crate::approval_gate_settings::create_verifier("correct horse battery").unwrap(),
        );
        write_state(h, &st, Some(NOW)).unwrap();
    }

    #[test]
    fn begin_confirm_disable_cycle() {
        let h = home("cyc");
        enabled_with_verifier(&h);
        let grants = ApprovalGateGrants::new();
        // begin
        let out = begin_totp_enrollment_locked(
            &h,
            &grants,
            Some(&ApprovalGateInputV1 {
                password: Some("correct horse battery".into()),
                ..Default::default()
            }),
            "dev",
            Some(NOW),
        )
        .unwrap();
        assert_eq!(out["pending"], json!(true));
        assert!(out["manual_key"].as_str().unwrap().len() == 32);
        // confirm with the REAL pending secret's code (recompute at counter).
        let st = load_state(&h);
        let pending_id = optional_string(st.get("totp_pending_secret_id")).unwrap();
        let mut store = TotpSecretStore::new(&h);
        let pending_secret = store.get_secret(&pending_id).unwrap();
        let now_e = epoch(Some(NOW));
        let code = crate::totp::totp_code_at_counter(&pending_secret, (now_e as i64 / 30) as u64);
        let cfg = confirm_totp_enrollment_locked(
            &h,
            &grants,
            Some(&ApprovalGateInputV1 {
                password: Some("correct horse battery".into()),
                totp_code: Some(code),
                ..Default::default()
            }),
            Some(NOW),
        )
        .unwrap();
        assert!(cfg.totp_enabled && !cfg.totp_pending);
        // disable with a fresh code at the next counter.
        let code2 =
            crate::totp::totp_code_at_counter(&pending_secret, ((now_e as i64 / 30) + 1) as u64);
        let cfg = disable_totp_locked(
            &h,
            &grants,
            Some(&ApprovalGateInputV1 {
                totp_code: Some(code2),
                ..Default::default()
            }),
            Some("2026-10-02T00:00:40+00:00"),
        )
        .unwrap();
        assert!(!cfg.totp_enabled);
        let _ = std::fs::remove_dir_all(&h);
    }

    #[test]
    fn confirm_without_pending_fails() {
        let h = home("np");
        enabled_with_verifier(&h);
        let grants = ApprovalGateGrants::new();
        let err = confirm_totp_enrollment_locked(
            &h,
            &grants,
            Some(&ApprovalGateInputV1 {
                password: Some("correct horse battery".into()),
                totp_code: Some("123456".into()),
                ..Default::default()
            }),
            Some(NOW),
        )
        .unwrap_err();
        assert_eq!(err.code, "approval_gate_totp_pending_required");
        let _ = std::fs::remove_dir_all(&h);
    }
}

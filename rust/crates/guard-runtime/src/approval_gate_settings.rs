//! Port of the approval-gate configuration/settings arm from
//! `src/codex_plugin_scanner/guard/approval_gate.py`.
//!
//! Covers `create_verifier` (:807-817), `public_config` (:181-200), the
//! settings-write path (`_next_settings_state` :249-293 + `update_settings`
//! :211-230 + `validate_settings_update` :233-247), `revoke_cooldown`
//! (:296-302), `unlock_cooldown`/`_unlock_cooldown_locked` (:304-348), and
//! `_require_password_confirmation` (:1341-1347) + `recent_totp_satisfied`
//! (:202-209).
//!
//! The global `_APPROVAL_GATE_LOCK` is the caller's process lock; each fn here
//! is the locked body operating on `state`/`guard_home`/`grants` supplied by the
//! caller. `write_state`/`load_state`/`public_config` own the JSON round-trip.

#![forbid(unsafe_code)]

use std::path::Path;

use serde_json::Value;

use crate::approval_gate_grants::{ApprovalGateErrorV1, ApprovalGateGrantV1, ApprovalGateGrants};
use crate::approval_gate_state::{
    constant_time_eq, cooldown_active, enabled, epoch, is_future, iso_from_epoch, load_state,
    optional_bool, optional_int, optional_string, reset_failed_attempts, verifier, write_state,
    ApprovalGatePublicConfig,
};
use crate::approval_gate_verify::{
    input_from_mapping, invalidate_active_grants, raise_if_locked, recent_totp_satisfied_locked,
    rotate_authentication_state, verify_password_stage, ApprovalGateInputV1,
};
use crate::encrypted_secret_store::random_bytes;
use crate::totp::APPROVAL_GATE_HASH_ITERATIONS;

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

fn factor_generation(state: &Value) -> i64 {
    optional_int(state.get("factor_generation"))
        .unwrap_or(0)
        .max(0)
}

pub(crate) fn invalid_cooldown() -> ApprovalGateErrorV1 {
    err(
        "approval_gate_invalid_cooldown",
        "Approval cooldown must be 0 (every approval), 900 (15 minutes), or 3600 (1 hour) seconds.",
        403,
    )
}

fn cooldown_seconds_of(state: &Value) -> i64 {
    crate::approval_gate_state::coerce_cooldown_seconds(state.get("cooldown_seconds")).unwrap_or(0)
}

/// `_has_pending_totp` (:1149-1152).
fn has_pending_totp(state: &Value, now_epoch: f64) -> bool {
    let pending_secret_id = optional_string(state.get("totp_pending_secret_id"));
    let pending_expires_at = optional_string(state.get("totp_pending_expires_at"));
    pending_secret_id.is_some() && is_future(pending_expires_at.as_deref(), now_epoch)
}

/// `create_verifier` (:807-817) — PBKDF2-HMAC-SHA256 with a random 16-byte salt.
pub(crate) fn create_verifier(password: &str) -> Result<Value, ApprovalGateErrorV1> {
    if password.chars().count() < crate::totp::APPROVAL_GATE_MIN_PASSWORD_LENGTH {
        return Err(err(
            "approval_gate_weak_password",
            "Approval gate password is too weak.",
            403,
        ));
    }
    let salt = random_bytes(16);
    let mut digest = vec![0u8; 32];
    pbkdf2::pbkdf2_hmac::<sha2::Sha256>(
        password.as_bytes(),
        &salt,
        APPROVAL_GATE_HASH_ITERATIONS,
        &mut digest,
    );
    Ok(serde_json::json!({
        "algorithm": "pbkdf2_sha256",
        "iterations": APPROVAL_GATE_HASH_ITERATIONS,
        "salt": b64_std_encode(&salt),
        "hash": b64_std_encode(&digest),
    }))
}

fn b64_std_encode(b: &[u8]) -> String {
    use base64ct::{Base64, Encoding};
    let mut buf = vec![0u8; b.len().div_ceil(3) * 4];
    Base64::encode(b, &mut buf).expect("b64 encode").to_owned()
}

/// `_require_password_confirmation` (:1341-1347) — constant-time match.
fn require_password_confirmation(
    password: &str,
    confirmation: Option<&str>,
) -> Result<(), ApprovalGateErrorV1> {
    match confirmation {
        Some(c) if constant_time_eq(password.as_bytes(), c.as_bytes()) => Ok(()),
        _ => Err(err(
            "approval_gate_password_mismatch",
            "Approval gate password confirmation does not match.",
            403,
        )),
    }
}

/// `public_config` (:181-200) — the `ApprovalGatePublicConfig` snapshot.
pub(crate) fn public_config_locked(
    guard_home: &Path,
    now: Option<&str>,
) -> ApprovalGatePublicConfig {
    let state = load_state(guard_home);
    let now_epoch = epoch(now);
    let configured = verifier(&state).is_some();
    let cooldown_expires_at = optional_string(state.get("cooldown_expires_at"))
        .filter(|value| is_future(Some(value), now_epoch));
    let cd_active = cooldown_active(&state, now_epoch);
    let locked_until = optional_string(state.get("locked_until"))
        .filter(|value| is_future(Some(value), now_epoch));
    let totp_enabled_v = totp_enabled(&state);
    let totp_recent = totp_enabled_v && recent_totp_satisfied_locked(guard_home, &state, now_epoch);
    ApprovalGatePublicConfig {
        enabled: enabled(&state),
        configured,
        cooldown_seconds: cooldown_seconds_of(&state),
        cooldown_active: cd_active,
        cooldown_expires_at,
        locked_until,
        fail_closed: state.get("fail_closed") == Some(&Value::Bool(true)),
        strict_all_decisions: optional_bool(state.get("strict_all_decisions"), None)
            .unwrap_or(false),
        totp_enabled: totp_enabled_v,
        totp_pending: has_pending_totp(&state, now_epoch),
        totp_recent_satisfied: totp_recent,
    }
}

/// `recent_totp_satisfied` (:202-209) — public predicate.
pub(crate) fn recent_totp_satisfied(guard_home: &Path, now: Option<&str>) -> bool {
    let state = load_state(guard_home);
    let now_epoch = epoch(now);
    recent_totp_satisfied_locked(guard_home, &state, now_epoch)
}

/// `validate_grant` thin wrapper used by `_next_settings_state` when the gate
/// is already enabled (`strict=True`, purpose `settings_write`). The locked
/// body is `_validate_grant_locked` — delegated to the grant table.
#[allow(clippy::too_many_arguments)]
fn validate_grant_for_settings(
    guard_home: &Path,
    grants: &ApprovalGateGrants,
    approval_gate_grant: Option<&ApprovalGateGrantV1>,
    now: Option<&str>,
    state: &Value,
) -> Result<(), ApprovalGateErrorV1> {
    let now_epoch = epoch(now);
    let grant_home = guard_home.to_string_lossy();
    let expires_epoch = approval_gate_grant
        .map(|g| epoch(Some(g.expires_at.as_str())))
        .unwrap_or(0.0);
    grants.validate(
        &grant_home,
        approval_gate_grant,
        expires_epoch,
        Some("settings_write"),
        true,
        None,
        None,
        None,
        None,
        factor_generation(state),
        totp_enabled(state),
        crate::approval_gate_consumers::totp_state_valid(guard_home, state),
        now_epoch,
    )
}

/// `_next_settings_state` (:249-293) — compute the next state or `None` when
/// `payload` is not a dict. Does NOT write; caller persists + invalidates when
/// `factor_generation` advances.
pub(crate) fn next_settings_state(
    guard_home: &Path,
    grants: &ApprovalGateGrants,
    payload: Option<&Value>,
    approval_gate_grant: Option<&ApprovalGateGrantV1>,
    now: Option<&str>,
) -> Result<Option<Value>, ApprovalGateErrorV1> {
    if payload.and_then(|v| v.as_object()).is_none() {
        return Ok(None);
    }
    let payload = payload.unwrap();
    let state = load_state(guard_home);
    let gate_was_enabled = enabled(&state);
    // Python: input_from_mapping({"approval_gate": payload})
    let wrapped = serde_json::json!({ "approval_gate": payload });
    let gate_input = input_from_mapping(Some(&wrapped)).unwrap_or_default();
    let requested_enabled = optional_bool(
        payload.get("enabled"),
        state.get("enabled").and_then(|v| v.as_bool()),
    );
    let mut next_state = state.clone();
    if gate_input.revoke_cooldown {
        if let Some(o) = next_state.as_object_mut() {
            o.remove("cooldown_expires_at");
        }
    }
    if gate_was_enabled {
        validate_grant_for_settings(guard_home, grants, approval_gate_grant, now, &state)?;
    }
    let np = gate_input.new_password.as_deref();
    if requested_enabled == Some(true) && !gate_was_enabled {
        match np {
            None => {
                return Err(err(
                    "approval_gate_password_required",
                    "Approval gate password is required.",
                    403,
                ));
            }
            Some(p) => {
                require_password_confirmation(p, gate_input.confirm_password.as_deref())?;
                next_state
                    .as_object_mut()
                    .unwrap()
                    .insert("verifier".into(), create_verifier(p)?);
                rotate_authentication_state(&mut next_state);
            }
        }
    } else if gate_was_enabled && np.is_some() {
        let p = np.unwrap();
        require_password_confirmation(p, gate_input.confirm_password.as_deref())?;
        next_state
            .as_object_mut()
            .unwrap()
            .insert("verifier".into(), create_verifier(p)?);
        rotate_authentication_state(&mut next_state);
    }
    // Apply the enabled/cooldown/fail_closed fields last.
    if requested_enabled.is_some_and(|en| en != gate_was_enabled) && np.is_none() {
        rotate_authentication_state(&mut next_state);
    }
    if let Some(en) = requested_enabled {
        next_state
            .as_object_mut()
            .unwrap()
            .insert("enabled".into(), Value::Bool(en));
    }
    if let Some(cs) = payload.get("cooldown_seconds") {
        let secs = crate::approval_gate_state::coerce_cooldown_seconds(Some(cs))
            .map_err(|_| invalid_cooldown())?;
        next_state
            .as_object_mut()
            .unwrap()
            .insert("cooldown_seconds".into(), Value::Number(secs.into()));
    }
    if let Some(sad) = payload.get("strict_all_decisions") {
        next_state.as_object_mut().unwrap().insert(
            "strict_all_decisions".into(),
            Value::Bool(sad.as_bool() == Some(true)),
        );
    }
    Ok(Some(next_state))
}

/// `update_settings` (:211-230) — write next state, invalidate grants when
/// `factor_generation` advanced, return public config.
pub(crate) fn update_settings(
    guard_home: &Path,
    grants: &ApprovalGateGrants,
    payload: Option<&Value>,
    approval_gate_grant: Option<&ApprovalGateGrantV1>,
    now: Option<&str>,
) -> Result<ApprovalGatePublicConfig, ApprovalGateErrorV1> {
    let previous_generation = factor_generation(&load_state(guard_home));
    let next_state = next_settings_state(guard_home, grants, payload, approval_gate_grant, now)?;
    if let Some(ns) = next_state {
        write_state(guard_home, &ns, now).map_err(|_| {
            err(
                "approval_gate_state_io",
                "Could not persist approval gate state.",
                500,
            )
        })?;
        if factor_generation(&ns) != previous_generation {
            invalidate_active_grants(grants, guard_home);
        }
    }
    Ok(public_config_locked(guard_home, now))
}

/// `validate_settings_update` (:233-247) — dry-run; validates payload without
/// writing.
pub(crate) fn validate_settings_update(
    guard_home: &Path,
    grants: &ApprovalGateGrants,
    payload: Option<&Value>,
    approval_gate_grant: Option<&ApprovalGateGrantV1>,
    now: Option<&str>,
) -> Result<(), ApprovalGateErrorV1> {
    next_settings_state(guard_home, grants, payload, approval_gate_grant, now).map(|_| ())
}

/// `revoke_cooldown` (:296-302) — drop `cooldown_expires_at`, persist, config.
pub(crate) fn revoke_cooldown(
    guard_home: &Path,
    now: Option<&str>,
) -> Result<ApprovalGatePublicConfig, ApprovalGateErrorV1> {
    let mut state = load_state(guard_home);
    if let Some(o) = state.as_object_mut() {
        o.remove("cooldown_expires_at");
    }
    write_state(guard_home, &state, now).map_err(|_| {
        err(
            "approval_gate_state_io",
            "Could not persist approval gate state.",
            500,
        )
    })?;
    Ok(public_config_locked(guard_home, now))
}

/// `_unlock_cooldown_locked` (:320-348) — set a `duration_seconds` cooldown
/// after a password re-verify.
pub(crate) fn unlock_cooldown_locked(
    guard_home: &Path,
    duration_seconds: i64,
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
    if verifier(&state).is_none() {
        return Err(err(
            "approval_gate_recovery_required",
            "Approval gate is enabled but no verifier is configured.",
            423,
        ));
    }
    if totp_enabled(&state) {
        return Err(err(
            "approval_gate_totp_required",
            "Cooldown unlock is unavailable while TOTP is enabled.",
            403,
        ));
    }
    let seconds =
        crate::approval_gate_state::coerce_cooldown_seconds(Some(&Value::from(duration_seconds)))
            .map_err(|_| invalid_cooldown())?;
    if seconds == 0 {
        return Err(err(
            "approval_gate_invalid_cooldown",
            "Cooldown unlock requires 900 or 3600 seconds.",
            403,
        ));
    }
    let now_epoch = epoch(now);
    raise_if_locked(&state, now_epoch)?;
    let gate_input = approval_gate_input.cloned().unwrap_or_default();
    verify_password_stage(guard_home, &mut state, gate_input.password.as_deref(), now)?;
    reset_failed_attempts(&mut state);
    let expires = iso_from_epoch(now_epoch + seconds as f64);
    state
        .as_object_mut()
        .unwrap()
        .insert("cooldown_expires_at".into(), Value::String(expires));
    write_state(guard_home, &state, now).map_err(|_| {
        err(
            "approval_gate_state_io",
            "Could not persist approval gate state.",
            500,
        )
    })?;
    Ok(public_config_locked(guard_home, now))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::approval_gate_state::default_state;
    use serde_json::json;

    fn home(tag: &str) -> std::path::PathBuf {
        let h = std::env::temp_dir().join(format!(
            "gate-set-{tag}-{}-{}",
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

    #[test]
    fn create_verifier_rejects_short_and_roundtrips() {
        assert!(create_verifier("short").is_err());
        let v = create_verifier("correct horse battery").unwrap();
        assert_eq!(v["algorithm"], json!("pbkdf2_sha256"));
        assert_eq!(v["iterations"], json!(310000));
        assert!(crate::approval_gate_state::verify_password(
            "correct horse battery",
            v.as_object()
        ));
    }

    #[test]
    fn enable_requires_password_and_confirm() {
        let h = home("en");
        let grants = ApprovalGateGrants::new();
        // No password -> required error.
        let err = update_settings(
            &h,
            &grants,
            Some(&json!({"enabled": true})),
            None,
            Some(NOW),
        )
        .unwrap_err();
        assert_eq!(err.code, "approval_gate_password_required");
        // Mismatched confirm -> mismatch.
        let err = update_settings(
            &h, &grants,
            Some(&json!({"enabled": true, "new_password": "correct horse battery", "confirm_password": "nope"})),
            None, Some(NOW),
        ).unwrap_err();
        assert_eq!(err.code, "approval_gate_password_mismatch");
        // Valid enable.
        let cfg = update_settings(
            &h, &grants,
            Some(&json!({"enabled": true, "new_password": "correct horse battery", "confirm_password": "correct horse battery"})),
            None, Some(NOW),
        ).unwrap();
        assert!(cfg.enabled && cfg.configured);
        let _ = std::fs::remove_dir_all(&h);
    }

    #[test]
    fn public_config_reflects_state() {
        let h = home("pc");
        let mut st = default_state();
        st.as_object_mut()
            .unwrap()
            .insert("enabled".into(), json!(true));
        write_state(&h, &st, Some(NOW)).unwrap();
        let cfg = public_config_locked(&h, Some(NOW));
        assert!(cfg.enabled);
        assert!(!cfg.configured);
        assert!(!cfg.totp_enabled && !cfg.totp_pending);
        let _ = std::fs::remove_dir_all(&h);
    }

    #[test]
    fn unlock_cooldown_sets_expiry_after_password() {
        let h = home("ul");
        let grants = ApprovalGateGrants::new();
        // Enable first.
        update_settings(
            &h, &grants,
            Some(&json!({"enabled": true, "new_password": "correct horse battery", "confirm_password": "correct horse battery"})),
            None, Some(NOW),
        ).unwrap();
        let cfg = unlock_cooldown_locked(
            &h,
            900,
            Some(&crate::approval_gate_verify::ApprovalGateInputV1 {
                password: Some("correct horse battery".into()),
                ..Default::default()
            }),
            Some(NOW),
        )
        .unwrap();
        assert!(cfg.cooldown_expires_at.is_some());
        assert!(cfg.cooldown_active);
        let _ = std::fs::remove_dir_all(&h);
    }

    #[test]
    fn revoke_cooldown_clears_expiry() {
        let h = home("rc");
        let mut st = default_state();
        st.as_object_mut()
            .unwrap()
            .insert("enabled".into(), json!(true));
        st.as_object_mut().unwrap().insert(
            "cooldown_expires_at".into(),
            json!("2030-01-01T00:00:00+00:00"),
        );
        write_state(&h, &st, Some(NOW)).unwrap();
        let cfg = revoke_cooldown(&h, Some(NOW)).unwrap();
        assert!(cfg.cooldown_expires_at.is_none());
        let re = load_state(&h);
        assert!(re.get("cooldown_expires_at").is_none());
        let _ = std::fs::remove_dir_all(&h);
    }

    #[test]
    fn non_dict_payload_returns_none() {
        let h = home("nd");
        let grants = ApprovalGateGrants::new();
        let out = next_settings_state(&h, &grants, Some(&json!([1, 2])), None, Some(NOW)).unwrap();
        assert!(out.is_none());
        let _ = std::fs::remove_dir_all(&h);
    }
}

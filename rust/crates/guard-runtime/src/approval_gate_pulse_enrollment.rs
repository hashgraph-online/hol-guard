//! Pulse enrollment, disable and recovery.
//!
//! - `begin_pulse_enrollment` needs the current factor (the approval password,
//!   plus the authenticator code when TOTP is on). The dashboard checks it
//!   first, on its own (`authorize_only`): that lets the same session start
//!   setup without the factor for 15 minutes, so the user can paste the agent
//!   key and try again after a refused scan. It asks Pulse which YID the
//!   pasted agent key belongs to and sends an enrollment request to the YID app.
//! - `confirm_pulse_enrollment` verifies that enrollment receipt, from the
//!   same OS session, at the fixed medium floor. Only then does it pin the YID,
//!   issuer and agent key, store the secrets, pause TOTP and rotate the
//!   factor generation, so every older grant and cooldown ends.
//! - `disable_pulse` needs a fresh Pulse grant for `settings_write`.
//! - `recover_pulse` is for a user who lost access to the YID app. It needs
//!   the approval password and the one-time recovery code shown at
//!   enrollment. Neither is ever readable by an agent: the password is a
//!   PBKDF2 verifier and the code is stored only as a SHA-256 hash.

#![forbid(unsafe_code)]

use std::collections::HashMap;
use std::path::Path;
use std::sync::{Mutex, OnceLock};

use guard_yanez_pulse::client::valid_agent_key;
use guard_yanez_pulse::receipt::{ReceiptPolicy, DEFAULT_MAX_AGE_SECONDS, YANEZ_ISSUER};
use guard_yanez_pulse::terms::{
    binding_digest, build_terms, consumer_token, match_code, ActionBinding,
};
use guard_yanez_pulse::PulseError;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::approval_gate_grants::{ApprovalGateErrorV1, ApprovalGateGrantV1, ApprovalGateGrants};
use crate::approval_gate_pulse::{
    clear_pulse_state, err, factor_generation, insert_pending, ledger_reserve, pulse_enabled,
    pulse_error, take_pending, verify_with_cached_keys, with_transport, PendingKind, PendingPulse,
    PULSE_ALLOWED_COOLDOWNS, PULSE_MIN_TIER, TOTP_PAUSED_BY_PULSE,
};
use crate::approval_gate_settings::public_config_locked;
use crate::approval_gate_state::{
    constant_time_eq, enabled, epoch, iso_from_epoch, load_state, optional_string,
    record_failed_attempt, reset_failed_attempts, write_state, ApprovalGateFactor,
};
use crate::approval_gate_verify::{
    current_totp_session_binding, invalidate_active_grants, raise_if_locked,
    rotate_authentication_state, token_urlsafe, verify_password_stage, ApprovalGateInputV1,
};
use crate::encrypted_secret_store::random_bytes;
use crate::totp::{verify_totp_code, TotpSecretStore, APPROVAL_GATE_TOTP_SKEW_STEPS};

const ENROLLMENT_PURPOSE: &str = "pulse_enrollment";
/// How long a confirmed password lets the same session start Pulse setup.
const SETUP_AUTHORIZATION_SECONDS: i64 = 900;

/// A confirmed current factor, held in memory only. It lets the session that
/// confirmed it start Pulse setup until it expires, Pulse is enrolled, or the
/// password or authenticator changes.
struct SetupAuthorization {
    session_binding: String,
    factor_generation: i64,
    expires_at: i64,
}

fn setup_authorizations() -> &'static Mutex<HashMap<String, SetupAuthorization>> {
    static AUTHORIZATIONS: OnceLock<Mutex<HashMap<String, SetupAuthorization>>> = OnceLock::new();
    AUTHORIZATIONS.get_or_init(|| Mutex::new(HashMap::new()))
}

fn authorize_setup(guard_home: &Path, state: &Value, now_epoch: i64) -> i64 {
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

fn setup_authorized(guard_home: &Path, state: &Value, now_epoch: i64) -> bool {
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

fn end_setup_authorization(guard_home: &Path) {
    if let Ok(mut table) = setup_authorizations().lock() {
        table.remove(guard_home.to_string_lossy().as_ref());
    }
}

fn state_io() -> ApprovalGateErrorV1 {
    err(
        "approval_gate_state_io",
        "Could not persist approval gate state.",
        500,
    )
}

fn totp_enabled(state: &Value) -> bool {
    state.get("totp_enabled") == Some(&Value::Bool(true))
}

/// Mask a YID for display: enough to recognise, not enough to reuse.
pub(crate) fn yid_hint(yid: &str) -> String {
    let chars: Vec<char> = yid.chars().collect();
    if chars.len() <= 8 {
        let tail: String = chars[chars.len().saturating_sub(2)..].iter().collect();
        return format!("…{tail}");
    }
    let head: String = chars[..4].iter().collect();
    let tail: String = chars[chars.len() - 4..].iter().collect();
    format!("{head}…{tail}")
}

/// Check the factor the gate uses today: the password, and the
/// authenticator code too when TOTP is on.
fn verify_current_factor(
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

fn enrollment_binding<'a>(
    yid: &'a str,
    session_binding: &'a str,
    nonce: &'a str,
    generation: i64,
) -> ActionBinding<'a> {
    ActionBinding {
        purpose: ENROLLMENT_PURPOSE,
        action: ENROLLMENT_PURPOSE,
        scope: ENROLLMENT_PURPOSE,
        subject: yid,
        session_nonce: "",
        session_binding,
        request_nonce: nonce,
        factor_generation: generation,
    }
}

/// `begin_pulse_enrollment`. With `authorize_only`, only checks the current
/// factor and authorizes this session to start setup for 15 minutes.
pub(crate) fn begin_pulse_enrollment(
    guard_home: &Path,
    input: Option<&ApprovalGateInputV1>,
    authorize_only: bool,
    now: Option<&str>,
) -> Result<Value, ApprovalGateErrorV1> {
    let mut state = load_state(guard_home);
    if !enabled(&state) {
        return Err(err(
            "approval_gate_required",
            "Turn on the approval gate with a password before adding Pulse.",
            403,
        ));
    }
    if pulse_enabled(&state) {
        return Err(err(
            "approval_gate_pulse_enabled",
            "Pulse is already the approval factor. Disable it first, with a Pulse approval.",
            409,
        ));
    }
    let now_epoch = epoch(now);
    raise_if_locked(&state, now_epoch)?;
    let input = input.cloned().unwrap_or_default();
    if authorize_only || input.password.is_some() {
        verify_current_factor(guard_home, &mut state, &input, now, now_epoch)?;
        reset_failed_attempts(&mut state);
        write_state(guard_home, &state, now).map_err(|_| state_io())?;
        if authorize_only {
            let expires_at = authorize_setup(guard_home, &state, now_epoch as i64);
            return Ok(json!({
                "status": "authorized",
                "expires_at": iso_from_epoch(expires_at as f64),
            }));
        }
    } else if !setup_authorized(guard_home, &state, now_epoch as i64) {
        return Err(err(
            "approval_gate_pulse_setup_expired",
            "Confirm your approval password again to continue Pulse setup.",
            403,
        ));
    }
    let agent_key = input
        .pulse_agent_key
        .as_deref()
        .map(str::trim)
        .filter(|k| valid_agent_key(k))
        .map(|k| Zeroizing::new(k.to_owned()))
        .ok_or_else(|| pulse_error(&PulseError::InvalidRequest("agent_key")))?;
    let binding_key = Zeroizing::new(random_bytes(32));
    let session_binding = current_totp_session_binding();
    let nonce = token_urlsafe(18);
    let generation = factor_generation(&state);
    let consent_not_after =
        now_epoch as i64 + guard_yanez_pulse::client::DECISION_WINDOW_SECONDS + 60;
    let (registry, terms, digest, created) = with_transport(&agent_key, |t| {
        let registry = t.user_keys()?;
        let binding = enrollment_binding(&registry.yid, &session_binding, &nonce, generation);
        let terms = build_terms(&binding_key, &binding)?;
        let digest = binding_digest(&binding_key, &binding)?;
        if registry.signable_floors().is_empty() {
            return Ok(None);
        }
        let created = t.create_authorization(
            &terms,
            &iso_from_epoch(consent_not_after as f64),
            &token_urlsafe(18),
        )?;
        Ok(Some((registry, terms, digest, created)))
    })
    .map_err(|e| pulse_error(&e))?
    .ok_or_else(|| {
        err(
            "approval_gate_pulse_no_signing_key",
            "Your Yanez identity has no device that can approve at medium or high assurance. Register a device in the YID app, then start again.",
            409,
        )
    })?;
    let code = match_code(&digest);
    insert_pending(
        guard_home,
        &created.request_id,
        PendingPulse {
            kind: PendingKind::Enrollment {
                agent_key,
                binding_key,
                yid: registry.yid.clone(),
            },
            binding: digest,
            request_nonce: nonce,
            terms,
            session_binding,
            factor_generation: generation,
            consent_not_after,
            artifact: None,
        },
        now_epoch as i64,
    );
    Ok(json!({
        "status": "pending",
        "request_id": created.request_id,
        "match_code": code,
        "yid_hint": yid_hint(&registry.yid),
        "decide_by": iso_from_epoch(consent_not_after as f64),
    }))
}

/// `confirm_pulse_enrollment`.
pub(crate) fn confirm_pulse_enrollment(
    guard_home: &Path,
    grants: &ApprovalGateGrants,
    request_id: &str,
    cooldown_seconds: i64,
    now: Option<&str>,
) -> Result<Value, ApprovalGateErrorV1> {
    let mut state = load_state(guard_home);
    if pulse_enabled(&state) {
        return Err(err(
            "approval_gate_pulse_enabled",
            "Pulse is already the approval factor.",
            409,
        ));
    }
    if !PULSE_ALLOWED_COOLDOWNS.contains(&cooldown_seconds) {
        return Err(crate::approval_gate_settings::invalid_cooldown());
    }
    let now_epoch = epoch(now);
    raise_if_locked(&state, now_epoch)?;
    let entry = take_pending(guard_home, request_id).ok_or_else(|| {
        err(
            "approval_gate_pulse_pending_required",
            "No Pulse enrollment is waiting. Start Pulse setup again.",
            403,
        )
    })?;
    let PendingKind::Enrollment {
        agent_key,
        binding_key,
        yid,
    } = &entry.kind
    else {
        return Err(pulse_error(&PulseError::WrongRequest));
    };
    let artifact = entry.artifact.clone().ok_or_else(|| {
        err(
            "approval_gate_pulse_pending",
            "Approve the enrollment in the YID app first.",
            409,
        )
    })?;
    // The enrollment must be confirmed from the session that started it, in
    // the same factor generation.
    if !constant_time_eq(
        entry.session_binding.as_bytes(),
        current_totp_session_binding().as_bytes(),
    ) || entry.factor_generation != factor_generation(&state)
    {
        return Err(pulse_error(&PulseError::TermsMismatch));
    }
    let now_i = now_epoch as i64;
    let (receipt, pinned_user_keys) = with_transport(agent_key, |t| {
        let registry = t.user_keys()?;
        let policy = ReceiptPolicy {
            expected_issuer: YANEZ_ISSUER,
            expected_yid: yid,
            expected_agent_key_id: None,
            expected_request_id: request_id,
            expected_terms: &entry.terms,
            expected_consent_not_after: entry.consent_not_after,
            min_tier: PULSE_MIN_TIER,
            max_age_seconds: DEFAULT_MAX_AGE_SECONDS,
            registry: &registry,
            pinned_user_keys: None,
            now_epoch: now_i,
        };
        let receipt = verify_with_cached_keys(t, &artifact, &policy)?;
        t.consume(&artifact, &consumer_token(binding_key, &receipt.jti)?)?;
        // The devices registered now are the ones the user enrolled. A key
        // Yanez lists later needs the user's confirmation in Guard.
        let pinned: Vec<String> = registry
            .keys
            .iter()
            .filter(|k| k.tier.is_some())
            .map(|k| k.public_key_hex.clone())
            .collect();
        Ok((receipt, pinned))
    })
    .map_err(|e| pulse_error(&e))?;

    let mut store = TotpSecretStore::new(guard_home);
    store.ensure_ready().map_err(|_| state_io())?;
    let agent_secret_id = format!("pulse-agent-{}", token_urlsafe(12));
    let binding_secret_id = format!("pulse-binding-{}", token_urlsafe(12));
    store
        .set_secret(&agent_secret_id, agent_key)
        .map_err(|_| state_io())?;
    store
        .set_secret(&binding_secret_id, &hex::encode(binding_key.as_slice()))
        .map_err(|_| state_io())?;
    let recovery_code = Zeroizing::new(format!(
        "{}-{}-{}-{}",
        token_urlsafe(6),
        token_urlsafe(6),
        token_urlsafe(6),
        token_urlsafe(6)
    ));
    // Pulse takes over from the authenticator without deleting it: the secret
    // and its replay counter stay stored, paused, and the authenticator comes
    // back when Pulse is turned off. An unfinished authenticator setup is dropped.
    let pause_totp = totp_enabled(&state) && optional_string(state.get("totp_secret_id")).is_some();
    if let Some(id) = optional_string(state.get("totp_pending_secret_id")) {
        let _ = store.delete_secret(&id);
    }
    clear_pulse_state(guard_home, &mut state);
    if let Some(o) = state.as_object_mut() {
        o.remove("totp_pending_secret_id");
        o.remove("totp_pending_expires_at");
        o.insert("totp_enabled".into(), json!(false));
        if pause_totp {
            o.insert(TOTP_PAUSED_BY_PULSE.into(), json!(true));
        }
        o.insert("pulse_enabled".into(), json!(true));
        o.insert("pulse_yid".into(), json!(receipt.yid));
        o.insert("pulse_issuer".into(), json!(receipt.issuer));
        o.insert("pulse_agent_key_id".into(), json!(receipt.agent_key_id));
        o.insert("pulse_user_keys".into(), json!(pinned_user_keys));
        o.insert("pulse_cooldown_seconds".into(), json!(cooldown_seconds));
        o.insert("pulse_agent_secret_id".into(), json!(agent_secret_id));
        o.insert("pulse_binding_secret_id".into(), json!(binding_secret_id));
        o.insert(
            "pulse_recovery_hash".into(),
            json!(hex::encode(Sha256::digest(recovery_code.as_bytes()))),
        );
    }
    ledger_reserve(&mut state, &receipt, now_i);
    reset_failed_attempts(&mut state);
    rotate_authentication_state(&mut state);
    write_state(guard_home, &state, now).map_err(|_| state_io())?;
    invalidate_active_grants(grants, guard_home);
    end_setup_authorization(guard_home);
    let mut out = public_config_locked(guard_home, now).to_dict();
    if let Some(o) = out.as_object_mut() {
        o.insert("yid_hint".into(), json!(yid_hint(&receipt.yid)));
        // Shown once. Guard keeps only its hash.
        o.insert("recovery_code".into(), json!(recovery_code.as_str()));
    }
    Ok(out)
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

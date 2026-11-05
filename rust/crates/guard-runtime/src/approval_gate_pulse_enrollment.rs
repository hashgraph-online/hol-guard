//! Pulse enrollment.
//!
//! - `begin_pulse_enrollment` needs the current factor, or a setup
//!   authorization from `approval_gate_pulse_setup`. It asks Pulse which YID
//!   the pasted agent key belongs to and sends an enrollment request to the
//!   YID app.
//! - `confirm_pulse_enrollment` verifies that enrollment receipt, from the
//!   same OS session, at the fixed medium floor. Only then does it pin the YID,
//!   issuer and agent key, store the secrets, pause TOTP and rotate the
//!   factor generation, so every older grant and cooldown ends.
//!
//! Turning Pulse off is in `approval_gate_pulse_disable`.

#![forbid(unsafe_code)]

use std::path::Path;

use guard_yanez_pulse::client::valid_agent_key;
use guard_yanez_pulse::receipt::{ReceiptPolicy, DEFAULT_MAX_AGE_SECONDS, YANEZ_ISSUER};
use guard_yanez_pulse::terms::{
    binding_digest, build_terms, consumer_token, match_code, ActionBinding,
};
use guard_yanez_pulse::PulseError;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::approval_gate_grants::{ApprovalGateErrorV1, ApprovalGateGrants};
use crate::approval_gate_pulse::{
    clear_pulse_state, err, factor_generation, insert_pending, ledger_reserve, pending_has_room,
    pulse_busy, pulse_enabled, pulse_error, restore_pending, take_pending, verify_with_cached_keys,
    with_transport, PendingKind, PendingPulse, PULSE_ALLOWED_COOLDOWNS, PULSE_MIN_TIER,
    TOTP_PAUSED_BY_PULSE,
};
use crate::approval_gate_pulse_setup::{
    authorize_setup, end_setup_authorization, setup_authorized, totp_enabled, verify_current_factor,
};
use crate::approval_gate_settings::public_config_locked;
use crate::approval_gate_state::{
    constant_time_eq, enabled, epoch, iso_from_epoch, load_state, optional_string,
    reset_failed_attempts, write_state,
};
use crate::approval_gate_verify::{
    current_totp_session_binding, invalidate_active_grants, raise_if_locked,
    rotate_authentication_state, token_urlsafe, ApprovalGateInputV1,
};
use crate::encrypted_secret_store::random_bytes;
use crate::totp::TotpSecretStore;

const ENROLLMENT_PURPOSE: &str = "pulse_enrollment";

pub(crate) fn state_io() -> ApprovalGateErrorV1 {
    err(
        "approval_gate_state_io",
        "Could not persist approval gate state.",
        500,
    )
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
    if !pending_has_room(guard_home, now_epoch as i64) {
        return Err(pulse_busy());
    }
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
    let inserted = insert_pending(
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
    if !inserted {
        return Err(pulse_busy());
    }
    Ok(json!({
        "status": "pending",
        "request_id": created.request_id,
        "match_code": code,
        "yid_hint": yid_hint(&registry.yid),
        "decide_by": iso_from_epoch(consent_not_after as f64),
    }))
}

/// `confirm_pulse_enrollment`.
///
/// The order matters. The pending entry goes back into the table on every
/// refusal that is not final (not approved yet, another session asking), so
/// an early or stray confirm never cancels setup. The secrets are stored
/// before the receipt is spent at Pulse, and removed again if spending it
/// fails, so a local write failure never wastes the user's approval. After
/// the network calls, the result is committed against the state saved now,
/// not the copy loaded before them.
pub(crate) fn confirm_pulse_enrollment(
    guard_home: &Path,
    grants: &ApprovalGateGrants,
    request_id: &str,
    cooldown_seconds: i64,
    now: Option<&str>,
) -> Result<Value, ApprovalGateErrorV1> {
    let state = load_state(guard_home);
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
    if !matches!(entry.kind, PendingKind::Enrollment { .. }) {
        restore_pending(guard_home, request_id, entry);
        return Err(pulse_error(&PulseError::WrongRequest));
    }
    // Only the session that started setup may finish it. Another session's
    // confirm is refused without touching that setup.
    if !constant_time_eq(
        entry.session_binding.as_bytes(),
        current_totp_session_binding().as_bytes(),
    ) {
        restore_pending(guard_home, request_id, entry);
        return Err(pulse_error(&PulseError::TermsMismatch));
    }
    // A factor change since setup started is final: this setup can never
    // be confirmed, so it is dropped.
    if entry.factor_generation != factor_generation(&state) {
        return Err(pulse_error(&PulseError::TermsMismatch));
    }
    let Some(artifact) = entry.artifact.clone() else {
        restore_pending(guard_home, request_id, entry);
        return Err(err(
            "approval_gate_pulse_pending",
            "Approve the enrollment in the YID app first.",
            409,
        ));
    };
    let PendingKind::Enrollment {
        agent_key,
        binding_key,
        yid,
    } = &entry.kind
    else {
        unreachable!("checked above");
    };
    let now_i = now_epoch as i64;
    let verified = with_transport(agent_key, |t| {
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
        // The devices registered now are the ones the user enrolled. A key
        // Yanez lists later needs the user's confirmation in Guard.
        let pinned: Vec<String> = registry
            .keys
            .iter()
            .filter(|k| k.tier.is_some())
            .map(|k| k.public_key_hex.clone())
            .collect();
        Ok((receipt, pinned))
    });
    let (receipt, pinned_user_keys) = match verified {
        Ok(verified) => verified,
        Err(PulseError::Unavailable) => {
            // Nothing is spent yet: keep the setup so the user can confirm
            // again once Pulse answers, without a new scan.
            restore_pending(guard_home, request_id, entry);
            return Err(pulse_error(&PulseError::Unavailable));
        }
        Err(e) => return Err(pulse_error(&e)),
    };

    // The verify above can take seconds. Settings saved meanwhile (a new
    // password, the gate turned off, Pulse set up from another window) win.
    let mut state = load_state(guard_home);
    if pulse_enabled(&state)
        || !enabled(&state)
        || factor_generation(&state) != entry.factor_generation
    {
        return Err(pulse_error(&PulseError::TermsMismatch));
    }

    let mut store = TotpSecretStore::new(guard_home);
    let agent_secret_id = format!("pulse-agent-{}", token_urlsafe(12));
    let binding_secret_id = format!("pulse-binding-{}", token_urlsafe(12));
    let stored = store.ensure_ready().is_ok()
        && store.set_secret(&agent_secret_id, agent_key).is_ok()
        && store
            .set_secret(&binding_secret_id, &hex::encode(binding_key.as_slice()))
            .is_ok();
    let forget_secrets = |store: &mut TotpSecretStore| {
        let _ = store.delete_secret(&agent_secret_id);
        let _ = store.delete_secret(&binding_secret_id);
    };
    if !stored {
        // Nothing is spent yet: keep the setup so the user can confirm again.
        forget_secrets(&mut store);
        restore_pending(guard_home, request_id, entry);
        return Err(state_io());
    }
    if let Err(e) = with_transport(agent_key, |t| {
        t.consume(&artifact, &consumer_token(binding_key, &receipt.jti)?)
    }) {
        forget_secrets(&mut store);
        // Not spent, so the user can confirm again once Pulse answers.
        restore_pending(guard_home, request_id, entry);
        return Err(pulse_error(&e));
    }

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
    // An enrollment receipt is single-use like any other. A full ledger
    // does not block setup: this receipt is already spent at Pulse.
    let _ = ledger_reserve(&mut state, &receipt, now_i);
    reset_failed_attempts(&mut state);
    rotate_authentication_state(&mut state);
    if write_state(guard_home, &state, now).is_err() {
        forget_secrets(&mut store);
        return Err(state_io());
    }
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

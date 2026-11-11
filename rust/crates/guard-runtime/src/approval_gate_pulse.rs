//! Yanez Pulse as the approval-gate factor.
//!
//! When `pulse_enabled` is set, Pulse replaces the password and TOTP the same
//! way TOTP replaces the password: `verify_or_raise_locked` accepts only a
//! verified, consumed Pulse receipt (or an open, matching Pulse cooldown).
//!
//! The flow is split so no network wait happens inside the approval-gate
//! critical section:
//!
//! 1. `pulse_request` builds terms bound to the held action and creates the
//!    Pulse authorization. It keeps the terms and binding in the resident's
//!    pending table.
//! 2. `pulse_poll` does one short long-poll. The pending-table lock is held
//!    only to read and update the entry, never across the HTTP call. An
//!    approved receipt stays in the resident; it is never returned.
//! 3. `verify` (`verify_pulse_stage`) takes the entry out of the table,
//!    rebuilds the binding from the verify call, verifies the receipt,
//!    records the `jti` in the local ledger, consumes it at Pulse, and only
//!    then lets the caller register a grant.
//!
//! Rejection, expiry, a failed check and an unreachable Pulse all leave the
//! action blocked. There is no password or TOTP fallback.

#![forbid(unsafe_code)]

use std::path::Path;

use guard_yanez_pulse::client::{PollOutcome, DECISION_WINDOW_SECONDS};
use guard_yanez_pulse::receipt::{ReceiptPolicy, DEFAULT_MAX_AGE_SECONDS, YANEZ_ISSUER};
use guard_yanez_pulse::terms::{
    binding_digest, build_terms_with_summary, consumer_token, match_code, ActionBinding,
};
use guard_yanez_pulse::{AssuranceTier, PulseError};
use serde_json::{json, Value};
use zeroize::Zeroizing;

use crate::approval_gate_grants::ApprovalGateErrorV1;
use crate::approval_gate_pulse_command as pulse_command;
pub(crate) use crate::approval_gate_pulse_store::{
    insert_pending, ledger_error, ledger_reserve, pending_has_room, pulse_busy,
    pulse_cooldown_covers, restore_pending, same_pulse_factor, take_pending,
    verify_with_cached_keys, with_transport, PendingKind, PendingPulse,
};
use crate::approval_gate_pulse_store::{
    pending, pending_key, record_pulse_cooldown, PULSE_COOLDOWN_STATE_KEY,
};
#[cfg(test)]
pub(crate) use crate::approval_gate_pulse_store::{
    pending_len, TEST_AFTER_TRANSPORT, TEST_MAX_PENDING_PER_HOME, TEST_PULSE_LEDGER_MAX,
    TEST_TRANSPORT,
};
use crate::approval_gate_state::{
    constant_time_eq, epoch, iso_from_epoch, load_state, optional_int, optional_string, write_state,
};
use crate::approval_gate_verify::{
    current_totp_session_binding, raise_if_locked, token_urlsafe, ApprovalGateInputV1,
};
use crate::totp::TotpSecretStore;

/// Clearing Pulse lives with turning it off.
pub(crate) use crate::approval_gate_pulse_disable::{clear_pulse_state, TOTP_PAUSED_BY_PULSE};

/// Pulse cooldowns a user may choose. `0`, the default, means a fresh
/// biometric approval for every held action.
pub(crate) const PULSE_ALLOWED_COOLDOWNS: [i64; 3] = [0, 900, 3600];
/// Extra time after the decision window before Pulse refuses the receipt.
const CONSENT_GRACE_SECONDS: i64 = 60;
/// Verdicts Guard can be asked to approve. A hard block never reaches Pulse.
const REVIEWABLE_VERDICTS: [&str; 2] = ["review", "require-reapproval"];

pub(crate) fn err(code: &str, message: &str, status: u16) -> ApprovalGateErrorV1 {
    ApprovalGateErrorV1 {
        code: code.to_owned(),
        message: message.to_owned(),
        status,
    }
}

pub(crate) fn pulse_error(e: &PulseError) -> ApprovalGateErrorV1 {
    err(e.code(), e.message(), e.status())
}

fn state_io() -> ApprovalGateErrorV1 {
    err(
        "approval_gate_state_io",
        "Could not persist approval gate state.",
        500,
    )
}

pub(crate) fn pulse_required() -> ApprovalGateErrorV1 {
    err(
        "approval_gate_pulse_required",
        "Approve this action in the YID app. This gate uses Yanez Pulse.",
        403,
    )
}

pub(crate) fn pulse_enabled(state: &Value) -> bool {
    state.get("pulse_enabled") == Some(&Value::Bool(true))
}

pub(crate) fn factor_generation(state: &Value) -> i64 {
    optional_int(state.get("factor_generation"))
        .unwrap_or(0)
        .max(0)
}

pub(crate) fn pulse_cooldown_seconds(state: &Value) -> i64 {
    optional_int(state.get("pulse_cooldown_seconds"))
        .filter(|s| PULSE_ALLOWED_COOLDOWNS.contains(s))
        .unwrap_or(0)
}

/// The floor when the user does not choose one at enrollment.
pub(crate) const PULSE_DEFAULT_MIN_TIER: AssuranceTier = AssuranceTier::Medium;

/// A floor the user may choose: `medium` or `high`. Low is never a floor.
pub(crate) fn parse_min_tier(value: &str) -> Option<AssuranceTier> {
    AssuranceTier::parse(value).filter(|tier| tier.is_allowed_floor())
}

/// The lowest tier a scan may reach, chosen at enrollment. A saved value
/// Guard cannot read is treated as high, so it fails closed.
pub(crate) fn pulse_min_tier(state: &Value) -> AssuranceTier {
    match state.get("pulse_min_tier") {
        None => PULSE_DEFAULT_MIN_TIER,
        Some(saved) => saved
            .as_str()
            .and_then(parse_min_tier)
            .unwrap_or(AssuranceTier::High),
    }
}

/// Pinned Pulse settings plus the two secrets, loaded only when needed.
pub(crate) struct PulseConfig {
    pub yid: String,
    pub agent_key_id: String,
    /// Approver keys pinned at enrollment.
    pub user_keys: Vec<String>,
    pub agent_key: Zeroizing<String>,
    pub binding_key: Zeroizing<Vec<u8>>,
}

fn recovery_required(message: &str) -> ApprovalGateErrorV1 {
    err("approval_gate_recovery_required", message, 423)
}

pub(crate) fn load_config(
    guard_home: &Path,
    state: &Value,
) -> Result<PulseConfig, ApprovalGateErrorV1> {
    let text = |key: &str| optional_string(state.get(key));
    let unavailable = || recovery_required("Pulse settings are incomplete. Use Pulse recovery.");
    let mut store = TotpSecretStore::new(guard_home);
    let agent_key = text("pulse_agent_secret_id")
        .and_then(|id| store.get_secret(&id))
        .map(Zeroizing::new)
        .ok_or_else(|| {
            recovery_required("The Pulse agent key is unavailable. Use Pulse recovery.")
        })?;
    let binding_key = text("pulse_binding_secret_id")
        .and_then(|id| store.get_secret(&id))
        .and_then(|hex_key| hex::decode(hex_key).ok())
        .filter(|k| k.len() == 32)
        .map(Zeroizing::new)
        .ok_or_else(unavailable)?;
    Ok(PulseConfig {
        yid: text("pulse_yid").ok_or_else(unavailable)?,
        agent_key_id: text("pulse_agent_key_id").ok_or_else(unavailable)?,
        user_keys: state
            .get("pulse_user_keys")
            .and_then(Value::as_array)
            .map(|keys| {
                keys.iter()
                    .filter_map(|k| k.as_str().map(str::to_owned))
                    .collect::<Vec<_>>()
            })
            .filter(|keys| !keys.is_empty())
            .ok_or_else(unavailable)?,
        agent_key,
        binding_key,
    })
}

// ------------------------------------------------------------ operations

#[allow(clippy::too_many_arguments)]
fn approval_binding<'a>(
    purpose: &'a str,
    action: Option<&'a str>,
    scope: Option<&'a str>,
    subject: Option<&'a str>,
    session_nonce: Option<&'a str>,
    session_binding: &'a str,
    request_nonce: &'a str,
    factor_generation: i64,
) -> ActionBinding<'a> {
    ActionBinding {
        purpose,
        action: action.unwrap_or(""),
        scope: scope.unwrap_or(""),
        subject: subject.unwrap_or(""),
        session_nonce: session_nonce.unwrap_or(""),
        session_binding,
        request_nonce,
        factor_generation,
    }
}

/// `pulse_request`. Creates the Pulse authorization for one held action.
#[allow(clippy::too_many_arguments)]
pub(crate) fn pulse_request(
    guard_home: &Path,
    purpose: &str,
    strict: bool,
    action: Option<&str>,
    scope: Option<&str>,
    subject: Option<&str>,
    session_nonce: Option<&str>,
    verdict: Option<&str>,
    batch_ids: &[String],
    now: Option<&str>,
) -> Result<Value, ApprovalGateErrorV1> {
    if verdict.is_some_and(|v| !REVIEWABLE_VERDICTS.contains(&v)) {
        return Err(err(
            "approval_gate_pulse_not_reviewable",
            "Guard blocked this action outright. There is nothing to approve.",
            409,
        ));
    }
    let state = load_state(guard_home);
    if !pulse_enabled(&state) {
        return Err(err(
            "approval_gate_pulse_not_enabled",
            "Yanez Pulse is not the approval factor for this Guard.",
            409,
        ));
    }
    let now_epoch = epoch(now);
    raise_if_locked(&state, now_epoch)?;
    let config = load_config(guard_home, &state)?;
    let strict = strict || state.get("strict_all_decisions") == Some(&Value::Bool(true));
    if !strict && pulse_cooldown_covers(&state, &config.binding_key, purpose, scope, now_epoch) {
        // No Pulse notification: the open cooldown already covers this.
        return Ok(json!({"status": "cooldown_covered"}));
    }
    let session_binding = current_totp_session_binding();
    let request_nonce = token_urlsafe(18);
    let generation = factor_generation(&state);
    let binding = approval_binding(
        purpose,
        action,
        scope,
        subject,
        session_nonce,
        &session_binding,
        &request_nonce,
        generation,
    );
    // What the YID app shows comes from Guard's own record of the request.
    let home = pulse_command::current_home();
    let summary = crate::approval_gate_pulse_summary::summary_with_command(
        guard_home,
        purpose,
        action,
        scope,
        subject,
        batch_ids,
        pulse_command::command_row(&state, home.as_deref()),
    );
    let terms = build_terms_with_summary(&config.binding_key, &binding, &summary)
        .map_err(|e| pulse_error(&e))?;
    let digest = binding_digest(&config.binding_key, &binding).map_err(|e| pulse_error(&e))?;
    let consent_not_after = now_epoch as i64 + DECISION_WINDOW_SECONDS + CONSENT_GRACE_SECONDS;
    // Checked before anything reaches the phone, so a caller that keeps
    // asking cannot keep sending prompts.
    if !pending_has_room(guard_home, now_epoch as i64) {
        return Err(pulse_busy());
    }
    let created = with_transport(&config.agent_key, |t| {
        t.create_authorization(
            &terms,
            &iso_from_epoch(consent_not_after as f64),
            &token_urlsafe(18),
        )
    })
    .map_err(|e| pulse_error(&e))?;
    let code = match_code(&digest);
    let inserted = insert_pending(
        guard_home,
        &created.request_id,
        PendingPulse {
            kind: PendingKind::Approval,
            binding: digest,
            request_nonce,
            terms,
            session_binding,
            factor_generation: generation,
            consent_not_after,
            artifact: None,
        },
        now_epoch as i64,
    );
    if !inserted {
        // Another request took the last slot during the network call.
        return Err(pulse_busy());
    }
    Ok(json!({
        "status": "pending",
        "request_id": created.request_id,
        "match_code": code,
        "decide_by": iso_from_epoch(consent_not_after as f64),
    }))
}

/// `pulse_poll`. One check of the request; returns its status only.
pub(crate) fn pulse_poll(
    guard_home: &Path,
    request_id: &str,
    now: Option<&str>,
) -> Result<Value, ApprovalGateErrorV1> {
    let now_epoch = epoch(now) as i64;
    // Read what the poll needs, then let go of the table before the HTTP call.
    let (agent_key, deadline) = {
        let table = pending()
            .lock()
            .map_err(|_| pulse_error(&PulseError::Unavailable))?;
        let entry = table
            .get(&pending_key(guard_home, request_id))
            .ok_or_else(|| pulse_error(&PulseError::Expired))?;
        if entry.artifact.is_some() {
            return Ok(json!({"status": "approved"}));
        }
        match &entry.kind {
            PendingKind::Enrollment { agent_key, .. } => {
                (Some(agent_key.clone()), entry.consent_not_after)
            }
            PendingKind::Approval => (None, entry.consent_not_after),
        }
    };
    if now_epoch > deadline {
        take_pending(guard_home, request_id);
        return Ok(json!({"status": "expired"}));
    }
    let agent_key = match agent_key {
        Some(key) => key,
        None => load_config(guard_home, &load_state(guard_home))?.agent_key,
    };
    let outcome = with_transport(&agent_key, |t| t.poll(request_id));
    let status = match outcome {
        Ok(PollOutcome::Pending) => "pending",
        Ok(PollOutcome::Approved { artifact }) => {
            if let Ok(mut table) = pending().lock() {
                if let Some(entry) = table.get_mut(&pending_key(guard_home, request_id)) {
                    entry.artifact = Some(artifact);
                }
            }
            "approved"
        }
        Ok(PollOutcome::Rejected) => {
            take_pending(guard_home, request_id);
            "rejected"
        }
        Ok(PollOutcome::Expired) | Err(PulseError::WrongRequest) => {
            take_pending(guard_home, request_id);
            "expired"
        }
        Err(e) => return Err(pulse_error(&e)),
    };
    Ok(json!({"status": status}))
}

/// The Pulse stage of `verify_or_raise_locked`. On `Ok`, the receipt was
/// verified against this exact action and consumed; the caller registers the
/// grant. Returns the cooldown expiry when one was opened.
#[allow(clippy::too_many_arguments)]
pub(crate) fn verify_pulse_stage(
    guard_home: &Path,
    state: &mut Value,
    gate_input: &ApprovalGateInputV1,
    purpose: &str,
    strict: bool,
    action: Option<&str>,
    scope: Option<&str>,
    subject: Option<&str>,
    session_nonce: Option<&str>,
    now_epoch: f64,
) -> Result<Option<String>, ApprovalGateErrorV1> {
    if gate_input.password.is_some() || gate_input.totp_code.is_some() {
        // Pulse replaces both factors; neither is a substitute.
        return Err(pulse_required());
    }
    let request_id = gate_input
        .pulse_request_id
        .as_deref()
        .ok_or_else(pulse_required)?;
    let entry = take_pending(guard_home, request_id).ok_or_else(pulse_required)?;
    let Some(artifact) = entry.artifact.clone() else {
        restore_pending(guard_home, request_id, entry);
        return Err(err(
            "approval_gate_pulse_pending",
            "The Pulse request has not been approved yet.",
            409,
        ));
    };
    if !matches!(entry.kind, PendingKind::Approval) {
        return Err(pulse_error(&PulseError::WrongRequest));
    }
    let config = load_config(guard_home, state)?;
    let session_binding = current_totp_session_binding();
    let expected = binding_digest(
        &config.binding_key,
        &approval_binding(
            purpose,
            action,
            scope,
            subject,
            session_nonce,
            &session_binding,
            &entry.request_nonce,
            factor_generation(state),
        ),
    )
    .map_err(|e| pulse_error(&e))?;
    // A different action, scope, subject, session or factor generation than
    // the one the user approved is a different request.
    if !constant_time_eq(expected.as_bytes(), entry.binding.as_bytes())
        || entry.factor_generation != factor_generation(state)
    {
        return Err(pulse_error(&PulseError::TermsMismatch));
    }
    let now = now_epoch as i64;
    let receipt = with_transport(&config.agent_key, |t| {
        // Read the registry now, not from a cache: a key removed from the YID
        // (lost device, rotation) must stop verifying at once.
        let registry = t.user_keys()?;
        let policy = ReceiptPolicy {
            expected_issuer: YANEZ_ISSUER,
            expected_yid: &config.yid,
            expected_agent_key_id: Some(&config.agent_key_id),
            expected_request_id: request_id,
            expected_terms: &entry.terms,
            expected_consent_not_after: entry.consent_not_after,
            min_tier: pulse_min_tier(state),
            max_age_seconds: DEFAULT_MAX_AGE_SECONDS,
            registry: &registry,
            pinned_user_keys: Some(&config.user_keys),
            now_epoch: now,
        };
        verify_with_cached_keys(t, &artifact, &policy)
    });
    let receipt = match receipt {
        Ok(receipt) => receipt,
        Err(PulseError::Unavailable) => {
            // Nothing is spent yet, locally or at Pulse: keep the user's
            // approval so a retry can verify it without a new scan.
            restore_pending(guard_home, request_id, entry);
            return Err(pulse_error(&PulseError::Unavailable));
        }
        Err(e) => return Err(pulse_error(&e)),
    };
    // The network call above can take seconds. Commit against what is saved
    // now, not the copy loaded before it: if Pulse was turned off or
    // replaced meanwhile, writing the old copy would bring it back.
    let fresh = load_state(guard_home);
    if !same_pulse_factor(state, &fresh) {
        return Err(pulse_error(&PulseError::TermsMismatch));
    }
    *state = fresh;
    // Spend it locally and durably first, then at Pulse. A crash between the
    // two leaves the receipt spent, never reusable.
    ledger_reserve(state, &receipt, now).map_err(ledger_error)?;
    write_state(guard_home, state, Some(&iso_from_epoch(now_epoch))).map_err(|_| state_io())?;
    let token = consumer_token(&config.binding_key, &receipt.jti).map_err(|e| pulse_error(&e))?;
    with_transport(&config.agent_key, |t| t.consume(&artifact, &token))
        .map_err(|e| pulse_error(&e))?;
    let strict = strict || state.get("strict_all_decisions") == Some(&Value::Bool(true));
    let seconds = pulse_cooldown_seconds(state);
    if !strict && seconds > 0 && gate_input.use_cooldown == Some(true) {
        return Ok(Some(record_pulse_cooldown(
            state,
            &config.binding_key,
            purpose,
            scope,
            seconds,
            now_epoch,
        )));
    }
    if let Some(o) = state.as_object_mut() {
        o.remove(PULSE_COOLDOWN_STATE_KEY);
    }
    Ok(None)
}

#[cfg(test)]
#[path = "approval_gate_pulse_tests.rs"]
mod tests;

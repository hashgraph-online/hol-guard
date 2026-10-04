//! Port of the `require_*`/`consume_*` grant consumers from
//! `src/codex_plugin_scanner/guard/approval_gate.py` (:552-806).
//!
//! Thin façade over `verify_or_raise_locked` (verify.rs) + grant-table
//! `validate`/`validate_and_consume`. Each fn is the locked body; the caller
//! holds `_APPROVAL_GATE_LOCK` and loads state once where the source does.

#![forbid(unsafe_code)]

use std::path::Path;

use crate::approval_gate_grants::{ApprovalGateErrorV1, ApprovalGateGrantV1, ApprovalGateGrants};
use crate::approval_gate_state::{enabled, epoch, load_state, optional_int};
use crate::approval_gate_verify::{verify_or_raise_locked, ApprovalGateInputV1};
use crate::totp::TotpSecretStore;

fn err(code: &str, message: &str, status: u16) -> ApprovalGateErrorV1 {
    ApprovalGateErrorV1 {
        code: code.to_owned(),
        message: message.to_owned(),
        status,
    }
}

fn totp_enabled(state: &serde_json::Value) -> bool {
    state.get("totp_enabled") == Some(&serde_json::Value::Bool(true))
}

fn factor_generation(state: &serde_json::Value) -> i64 {
    optional_int(state.get("factor_generation"))
        .unwrap_or(0)
        .max(0)
}

/// `_is_high_risk_action` (:1331-1333): `action=="allow" or scope=="global"`.
fn is_high_risk_action(action: &str, scope: &str) -> bool {
    action == "allow" || scope == "global"
}

/// `_is_strict_approval_action` (:1336-1338): `scope == "global"`.
fn is_strict_approval_action(_action: &str, scope: &str) -> bool {
    scope == "global"
}

/// `_requires_decision_gate` (:1324-1329).
fn requires_decision_gate(state: &serde_json::Value, action: &str, scope: &str) -> bool {
    if !enabled(state) {
        return false;
    }
    if is_high_risk_action(action, scope) {
        return true;
    }
    state.get("strict_all_decisions") == Some(&serde_json::Value::Bool(true))
}

/// `totp_state_valid` for `validate*` — whether the TOTP state resolves.
fn totp_state_valid(guard_home: &Path, state: &serde_json::Value) -> bool {
    match crate::approval_gate_state::optional_string(state.get("totp_secret_id")) {
        Some(id) => {
            let mut store = TotpSecretStore::new(guard_home);
            store.get_secret(&id).is_some()
        }
        None => false,
    }
}

/// Shared `validate_grant` dispatch (non-consuming) used by require_*.
#[allow(clippy::too_many_arguments)]
fn validate_grant_locked(
    guard_home: &Path,
    grants: &ApprovalGateGrants,
    grant: Option<&ApprovalGateGrantV1>,
    purpose: Option<&str>,
    strict: bool,
    action: Option<&str>,
    scope: Option<&str>,
    subject: Option<&str>,
    session_nonce: Option<&str>,
    now: Option<&str>,
) -> Result<(), ApprovalGateErrorV1> {
    let state = load_state(guard_home);
    let now_epoch = epoch(now);
    let grant_home = guard_home.to_string_lossy();
    let expires_epoch = grant
        .map(|g| epoch(Some(g.expires_at.as_str())))
        .unwrap_or(0.0);
    grants.validate(
        &grant_home,
        grant,
        expires_epoch,
        purpose,
        strict,
        action,
        scope,
        subject,
        session_nonce,
        factor_generation(&state),
        totp_enabled(&state),
        totp_state_valid(guard_home, &state),
        now_epoch,
    )
}

/// `require_approval_decision` (:552-587). Returns grant or None when no gate.
#[allow(clippy::too_many_arguments)]
pub(crate) fn require_approval_decision(
    guard_home: &Path,
    grants: &ApprovalGateGrants,
    action: &str,
    scope: &str,
    approval_gate_input: Option<&ApprovalGateInputV1>,
    approval_gate_grant: Option<&ApprovalGateGrantV1>,
    subject: Option<&str>,
    session_nonce: Option<&str>,
    now: Option<&str>,
) -> Result<Option<ApprovalGateGrantV1>, ApprovalGateErrorV1> {
    let state = load_state(guard_home);
    if !requires_decision_gate(&state, action, scope) {
        return Ok(None);
    }
    let strict = is_strict_approval_action(action, scope);
    if let Some(g) = approval_gate_grant {
        validate_grant_locked(
            guard_home,
            grants,
            Some(g),
            Some("approval_decision"),
            strict,
            Some(action),
            Some(scope),
            subject,
            session_nonce,
            now,
        )?;
        return Ok(Some(g.clone()));
    }
    verify_or_raise_locked(
        guard_home,
        &mut state.clone(),
        grants,
        "approval_decision",
        approval_gate_input,
        strict,
        Some(action),
        Some(scope),
        subject,
        session_nonce,
        now,
    )
    .map(Some)
}

/// `require_policy_write` (:589-602).
pub(crate) fn require_policy_write(
    guard_home: &Path,
    grants: &ApprovalGateGrants,
    action: &str,
    scope: &str,
    approval_gate_grant: Option<&ApprovalGateGrantV1>,
    now: Option<&str>,
) -> Result<(), ApprovalGateErrorV1> {
    let state = load_state(guard_home);
    if !requires_decision_gate(&state, action, scope) {
        return Ok(());
    }
    validate_grant_locked(
        guard_home,
        grants,
        approval_gate_grant,
        None,
        is_strict_approval_action(action, scope),
        None,
        None,
        None,
        None,
        now,
    )
}

/// `require_request_resolution` (:604-619).
pub(crate) fn require_request_resolution(
    guard_home: &Path,
    grants: &ApprovalGateGrants,
    resolution_action: &str,
    resolution_scope: &str,
    approval_gate_grant: Option<&ApprovalGateGrantV1>,
    now: Option<&str>,
) -> Result<(), ApprovalGateErrorV1> {
    let state = load_state(guard_home);
    if !requires_decision_gate(&state, resolution_action, resolution_scope) {
        return Ok(());
    }
    validate_grant_locked(
        guard_home,
        grants,
        approval_gate_grant,
        None,
        is_strict_approval_action(resolution_action, resolution_scope),
        None,
        None,
        None,
        None,
        now,
    )
}

/// `require_policy_clear` (:621-628).
pub(crate) fn require_policy_clear(
    guard_home: &Path,
    grants: &ApprovalGateGrants,
    approval_gate_grant: Option<&ApprovalGateGrantV1>,
    now: Option<&str>,
) -> Result<(), ApprovalGateErrorV1> {
    if !enabled(&load_state(guard_home)) {
        return Ok(());
    }
    validate_grant_locked(
        guard_home,
        grants,
        approval_gate_grant,
        Some("policy_clear"),
        true,
        None,
        None,
        None,
        None,
        now,
    )
}

/// `require_settings_write` (:630-637).
pub(crate) fn require_settings_write(
    guard_home: &Path,
    grants: &ApprovalGateGrants,
    approval_gate_grant: Option<&ApprovalGateGrantV1>,
    now: Option<&str>,
) -> Result<(), ApprovalGateErrorV1> {
    if !enabled(&load_state(guard_home)) {
        return Ok(());
    }
    validate_grant_locked(
        guard_home,
        grants,
        approval_gate_grant,
        Some("settings_write"),
        true,
        None,
        None,
        None,
        None,
        now,
    )
}

/// `require_high_risk` (:639-677).
#[allow(clippy::too_many_arguments)]
pub(crate) fn require_high_risk(
    guard_home: &Path,
    grants: &ApprovalGateGrants,
    purpose: &str,
    approval_gate_input: Option<&ApprovalGateInputV1>,
    approval_gate_grant: Option<&ApprovalGateGrantV1>,
    action: Option<&str>,
    scope: Option<&str>,
    subject: Option<&str>,
    session_nonce: Option<&str>,
    now: Option<&str>,
) -> Result<Option<ApprovalGateGrantV1>, ApprovalGateErrorV1> {
    let state = load_state(guard_home);
    if !enabled(&state) {
        return Ok(None);
    }
    if let Some(g) = approval_gate_grant {
        validate_grant_locked(
            guard_home,
            grants,
            Some(g),
            Some(purpose),
            true,
            action,
            scope,
            subject,
            session_nonce,
            now,
        )?;
        return Ok(Some(g.clone()));
    }
    verify_or_raise_locked(
        guard_home,
        &mut state.clone(),
        grants,
        purpose,
        approval_gate_input,
        true,
        action,
        scope,
        subject,
        session_nonce,
        now,
    )
    .map(Some)
}

/// `require_extension_control` (:679-701) — strict proof, must be configured.
pub(crate) fn require_extension_control(
    guard_home: &Path,
    grants: &ApprovalGateGrants,
    approval_gate_input: Option<&ApprovalGateInputV1>,
    action: &str,
    subject: &str,
    session_nonce: &str,
    now: Option<&str>,
) -> Result<ApprovalGateGrantV1, ApprovalGateErrorV1> {
    let mut state = load_state(guard_home);
    if !enabled(&state) {
        return Err(err(
            "approval_gate_configuration_required",
            "Configure the approval gate before changing extension controls.",
            423,
        ));
    }
    verify_or_raise_locked(
        guard_home,
        &mut state,
        grants,
        "extension_control_mutation",
        approval_gate_input,
        true,
        Some(action),
        Some("extension-control-authority"),
        Some(subject),
        Some(session_nonce),
        now,
    )
}

/// `consume_extension_control_grant` (:704-724).
pub(crate) fn consume_extension_control_grant(
    guard_home: &Path,
    grants: &ApprovalGateGrants,
    grant: &ApprovalGateGrantV1,
    action: &str,
    subject: &str,
    session_nonce: &str,
    now: Option<&str>,
) -> Result<(), ApprovalGateErrorV1> {
    let state = load_state(guard_home);
    grants.validate_and_consume(
        &guard_home.to_string_lossy(),
        grant,
        epoch(Some(grant.expires_at.as_str())),
        Some("extension_control_mutation"),
        true,
        Some(action),
        Some("extension-control-authority"),
        Some(subject),
        Some(session_nonce),
        factor_generation(&state),
        totp_enabled(&state),
        totp_state_valid(guard_home, &state),
        epoch(now),
    )
}

/// `require_local_cli_trust` (:727-749) — strict proof, must be configured.
pub(crate) fn require_local_cli_trust(
    guard_home: &Path,
    grants: &ApprovalGateGrants,
    approval_gate_input: Option<&ApprovalGateInputV1>,
    action: &str,
    subject: &str,
    session_nonce: &str,
    now: Option<&str>,
) -> Result<ApprovalGateGrantV1, ApprovalGateErrorV1> {
    let mut state = load_state(guard_home);
    if !enabled(&state) {
        return Err(err(
            "approval_gate_configuration_required",
            "Configure the approval gate before changing CLI allow-list settings.",
            423,
        ));
    }
    verify_or_raise_locked(
        guard_home,
        &mut state,
        grants,
        "local_cli_trust_mutation",
        approval_gate_input,
        true,
        Some(action),
        Some("local-cli-allowlist"),
        Some(subject),
        Some(session_nonce),
        now,
    )
}

/// `consume_local_cli_trust_grant` (:752-772).
pub(crate) fn consume_local_cli_trust_grant(
    guard_home: &Path,
    grants: &ApprovalGateGrants,
    grant: &ApprovalGateGrantV1,
    action: &str,
    subject: &str,
    session_nonce: &str,
    now: Option<&str>,
) -> Result<(), ApprovalGateErrorV1> {
    let state = load_state(guard_home);
    grants.validate_and_consume(
        &guard_home.to_string_lossy(),
        grant,
        epoch(Some(grant.expires_at.as_str())),
        Some("local_cli_trust_mutation"),
        true,
        Some(action),
        Some("local-cli-allowlist"),
        Some(subject),
        Some(session_nonce),
        factor_generation(&state),
        totp_enabled(&state),
        totp_state_valid(guard_home, &state),
        epoch(now),
    )
}

//! Port of the approval-gate verification arm from
//! `src/codex_plugin_scanner/guard/approval_gate.py`.
//!
//! Covers the single-call verify→grant flow (`_verify_or_raise_locked`,
//! :963-1058), the two factor stages (`_verify_password_stage` :1155-1175,
//! `_verify_totp_or_raise` :1177-1201), the TOTP-recent satisfaction proof
//! (`_record_recent_totp_satisfaction` :1225-1253 +
//! `_recent_totp_satisfied_locked` :1256-1303), session binding
//! (`_current_totp_session_binding` :1305-1321), and auth-state rotation
//! (`_rotate_authentication_state` :1129-1137 + `_invalidate_active_grants`
//! :1140-1144).
//!
//! All state transitions are **in-memory on the caller's `state: &mut Value`**
//! (the `approval-gate.json` dict) plus the success-path `_write_state` persist
//! (`approval_gate.py:1284`) just before `_register_grant`. The resident grant
//! `crate::approval_gate_grants` (the one-table `_ACTIVE_GRANTS` port).

#![forbid(unsafe_code)]

use std::path::Path;

use guard_policy_snapshot::local_authority_integrity::{
    sign_local_authority_payload, verify_local_authority_payload,
};
use serde_json::{Map, Value};

use crate::approval_gate_grants::{
    ApprovalGateErrorV1, ApprovalGateGrantV1, ApprovalGateGrants, GrantFields,
};
use crate::approval_gate_state::{
    coerce_cooldown_seconds, constant_time_eq, cooldown_active, epoch, is_future, iso_from_epoch,
    optional_int, optional_string, record_failed_attempt, reset_failed_attempts, verifier,
    verify_password, write_state, ApprovalGateFactor,
};
use crate::encrypted_secret_store::{b64url_encode, random_bytes};
use crate::totp::{verify_totp_code, TotpSecretStore, APPROVAL_GATE_TOTP_SKEW_STEPS};

/// `_TOTP_RECENT_STATE_KEY` (:95).
const TOTP_RECENT_STATE_KEY: &str = "totp_recent_proof";
/// `_TOTP_RECENT_INTEGRITY_PURPOSE` (:96).
const TOTP_RECENT_INTEGRITY_PURPOSE: &str = "guard-approval-gate-totp-recent";
/// `APPROVAL_GATE_TOTP_RECENT_TTL_SECONDS` — see `totp.rs` / :_TOTP_RECENT ttl.
const TOTP_RECENT_TTL_SECONDS: f64 = 60.0;
/// `_TOTP_SESSION_ENV_KEYS` (:97-104).
const TOTP_SESSION_ENV_KEYS: [&str; 6] = [
    "TERM_SESSION_ID",
    "WT_SESSION",
    "WEZTERM_PANE",
    "KITTY_WINDOW_ID",
    "TMUX_PANE",
    "SSH_TTY",
];
/// `_INVALIDATED_AUTH_STATE_KEYS` (:105-113).
const INVALIDATED_AUTH_STATE_KEYS: [&str; 7] = [
    "approval_sessions",
    "recovery_code_hashes",
    "recovery_codes",
    "session_nonces",
    "trusted_device_state",
    "trusted_devices",
    TOTP_RECENT_STATE_KEY,
];

fn err(code: &str, message: &str, status: u16) -> ApprovalGateErrorV1 {
    ApprovalGateErrorV1 {
        code: code.to_owned(),
        message: message.to_owned(),
        status,
    }
}

/// `secrets.token_urlsafe(nbytes)` — urlsafe-b64 of `nbytes` random bytes with
/// padding stripped. n=18 → 24 chars, n=24 → 32 chars.
pub(crate) fn token_urlsafe(nbytes: usize) -> String {
    let raw = random_bytes(nbytes);
    b64url_encode(&raw).trim_end_matches('=').to_owned()
}

/// `_totp_enabled` (:1121-1123).
fn totp_enabled(state: &Value) -> bool {
    state.get("totp_enabled") == Some(&Value::Bool(true))
}

/// `_factor_generation` (:1125-1126).
fn factor_generation(state: &Value) -> i64 {
    optional_int(state.get("factor_generation"))
        .unwrap_or(0)
        .max(0)
}

/// `_cooldown_seconds` (:1374-1375) → `coerce_cooldown_seconds`.
fn cooldown_seconds(state: &Value) -> Result<i64, ApprovalGateErrorV1> {
    coerce_cooldown_seconds(state.get("cooldown_seconds"))
        .map_err(|_| ApprovalGateErrorV1 {
            code: "approval_gate_invalid_cooldown".to_owned(),
            message: "Approval cooldown must be 0 (every approval), 900 (15 minutes), or 3600 (1 hour) seconds.".to_owned(),
            status: 400,
        })
}

/// `_current_totp_session_binding` (:1305-1321) — `sid`/`ppid`/`pid` +
/// terminal env vars, sha256 hex of `"\0"`-joined signals.
/// Read `ppid` (field 4) and `sid` (field 6) from `/proc/self/stat` without
/// unsafe. `/proc` layout: `pid (comm) state ppid pgrp session ...` — `comm`
/// may contain spaces so parse after the last `)`.
#[cfg(unix)]
fn proc_self_ppid_sid() -> (i64, i64) {
    let stat = match std::fs::read_to_string("/proc/self/stat") {
        Ok(s) => s,
        Err(_) => return (0, -1),
    };
    let after = match stat.rfind(')') {
        Some(i) => &stat[i + 1..],
        None => return (0, -1),
    };
    // after `)`: " S ppid pgrp session ..."
    let fields: Vec<&str> = after.split_whitespace().collect();
    // fields[0]=state, [1]=ppid, [2]=pgrp, [3]=session(sid)
    let ppid = fields
        .get(1)
        .and_then(|v| v.parse::<i64>().ok())
        .unwrap_or(0);
    let sid = fields
        .get(3)
        .and_then(|v| v.parse::<i64>().ok())
        .unwrap_or(-1);
    (ppid, sid)
}

#[cfg(unix)]
pub(crate) fn current_totp_session_binding() -> Option<String> {
    let mut signals: Vec<String> = Vec::new();
    let (_ppid, sid) = proc_self_ppid_sid();
    if sid >= 0 {
        signals.push(format!("sid={sid}"));
    }
    for key in TOTP_SESSION_ENV_KEYS {
        if let Ok(value) = std::env::var(key) {
            if !value.is_empty() {
                signals.push(format!("{key}={value}"));
            }
        }
    }
    if signals.is_empty() {
        let (parent_pid, _sid) = proc_self_ppid_sid();
        if parent_pid > 0 {
            signals.push(format!("ppid={parent_pid}"));
        } else {
            signals.push(format!("pid={}", std::process::id()));
        }
    }
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(signals.join("\0").as_bytes());
    Some(hex::encode(h.finalize()))
}

#[cfg(not(unix))]
fn current_totp_session_binding() -> Option<String> {
    let mut signals: Vec<String> = Vec::new();
    for key in TOTP_SESSION_ENV_KEYS {
        if let Ok(value) = std::env::var(key) {
            if !value.is_empty() {
                signals.push(format!("{key}={value}"));
            }
        }
    }
    if signals.is_empty() {
        signals.push(format!("pid={}", std::process::id()));
    }
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(signals.join("\0").as_bytes());
    Some(hex::encode(h.finalize()))
}

/// `_validate_totp_state_or_raise` (:1204-1218).
fn validate_totp_state_or_raise(
    guard_home: &Path,
    state: &Value,
) -> Result<String, ApprovalGateErrorV1> {
    let secret_id = optional_string(state.get("totp_secret_id")).ok_or_else(|| {
        err(
            "approval_gate_recovery_required",
            "Approval gate TOTP secret is unavailable.",
            423,
        )
    })?;
    let mut store = TotpSecretStore::new(guard_home);
    store.get_secret(&secret_id).ok_or_else(|| {
        err(
            "approval_gate_recovery_required",
            "Approval gate TOTP secret is unavailable.",
            423,
        )
    })
}

/// `_record_recent_totp_satisfaction` (:1225-1253) — sign a recent-TOTP proof
/// keyed by the TOTP secret itself, stored in state for within-TTL reuse.
fn record_recent_totp_satisfaction(
    guard_home: &Path,
    state: &mut Value,
    accepted_counter: i64,
    now_epoch: f64,
) {
    let session_binding = current_totp_session_binding();
    let secret_id = optional_string(state.get("totp_secret_id"));
    let (session_binding, secret_id) = match (session_binding, secret_id) {
        (Some(b), Some(s)) => (b, s),
        _ => {
            if let Some(obj) = state.as_object_mut() {
                obj.remove(TOTP_RECENT_STATE_KEY);
            }
            return;
        }
    };
    let secret = match validate_totp_state_or_raise(guard_home, state) {
        Ok(s) => s,
        Err(_) => return,
    };
    let issued_at = iso_from_epoch(now_epoch);
    let mut payload = Map::new();
    payload.insert("session_binding".into(), Value::String(session_binding));
    payload.insert(
        "factor_generation".into(),
        Value::Number(factor_generation(state).into()),
    );
    payload.insert(
        "accepted_counter".into(),
        Value::Number(accepted_counter.into()),
    );
    payload.insert("issued_at".into(), Value::String(issued_at.clone()));
    payload.insert(
        "expires_at".into(),
        Value::String(iso_from_epoch(now_epoch + TOTP_RECENT_TTL_SECONDS)),
    );
    let fields = match sign_local_authority_payload(
        &Value::Object(payload.clone()),
        secret.as_bytes(),
        &secret_id,
        TOTP_RECENT_INTEGRITY_PURPOSE,
        &issued_at,
    ) {
        Ok(f) => f,
        Err(_) => return,
    };
    let mut integrity = Map::new();
    integrity.insert(
        "integrity_version".into(),
        Value::Number(fields.integrity_version.into()),
    );
    integrity.insert("payload_hash".into(), Value::String(fields.payload_hash));
    integrity.insert("payload_mac".into(), Value::String(fields.payload_mac));
    integrity.insert(
        "integrity_key_id".into(),
        Value::String(fields.integrity_key_id),
    );
    integrity.insert("signed_at".into(), Value::String(fields.signed_at));
    let mut proof = Map::new();
    proof.insert("payload".into(), Value::Object(payload));
    proof.insert("integrity".into(), Value::Object(integrity));
    state
        .as_object_mut()
        .map(|o| o.insert(TOTP_RECENT_STATE_KEY.into(), Value::Object(proof)));
}

/// `_recent_totp_satisfied_locked` (:1256-1303).
pub(crate) fn recent_totp_satisfied_locked(
    guard_home: &Path,
    state: &Value,
    now_epoch: f64,
) -> bool {
    let proof = match state.get(TOTP_RECENT_STATE_KEY).and_then(|v| v.as_object()) {
        Some(p) => p,
        None => return false,
    };
    let payload = match proof.get("payload").and_then(|v| v.as_object()) {
        Some(p) => p,
        None => return false,
    };
    let integrity = match proof.get("integrity") {
        Some(i) => i.clone(),
        None => return false,
    };
    let session_binding = match current_totp_session_binding() {
        Some(b) => b,
        None => return false,
    };
    let secret_id = match optional_string(state.get("totp_secret_id")) {
        Some(s) => s,
        None => return false,
    };
    let secret = match validate_totp_state_or_raise(guard_home, state) {
        Ok(s) => s,
        Err(_) => return false,
    };
    let verify = verify_local_authority_payload(
        &Value::Object(payload.clone()),
        &integrity,
        Some(secret.as_bytes()),
        Some(secret_id.as_str()),
        TOTP_RECENT_INTEGRITY_PURPOSE,
    );
    if verify.status != "valid" {
        return false;
    }
    let stored_binding = match payload
        .get("session_binding")
        .and_then(|v| optional_string(Some(v)))
    {
        Some(b) => b,
        None => return false,
    };
    if !constant_time_eq(stored_binding.as_bytes(), session_binding.as_bytes()) {
        return false;
    }
    if payload
        .get("factor_generation")
        .and_then(|v| optional_int(Some(v)))
        != Some(factor_generation(state))
    {
        return false;
    }
    let accepted_counter = payload
        .get("accepted_counter")
        .and_then(|v| optional_int(Some(v)));
    if accepted_counter.is_none()
        || accepted_counter != optional_int(state.get("totp_last_counter"))
    {
        return false;
    }
    let issued_at = payload
        .get("issued_at")
        .and_then(|v| optional_string(Some(v)));
    let expires_at = payload
        .get("expires_at")
        .and_then(|v| optional_string(Some(v)));
    let (issued_at, expires_at) = match (issued_at, expires_at) {
        (Some(i), Some(e)) => (i, e),
        _ => return false,
    };
    let issued_epoch = epoch(Some(&issued_at));
    let expires_epoch = epoch(Some(&expires_at));
    if issued_epoch <= 0.0 || issued_epoch > now_epoch + 1.0 {
        return false;
    }
    if expires_epoch <= issued_epoch {
        return false;
    }
    if expires_epoch - issued_epoch > TOTP_RECENT_TTL_SECONDS + 0.001 {
        return false;
    }
    expires_epoch > now_epoch
}

/// `_verify_password_stage` (:1155-1175).
fn verify_password_stage(
    guard_home: &Path,
    state: &mut Value,
    password: Option<&str>,
    now: Option<&str>,
) -> Result<(), ApprovalGateErrorV1> {
    let verifier_payload = verifier(state);
    if verifier_payload.is_none() {
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
    if !verify_password(password, verifier_payload) {
        record_failed_attempt(guard_home, state, ApprovalGateFactor::Password, now);
        return Err(err(
            "approval_gate_invalid_password",
            "Approval password is invalid.",
            403,
        ));
    }
    Ok(())
}

/// `_verify_totp_or_raise` (:1177-1201).
fn verify_totp_or_raise(
    guard_home: &Path,
    state: &mut Value,
    code: &str,
    now_epoch: f64,
    allow_reused_counter: bool,
) -> Result<i64, ApprovalGateErrorV1> {
    let secret = validate_totp_state_or_raise(guard_home, state)?;
    let allow_last =
        allow_reused_counter && recent_totp_satisfied_locked(guard_home, state, now_epoch);
    let accepted = verify_totp_code(
        &secret,
        code,
        now_epoch,
        APPROVAL_GATE_TOTP_SKEW_STEPS,
        optional_int(state.get("totp_last_counter")),
        allow_last,
    );
    match accepted {
        Some(c) => Ok(c),
        None => {
            let now_iso = iso_from_epoch(now_epoch);
            record_failed_attempt(guard_home, state, ApprovalGateFactor::Totp, Some(&now_iso));
            Err(err(
                "approval_gate_totp_invalid",
                "That authenticator code is wrong. Open your authenticator app and enter the current six-digit code.",
                403,
            ))
        }
    }
}

/// `_rotate_authentication_state` (:1129-1137) — advance factor generation,
/// drop state that could outlive rotation.
pub(crate) fn rotate_authentication_state(state: &mut Value) {
    let next = factor_generation(state) + 1;
    if let Some(obj) = state.as_object_mut() {
        obj.insert("factor_generation".into(), Value::Number(next.into()));
        obj.remove("cooldown_expires_at");
        for key in INVALIDATED_AUTH_STATE_KEYS {
            obj.remove(key);
        }
    }
}

/// `_invalidate_active_grants` (:1140-1144) → table `invalidate_for_home`.
pub(crate) fn invalidate_active_grants(grants: &ApprovalGateGrants, guard_home: &Path) {
    grants.invalidate_for_home(&guard_home.to_string_lossy());
}

/// The approval-gate input (`ApprovalGateInput`, dataclass) — optional
/// password + optional totp code. `new_password` is consumed by the
/// configuration arm, not verification, so it is not modelled here.
#[derive(Debug, Default, Clone, PartialEq)]
pub struct ApprovalGateInputV1 {
    pub password: Option<String>,
    pub new_password: Option<String>,
    pub confirm_password: Option<String>,
    pub totp_code: Option<String>,
    pub use_cooldown: Option<bool>,
    pub revoke_cooldown: bool,
    pub require_fresh_totp: bool,
}

/// `input_from_mapping` (:161-178) — daemon/dashboard payload -> gate input.
/// Reads `approval_gate` sub-mapping plus top-level `approval_password` /
/// `approval_totp_code` / `approval_gate_use_cooldown` fallbacks.
pub fn input_from_mapping(payload: Option<&Value>) -> Option<ApprovalGateInputV1> {
    let payload = payload?.as_object()?;
    let gate = payload
        .get("approval_gate")
        .and_then(|v| v.as_object())
        .cloned()
        .unwrap_or_default();
    let opt_str = |m: &Map<String, Value>, k: &str| optional_string(m.get(k));
    let password = opt_str(payload, "approval_password").or_else(|| opt_str(&gate, "password"));
    let current_password = opt_str(&gate, "current_password");
    let totp_code = opt_str(payload, "approval_totp_code").or_else(|| opt_str(&gate, "totp_code"));
    let use_cooldown = payload
        .get("approval_gate_use_cooldown")
        .and_then(|v| v.as_bool())
        .or_else(|| gate.get("use_cooldown").and_then(|v| v.as_bool()));
    let revoke_cooldown = gate
        .get("revoke_cooldown")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    Some(ApprovalGateInputV1 {
        password: current_password.or(password),
        new_password: opt_str(&gate, "new_password"),
        confirm_password: opt_str(&gate, "confirm_password"),
        totp_code,
        use_cooldown,
        revoke_cooldown,
        require_fresh_totp: false,
    })
}

/// `_verify_or_raise_locked` (:963-1058). Pure on `state`; the caller supplies
/// `now_epoch`/`now` and the resident grant table.
///
/// `purpose` maps to `ApprovalGatePurpose`; `strict`, `action`, `scope`,
/// `subject`, `session_nonce` pass through to `_register_grant`.
#[allow(clippy::too_many_arguments)]
pub(crate) fn verify_or_raise_locked(
    guard_home: &Path,
    state: &mut Value,
    grants: &ApprovalGateGrants,
    purpose: &str,
    approval_gate_input: Option<&ApprovalGateInputV1>,
    strict: bool,
    action: Option<&str>,
    scope: Option<&str>,
    subject: Option<&str>,
    session_nonce: Option<&str>,
    now: Option<&str>,
) -> Result<ApprovalGateGrantV1, ApprovalGateErrorV1> {
    let now_epoch = epoch(now);
    let locked_until = optional_string(state.get("locked_until"));
    if is_future(locked_until.as_deref(), now_epoch) {
        return Err(err(
            "approval_gate_locked",
            "Approval gate is temporarily locked.",
            423,
        ));
    }
    let gate_input = approval_gate_input.cloned().unwrap_or_default();
    if verifier(state).is_none() {
        return Err(err(
            "approval_gate_recovery_required",
            "Approval gate is enabled but no verifier is configured.",
            423,
        ));
    }
    if !totp_enabled(state) && !strict && cooldown_active(state, now_epoch) {
        return register_grant(
            guard_home,
            state,
            grants,
            purpose,
            action,
            scope,
            subject,
            session_nonce,
            vec!["cooldown".to_owned()],
            false,
            true,
            optional_string(state.get("cooldown_expires_at")),
            false,
            false,
            now,
        );
    }
    let mut accepted_counter: Option<i64> = None;
    if totp_enabled(state) {
        if gate_input.totp_code.is_none() {
            // Python `_verify_or_raise` (:1300-1308): with TOTP enabled and no
            // code supplied, the gate requires a recent satisfied proof
            // regardless of whether a password was sent — the password is not a
            // substitute second factor.
            if recent_totp_satisfied_locked(guard_home, state, now_epoch) {
                // Reuse the recent TOTP proof without re-entering a code.
                accepted_counter = optional_int(state.get("totp_last_counter"));
            } else {
                return Err(err(
                    "approval_gate_totp_required",
                    "TOTP code is required.",
                    403,
                ));
            }
        } else {
            let code = gate_input.totp_code.as_deref().unwrap();
            accepted_counter = Some(verify_totp_or_raise(
                guard_home, state, code, now_epoch, true,
            )?);
            if let Some(obj) = state.as_object_mut() {
                obj.insert(
                    "totp_last_counter".into(),
                    Value::Number(accepted_counter.unwrap().into()),
                );
            }
            record_recent_totp_satisfaction(
                guard_home,
                state,
                accepted_counter.unwrap(),
                now_epoch,
            );
        }
        if gate_input.password.is_some() {
            verify_password_stage(guard_home, state, gate_input.password.as_deref(), now)?;
        }
    } else {
        verify_password_stage(guard_home, state, gate_input.password.as_deref(), now)?;
    }
    reset_failed_attempts(state);
    let cooldown_seconds_val = cooldown_seconds(state)?;
    let mut cooldown_expires_at: Option<String> = None;
    let mut used_cooldown = false;
    if cooldown_seconds_val > 0 && !totp_enabled(state) && !strict {
        let expiry = now_epoch + cooldown_seconds_val as f64;
        cooldown_expires_at = Some(iso_from_epoch(expiry));
        if let Some(obj) = state.as_object_mut() {
            obj.insert(
                "cooldown_expires_at".into(),
                Value::String(cooldown_expires_at.clone().unwrap()),
            );
        }
        used_cooldown = true;
    }
    let factor_set: Vec<String> = if totp_enabled(state) && accepted_counter.is_some() {
        if gate_input.password.is_some() {
            vec!["totp".into(), "password".into()]
        } else {
            vec!["totp".into()]
        }
    } else {
        vec!["password".into()]
    };
    write_state(guard_home, state, now).map_err(|_| {
        err(
            "approval_gate_state_io",
            "Could not persist approval gate state.",
            500,
        )
    })?;
    register_grant(
        guard_home,
        state,
        grants,
        purpose,
        action,
        scope,
        subject,
        session_nonce,
        factor_set,
        strict,
        used_cooldown,
        cooldown_expires_at,
        accepted_counter.is_none(),
        accepted_counter.is_some(),
        now,
    )
}

/// `_register_grant` (:1063-1119) — resolve defaults, mint tokens, register.
#[allow(clippy::too_many_arguments)]
fn register_grant(
    guard_home: &Path,
    state: &Value,
    grants: &ApprovalGateGrants,
    purpose: &str,
    action: Option<&str>,
    scope: Option<&str>,
    subject: Option<&str>,
    session_nonce: Option<&str>,
    factor_set: Vec<String>,
    strict: bool,
    used_cooldown: bool,
    cooldown_expires_at: Option<String>,
    password_verified: bool,
    totp_verified: bool,
    now: Option<&str>,
) -> Result<ApprovalGateGrantV1, ApprovalGateErrorV1> {
    let now_epoch = epoch(now);
    let expires_epoch = now_epoch + crate::totp::APPROVAL_GATE_GRANT_TTL_SECONDS as f64;
    let issued_at = iso_from_epoch(now_epoch);
    let expires_at = iso_from_epoch(expires_epoch);
    grants.register(
        &guard_home.to_string_lossy(),
        GrantFields {
            purpose,
            action,
            scope,
            subject,
            session_nonce,
            factor_set,
            strict,
            used_cooldown,
            cooldown_expires_at,
            password_verified,
            totp_verified,
            factor_generation: factor_generation(state),
            grant_id: token_urlsafe(24),
            subject_token: token_urlsafe(18),
            nonce_token: token_urlsafe(18),
        },
        now_epoch,
        &issued_at,
        &expires_at,
        expires_epoch,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const VERIFIER: &str = r#"{"salt":"AQIDBAUGBwgJCgsMDQ4PEA==","hash":"LnzsqzF1RwckQbo6EfZW6OXVxlmuKxwnvvTcPI0jdNw=","iterations":310000,"algorithm":"pbkdf2_sha256"}"#;
    // RFC 6238 SHA-1 test secret, base32.
    const TOTP_SECRET: &str = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";

    fn home(tag: &str) -> std::path::PathBuf {
        let h = std::env::temp_dir().join(format!(
            "gate-verify-{tag}-{}-{}",
            std::process::id(),
            nanos()
        ));
        std::fs::create_dir_all(&h).unwrap();
        h
    }
    fn nanos() -> u128 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    }

    fn enabled_state() -> Value {
        let mut st = crate::approval_gate_state::default_state();
        st.as_object_mut()
            .unwrap()
            .insert("enabled".into(), json!(true));
        st.as_object_mut()
            .unwrap()
            .insert("verifier".into(), serde_json::from_str(VERIFIER).unwrap());
        st.as_object_mut()
            .unwrap()
            .insert("fail_closed".into(), json!(false));
        st
    }

    fn input(password: Option<&str>, code: Option<&str>) -> ApprovalGateInputV1 {
        ApprovalGateInputV1 {
            password: password.map(str::to_owned),
            totp_code: code.map(str::to_owned),
            ..Default::default()
        }
    }

    #[test]
    fn password_stage_issues_grant_and_verifies() {
        let h = home("pw");
        let grants = ApprovalGateGrants::new();
        let mut st = enabled_state();
        let g = verify_or_raise_locked(
            &h,
            &mut st,
            &grants,
            "local_once",
            Some(&input(Some("correct horse battery"), None)),
            false,
            None,
            None,
            None,
            None,
            Some("2026-10-02T00:00:00+00:00"),
        )
        .expect("grant");
        assert_eq!(g.factor_set, vec!["password"]);
        assert!(g.password_verified && !g.totp_verified);
        assert_eq!(grants.len(), 1);
        // Validate the resident grant back.
        let now_epoch = epoch(Some("2026-10-02T00:00:01+00:00"));
        grants
            .validate(
                &h.to_string_lossy(),
                Some(&g),
                epoch(Some(g.expires_at.as_str())),
                Some("local_once"),
                false,
                None,
                None,
                None,
                None,
                0,
                false,
                true,
                now_epoch,
            )
            .expect("grant validates");
        let _ = std::fs::remove_dir_all(&h);
    }

    #[test]
    fn wrong_password_records_failure_and_errors() {
        let h = home("bad");
        let grants = ApprovalGateGrants::new();
        let mut st = enabled_state();
        let err = verify_or_raise_locked(
            &h,
            &mut st,
            &grants,
            "local_once",
            Some(&input(Some("nope"), None)),
            false,
            None,
            None,
            None,
            None,
            Some("2026-10-02T00:00:00+00:00"),
        )
        .unwrap_err();
        assert_eq!(err.code, "approval_gate_invalid_password");
        assert_eq!(optional_int(st.get("password_failed_attempts")), Some(1));
        assert_eq!(grants.len(), 0);
        let _ = std::fs::remove_dir_all(&h);
    }

    #[test]
    fn no_verifier_is_recovery_required() {
        let h = home("nov");
        let grants = ApprovalGateGrants::new();
        let mut st = crate::approval_gate_state::default_state();
        st.as_object_mut()
            .unwrap()
            .insert("enabled".into(), json!(true));
        st.as_object_mut()
            .unwrap()
            .insert("fail_closed".into(), json!(false));
        let err = verify_or_raise_locked(
            &h,
            &mut st,
            &grants,
            "local_once",
            Some(&input(Some("x"), None)),
            false,
            None,
            None,
            None,
            None,
            Some("2026-10-02T00:00:00+00:00"),
        )
        .unwrap_err();
        assert_eq!(err.code, "approval_gate_recovery_required");
        assert_eq!(err.status, 423);
        let _ = std::fs::remove_dir_all(&h);
    }

    #[test]
    fn totp_stage_verifies_and_records_recent_proof() {
        let h = home("totp");
        let grants = ApprovalGateGrants::new();
        let mut st = enabled_state();
        // Enable TOTP with a stored secret.
        let mut store = TotpSecretStore::new(&h);
        store.ensure_ready().unwrap();
        store.set_secret("dev-secret", TOTP_SECRET).unwrap();
        {
            let o = st.as_object_mut().unwrap();
            o.insert("totp_enabled".into(), json!(true));
            o.insert("totp_secret_id".into(), json!("dev-secret"));
        }
        // counter for 2026-10-02T00:00:00Z = epoch 1790467200 / 30.
        let now_iso = "2026-10-02T00:00:00+00:00";
        let now_e = epoch(Some(now_iso));
        let counter = (now_e as i64) / 30;
        let code = crate::totp::totp_code_at_counter(TOTP_SECRET, counter as u64);
        assert_eq!(code.len(), 6);
        let g = verify_or_raise_locked(
            &h,
            &mut st,
            &grants,
            "local_once",
            Some(&input(None, Some(&code))),
            false,
            None,
            None,
            None,
            None,
            Some(now_iso),
        )
        .expect("totp grant");
        assert_eq!(g.factor_set, vec!["totp"]);
        assert!(g.totp_verified && !g.password_verified);
        assert_eq!(optional_int(st.get("totp_last_counter")), Some(counter));
        // Recent proof recorded + satisfied for the same session binding.
        assert!(st.get(TOTP_RECENT_STATE_KEY).is_some());
        assert!(recent_totp_satisfied_locked(&h, &st, now_e + 1.0));
        let _ = std::fs::remove_dir_all(&h);
    }

    #[test]
    fn rotate_authentication_state_drops_invalidated_and_advances() {
        let mut st = enabled_state();
        {
            let o = st.as_object_mut().unwrap();
            o.insert("factor_generation".into(), json!(3));
            o.insert("cooldown_expires_at".into(), json!("x"));
            o.insert("session_nonces".into(), json!({}));
            o.insert(TOTP_RECENT_STATE_KEY.into(), json!({}));
            o.insert("enabled".into(), json!(true));
        }
        rotate_authentication_state(&mut st);
        assert_eq!(optional_int(st.get("factor_generation")), Some(4));
        for k in [
            "cooldown_expires_at",
            "session_nonces",
            TOTP_RECENT_STATE_KEY,
        ] {
            assert!(st.get(k).is_none(), "dropped {k}");
        }
        assert_eq!(st.get("enabled"), Some(&json!(true)));
    }

    #[test]
    fn token_urlsafe_lengths_and_charset() {
        let t18 = token_urlsafe(18);
        let t24 = token_urlsafe(24);
        assert_eq!(t18.len(), 24);
        assert_eq!(t24.len(), 32);
        for c in t18.chars().chain(t24.chars()) {
            assert!(c.is_ascii_alphanumeric() || c == '-' || c == '_', "bad {c}");
        }
        assert_ne!(token_urlsafe(18), token_urlsafe(18));
    }
}

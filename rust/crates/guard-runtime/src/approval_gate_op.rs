//! `ApprovalGate` — resident op that runs the `approval_gate.py` free fns
//! inside the resident under the process grant-table lock.
//!
//! IO op: each method opens `guard_home` state (`approval-gate.json`), resolves
//! TOTP secrets via `TotpSecretStore`, and mutates the resident grant table —
//! none of that crosses the wire; the request carries only `params` +
//! `approval_gate_input` + `approval_gate_grant` + scalar flags.

use std::path::{Path, PathBuf};
use std::sync::LazyLock;

use guard_contracts::{
    ApprovalGateGrantWireV1, ApprovalGateInputWireV1, ApprovalGateMethodV1, ApprovalGateRequestV1,
    ApprovalGateResultV1, APPROVAL_GATE_REQUEST_SCHEMA, APPROVAL_GATE_RESULT_SCHEMA,
};
use serde_json::{json, Value};

use crate::approval_gate_consumers as consumers;
use crate::approval_gate_enrollment as enrollment;
use crate::approval_gate_grants::{ApprovalGateErrorV1, ApprovalGateGrantV1, ApprovalGateGrants};
use crate::approval_gate_settings as settings;
use crate::approval_gate_state::{epoch, optional_int, optional_string};
use crate::approval_gate_verify::{verify_or_raise_locked, ApprovalGateInputV1};
use crate::totp::TotpSecretStore;

/// `totp_enabled` — `approval_gate_state.py` predicate; private in each arm so
/// re-declared here (2-line body) rather than widened to `pub`.
fn gate_totp_enabled(state: &Value) -> bool {
    state.get("totp_enabled") == Some(&Value::Bool(true))
}

/// `factor_generation` — `approval_gate_state.py` accessor; private in each arm.
fn gate_factor_generation(state: &Value) -> i64 {
    optional_int(state.get("factor_generation"))
        .unwrap_or(0)
        .max(0)
}

/// One-resident grant table — mirrors Python's module-global `_ACTIVE_GRANTS`.
/// `LazyLock` initialises once per resident process; `Mutex` inside
/// `ApprovalGateGrants` supplies the `_APPROVAL_GATE_LOCK` discipline.
static APPROVAL_GATE_GRANTS: LazyLock<ApprovalGateGrants> = LazyLock::new(ApprovalGateGrants::new);
pub(crate) static PRIVILEGE_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

pub(crate) fn grants() -> &'static ApprovalGateGrants {
    &APPROVAL_GATE_GRANTS
}

fn input_from_wire(w: &ApprovalGateInputWireV1) -> ApprovalGateInputV1 {
    ApprovalGateInputV1 {
        password: w.password.clone(),
        new_password: w.new_password.clone(),
        confirm_password: w.confirm_password.clone(),
        totp_code: w.totp_code.clone(),
        use_cooldown: w.use_cooldown,
        revoke_cooldown: w.revoke_cooldown,
        require_fresh_totp: w.require_fresh_totp,
    }
}

fn grant_from_wire(w: &ApprovalGateGrantWireV1) -> ApprovalGateGrantV1 {
    ApprovalGateGrantV1 {
        grant_id: w.grant_id.clone(),
        purpose: w.purpose.clone(),
        issued_at: w.issued_at.clone(),
        expires_at: w.expires_at.clone(),
        action: w.action.clone(),
        scope: w.scope.clone(),
        subject: w.subject.clone(),
        session_nonce: w.session_nonce.clone(),
        factor_set: w.factor_set.clone(),
        strict: w.strict,
        used_cooldown: w.used_cooldown,
        cooldown_expires_at: w.cooldown_expires_at.clone(),
        password_verified: w.password_verified,
        totp_verified: w.totp_verified,
    }
}

/// `ApprovalGateGrant` → the 15-key dict Python consumers expect (field order
/// matches `approval_gate.py` dataclass declaration order).
fn grant_to_value(g: &ApprovalGateGrantV1) -> Value {
    json!({
        "grant_id": g.grant_id,
        "purpose": g.purpose,
        "issued_at": g.issued_at,
        "expires_at": g.expires_at,
        "action": g.action,
        "scope": g.scope,
        "subject": g.subject,
        "session_nonce": g.session_nonce,
        "factor_set": g.factor_set,
        "strict": g.strict,
        "used_cooldown": g.used_cooldown,
        "cooldown_expires_at": g.cooldown_expires_at,
        "password_verified": g.password_verified,
        "totp_verified": g.totp_verified,
    })
}

fn pstr<'a>(params: Option<&'a Value>, key: &str) -> Option<&'a str> {
    params.and_then(|p| p.get(key)).and_then(Value::as_str)
}

fn totp_state_valid(guard_home: &Path, state: &Value) -> bool {
    match optional_string(state.get("totp_secret_id")) {
        Some(id) => TotpSecretStore::new(guard_home).get_secret(&id).is_some(),
        None => false,
    }
}

fn err(code: &str, message: &str, status: u16) -> ApprovalGateErrorV1 {
    ApprovalGateErrorV1 {
        code: code.to_owned(),
        message: message.to_owned(),
        status,
    }
}

fn missing(field: &str) -> ApprovalGateErrorV1 {
    err(
        "native_approval_gate_invalid",
        &format!("Missing required approval-gate field `{field}`."),
        400,
    )
}

pub(crate) fn evaluate_approval_gate_request(
    request: &ApprovalGateRequestV1,
) -> Result<Vec<u8>, String> {
    let request_sha256 = request_digest(request).map_err(str::to_owned)?;
    let (status, code, error_status, message, payload) = match evaluate(request) {
        Ok(payload) => ("ok".to_owned(), "ok".to_owned(), None, None, Some(payload)),
        Err(e) => (
            "error".to_owned(),
            e.code,
            Some(e.status),
            Some(e.message),
            None,
        ),
    };
    let result = ApprovalGateResultV1 {
        schema: APPROVAL_GATE_RESULT_SCHEMA.to_owned(),
        request_id: request.request_id.clone(),
        request_sha256,
        status,
        code,
        error_status,
        message,
        payload,
    };
    crate::encode_response(&result)
}

fn request_digest(request: &ApprovalGateRequestV1) -> Result<String, &'static str> {
    let material = serde_json::to_value(request).map_err(|_| "native_approval_gate_invalid")?;
    let mut bytes = Vec::new();
    super::context_digest_json::write_canonical_json_with_limit(&material, &mut bytes, usize::MAX)
        .map_err(|_| "native_approval_gate_invalid")?;
    Ok(format!(
        "sha256:{}",
        guard_policy_snapshot::digest_bytes(&bytes)
    ))
}

fn evaluate(request: &ApprovalGateRequestV1) -> Result<Value, ApprovalGateErrorV1> {
    let _privilege_lock = PRIVILEGE_LOCK.lock().map_err(|_| {
        err(
            "native_approval_gate_unavailable",
            "Approval gate lock is unavailable.",
            503,
        )
    })?;
    if request.schema != APPROVAL_GATE_REQUEST_SCHEMA {
        return Err(err(
            "native_approval_gate_schema_mismatch",
            "Approval-gate request schema mismatch.",
            400,
        ));
    }
    let guard_home = PathBuf::from(&request.guard_home);
    let now = request.now.as_deref();
    let params = request.params.as_ref();
    let input = request.approval_gate_input.as_ref().map(input_from_wire);
    let grant = request.approval_gate_grant.as_ref().map(grant_from_wire);
    let input_ref = input.as_ref();
    let grant_ref = grant.as_ref();
    let grants = grants();

    match request.method {
        ApprovalGateMethodV1::PublicConfig => {
            Ok(settings::public_config_locked(&guard_home, now).to_dict())
        }
        ApprovalGateMethodV1::RecentTotpSatisfied => {
            Ok(json!({"satisfied": settings::recent_totp_satisfied(&guard_home, now)}))
        }
        ApprovalGateMethodV1::Verify => {
            let mut state = crate::approval_gate_state::load_state(&guard_home);
            let g = verify_or_raise_locked(
                &guard_home,
                &mut state,
                grants,
                request.purpose.as_deref().unwrap_or("generic"),
                input_ref,
                request.strict,
                pstr(params, "action"),
                pstr(params, "scope"),
                pstr(params, "subject"),
                pstr(params, "session_nonce"),
                now,
            )?;
            Ok(json!({"grant": grant_to_value(&g)}))
        }
        ApprovalGateMethodV1::ValidateGrant => {
            let state = crate::approval_gate_state::load_state(&guard_home);
            grants.validate(
                &request.guard_home,
                grant_ref,
                grant_ref
                    .map(|g| epoch(Some(g.expires_at.as_str())))
                    .unwrap_or(0.0),
                request.purpose.as_deref(),
                request.strict,
                pstr(params, "action"),
                pstr(params, "scope"),
                pstr(params, "subject"),
                pstr(params, "session_nonce"),
                gate_factor_generation(&state),
                gate_totp_enabled(&state),
                totp_state_valid(&guard_home, &state),
                epoch(now),
            )?;
            Ok(json!({"validated": true}))
        }
        ApprovalGateMethodV1::UpdateSettings => {
            let cfg = settings::update_settings(&guard_home, grants, params, grant_ref, now)?;
            Ok(cfg.to_dict())
        }
        ApprovalGateMethodV1::ValidateSettingsUpdate => {
            settings::validate_settings_update(&guard_home, grants, params, grant_ref, now)?;
            Ok(json!({"validated": true}))
        }
        ApprovalGateMethodV1::RevokeCooldown => {
            Ok(settings::revoke_cooldown(&guard_home, now)?.to_dict())
        }
        ApprovalGateMethodV1::UnlockCooldown => {
            let duration = request
                .duration_seconds
                .ok_or_else(|| missing("duration_seconds"))?;
            Ok(settings::unlock_cooldown_locked(&guard_home, duration, input_ref, now)?.to_dict())
        }
        ApprovalGateMethodV1::BeginTotpEnrollment => {
            let label = request.device_label.as_deref().unwrap_or("local-device");
            enrollment::begin_totp_enrollment_locked(&guard_home, grants, input_ref, label, now)
        }
        ApprovalGateMethodV1::ConfirmTotpEnrollment => Ok(
            enrollment::confirm_totp_enrollment_locked(&guard_home, grants, input_ref, now)?
                .to_dict(),
        ),
        ApprovalGateMethodV1::DisableTotp => {
            Ok(enrollment::disable_totp_locked(&guard_home, grants, input_ref, now)?.to_dict())
        }
        ApprovalGateMethodV1::RequireApprovalDecision => {
            let action = pstr(params, "action").ok_or_else(|| missing("action"))?;
            let scope = pstr(params, "scope").ok_or_else(|| missing("scope"))?;
            let g = consumers::require_approval_decision(
                &guard_home,
                grants,
                action,
                scope,
                input_ref,
                grant_ref,
                pstr(params, "subject"),
                pstr(params, "session_nonce"),
                now,
            )?;
            Ok(json!({"grant": g.as_ref().map(grant_to_value)}))
        }
        ApprovalGateMethodV1::RequireHighRisk => {
            let purpose = request
                .purpose
                .as_deref()
                .ok_or_else(|| missing("purpose"))?;
            let g = consumers::require_high_risk(
                &guard_home,
                grants,
                purpose,
                input_ref,
                grant_ref,
                pstr(params, "action"),
                pstr(params, "scope"),
                pstr(params, "subject"),
                pstr(params, "session_nonce"),
                now,
            )?;
            Ok(json!({"grant": g.as_ref().map(grant_to_value)}))
        }
        ApprovalGateMethodV1::RequireExtensionControl => {
            let g = consumers::require_extension_control(
                &guard_home,
                grants,
                input_ref,
                pstr(params, "action").ok_or_else(|| missing("action"))?,
                pstr(params, "subject").ok_or_else(|| missing("subject"))?,
                pstr(params, "session_nonce").ok_or_else(|| missing("session_nonce"))?,
                now,
            )?;
            Ok(json!({"grant": grant_to_value(&g)}))
        }
        ApprovalGateMethodV1::ConsumeExtensionControlGrant => {
            consumers::consume_extension_control_grant(
                &guard_home,
                grants,
                grant_ref.ok_or_else(|| missing("approval_gate_grant"))?,
                pstr(params, "action").ok_or_else(|| missing("action"))?,
                pstr(params, "subject").ok_or_else(|| missing("subject"))?,
                pstr(params, "session_nonce").ok_or_else(|| missing("session_nonce"))?,
                now,
            )?;
            Ok(json!({"consumed": true}))
        }
        ApprovalGateMethodV1::RequireLocalCliTrust => {
            let g = consumers::require_local_cli_trust(
                &guard_home,
                grants,
                input_ref,
                pstr(params, "action").ok_or_else(|| missing("action"))?,
                pstr(params, "subject").ok_or_else(|| missing("subject"))?,
                pstr(params, "session_nonce").ok_or_else(|| missing("session_nonce"))?,
                now,
            )?;
            Ok(json!({"grant": grant_to_value(&g)}))
        }
        ApprovalGateMethodV1::ConsumeLocalCliTrustGrant => {
            consumers::consume_local_cli_trust_grant(
                &guard_home,
                grants,
                grant_ref.ok_or_else(|| missing("approval_gate_grant"))?,
                pstr(params, "action").ok_or_else(|| missing("action"))?,
                pstr(params, "subject").ok_or_else(|| missing("subject"))?,
                pstr(params, "session_nonce").ok_or_else(|| missing("session_nonce"))?,
                now,
            )?;
            Ok(json!({"consumed": true}))
        }
        ApprovalGateMethodV1::RequirePolicyClear => {
            consumers::require_policy_clear(&guard_home, grants, grant_ref, now)?;
            Ok(json!({"ok": true}))
        }
        ApprovalGateMethodV1::RequireSettingsWrite => {
            consumers::require_settings_write(&guard_home, grants, grant_ref, now)?;
            Ok(json!({"ok": true}))
        }
        ApprovalGateMethodV1::RequirePolicyWrite => {
            let action = pstr(params, "action").ok_or_else(|| missing("action"))?;
            let scope = pstr(params, "scope").ok_or_else(|| missing("scope"))?;
            consumers::require_policy_write(&guard_home, grants, action, scope, grant_ref, now)?;
            Ok(json!({"ok": true}))
        }
        ApprovalGateMethodV1::RequireRequestResolution => {
            let action = pstr(params, "action").ok_or_else(|| missing("action"))?;
            let scope = pstr(params, "scope").ok_or_else(|| missing("scope"))?;
            consumers::require_request_resolution(
                &guard_home,
                grants,
                action,
                scope,
                grant_ref,
                now,
            )?;
            Ok(json!({"ok": true}))
        }
        ApprovalGateMethodV1::CreateVerifier => {
            let password = input_ref
                .and_then(|i| i.password.as_deref())
                .or_else(|| pstr(params, "password"))
                .ok_or_else(|| missing("password"))?;
            Ok(settings::create_verifier(password)?)
        }
        ApprovalGateMethodV1::AuditPayload => Ok(json!({"approval_gate": {
            "purpose": request.purpose,
            "satisfied": grant_ref.is_some(),
            "used_cooldown": grant_ref.map(|g| g.used_cooldown).unwrap_or(false),
            "cooldown_expires_at": grant_ref.and_then(|g| g.cooldown_expires_at.clone()),
            "action": pstr(params, "action"),
            "scope": pstr(params, "scope"),
        }})),
    }
}

#[cfg(test)]
#[path = "approval_gate_op_tests.rs"]
mod tests;

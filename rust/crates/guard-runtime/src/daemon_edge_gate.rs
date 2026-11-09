//! The daemon's `require_high_risk` check, sent to the resident's approval
//! gate as the daemon's own client sends it.
//!
//! The edge has a session of its own, so it sends the daemon's session facts
//! from the handshake: a recent TOTP proof binds to the daemon's session, not
//! the edge's. Without them the daemon checks the gate itself.
//!
//! Once the resident may have run the check, the edge answers whatever comes
//! back and never hands the request to the daemon, which would run the check
//! a second time.

use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use guard_contracts::{
    ApprovalGateGrantWireV1, ApprovalGateInputWireV1, ApprovalGateMethodV1, ApprovalGateRequestV1,
    APPROVAL_GATE_REQUEST_SCHEMA, APPROVAL_GATE_RESULT_SCHEMA,
};
use serde_json::{json, Map, Value};

use super::super::ReadConfig;
use crate::approval_gate_verify::input_from_mapping;

const GATE_TIMEOUT: Duration = Duration::from_secs(5);
const GATE_BUDGET_MS: u64 = 5_000;
const STATE_FILE: &str = "approval-gate.json";
const UNPROVISIONED: [&str; 2] = [
    "native_policy_verifier_key_missing",
    "native_resident_state_dir_create_failed",
];

static REQUEST_IDS: AtomicU64 = AtomicU64::new(0);

#[derive(Debug, PartialEq)]
pub(super) enum Gate {
    /// The check passed, with the grant the resident issued: `None` when the
    /// home needs no gate.
    Passed(Option<Box<ApprovalGateGrantWireV1>>),
    /// The status and `ApprovalGateError.to_payload()` body.
    Refused(u16, Map<String, Value>),
}

/// `require_high_risk(guard_home, purpose=..., approval_gate_input=
/// input_from_mapping(payload))`. `None` hands the request to the daemon.
pub(super) fn require_high_risk(
    purpose: &str,
    payload: &Map<String, Value>,
    config: &ReadConfig,
) -> Option<Gate> {
    let input = wire_input(payload);
    call(
        ApprovalGateMethodV1::RequireHighRisk,
        Some(json!({
            "action": null,
            "scope": null,
            "subject": null,
            "session_nonce": null,
        })),
        input,
        None,
        Some(purpose),
        config,
    )
}

/// `require_settings_write(guard_home, approval_gate_grant=grant)`, run
/// after `require_high_risk` passed with that grant.
pub(super) fn require_settings_write(
    grant: Option<Box<ApprovalGateGrantWireV1>>,
    config: &ReadConfig,
) -> Option<Gate> {
    let granted = grant.is_some();
    let answer = call(
        ApprovalGateMethodV1::RequireSettingsWrite,
        None,
        None,
        grant.map(|grant| *grant),
        None,
        config,
    );
    // A grant means the gate is set up, so a check that went unanswered
    // fails closed rather than letting the write through.
    match answer {
        None if granted => Some(unavailable()),
        answer => answer,
    }
}

/// One configuration method (`_native`): the resident's `payload`, or the
/// refusal to answer. `None` goes to the daemon before the resident ran.
/// No answer at all fails closed, as the daemon's client does.
pub(super) fn operate(
    method: ApprovalGateMethodV1,
    params: Option<Value>,
    payload: &Map<String, Value>,
    device_label: Option<&str>,
    config: &ReadConfig,
) -> Option<Result<Map<String, Value>, (u16, Map<String, Value>)>> {
    let input = wire_input(payload);
    let (request, digest, encoded) =
        build(method, params, input, None, None, device_label, config)?;
    let refusal = |gate: Gate| match gate {
        Gate::Refused(status, body) => Err((status, body)),
        Gate::Passed(_) => Ok(Map::new()),
    };
    let Some(Value::Object(envelope)) = send(&encoded, config) else {
        return Some(refusal(unavailable()));
    };
    if envelope.get("schema").and_then(Value::as_str) != Some(APPROVAL_GATE_RESULT_SCHEMA)
        || envelope.get("request_id").and_then(Value::as_str) != Some(request.request_id.as_str())
        || envelope.get("request_sha256").and_then(Value::as_str) != Some(digest.as_str())
    {
        return Some(refusal(unavailable()));
    }
    Some(match envelope.get("status").and_then(Value::as_str) {
        Some("error") => refusal(refused(&envelope).unwrap_or_else(unavailable)),
        Some("ok") => match envelope.get("payload") {
            Some(Value::Object(answer)) => Ok(answer.clone()),
            _ => refusal(unavailable()),
        },
        _ => refusal(unavailable()),
    })
}

/// `ApprovalGatePublicConfig.to_dict()` from a resident answer: `None` when
/// a field `config_from_wire` needs is missing.
pub(super) fn public_config(answer: &Map<String, Value>) -> Option<Value> {
    let flag = |key: &str| answer.get(key).map(truthy);
    let optional = |key: &str| answer.get(key).cloned().unwrap_or(Value::Null);
    Some(json!({
        "enabled": flag("enabled")?,
        "configured": flag("configured")?,
        "cooldown_seconds": answer.get("cooldown_seconds")?.as_i64()?,
        "cooldown_active": flag("cooldown_active")?,
        "cooldown_expires_at": optional("cooldown_expires_at"),
        "locked_until": optional("locked_until"),
        "fail_closed": flag("fail_closed")?,
        "strict_all_decisions": flag("strict_all_decisions")?,
        "totp_enabled": flag("totp_enabled")?,
        "totp_pending": flag("totp_pending")?,
        "totp_recent_satisfied": flag("totp_recent_satisfied").unwrap_or(false),
    }))
}

fn truthy(value: &Value) -> bool {
    match value {
        Value::Null => false,
        Value::Bool(flag) => *flag,
        Value::Number(number) => number.as_f64() != Some(0.0),
        Value::String(text) => !text.is_empty(),
        Value::Array(items) => !items.is_empty(),
        Value::Object(map) => !map.is_empty(),
    }
}

fn wire_input(payload: &Map<String, Value>) -> Option<ApprovalGateInputWireV1> {
    input_from_mapping(Some(&Value::Object(payload.clone()))).map(|input| ApprovalGateInputWireV1 {
        password: input.password,
        new_password: input.new_password,
        confirm_password: input.confirm_password,
        totp_code: input.totp_code,
        use_cooldown: input.use_cooldown,
        revoke_cooldown: input.revoke_cooldown,
        require_fresh_totp: input.require_fresh_totp,
    })
}

type Built = (ApprovalGateRequestV1, String, Vec<u8>);

fn build(
    method: ApprovalGateMethodV1,
    params: Option<Value>,
    approval_gate_input: Option<ApprovalGateInputWireV1>,
    approval_gate_grant: Option<ApprovalGateGrantWireV1>,
    purpose: Option<&str>,
    device_label: Option<&str>,
    config: &ReadConfig,
) -> Option<Built> {
    let session_signals = config.session_signals.clone()?;
    let request = ApprovalGateRequestV1 {
        schema: APPROVAL_GATE_REQUEST_SCHEMA.to_owned(),
        request_id: format!(
            "daemon-edge-ag-{}",
            REQUEST_IDS.fetch_add(1, Ordering::Relaxed)
        ),
        guard_home: config.guard_home.clone(),
        method,
        params,
        approval_gate_input,
        approval_gate_grant,
        strict: false,
        purpose: purpose.map(str::to_owned),
        now: None,
        duration_seconds: None,
        device_label: device_label.map(str::to_owned),
        session_signals,
    };
    let digest = crate::approval_gate_op::request_digest(&request).ok()?;
    let encoded = serde_json::to_vec(&json!({
        "operation": "approval_gate",
        "deadline_budget_ms": GATE_BUDGET_MS,
        "request": request,
    }))
    .ok()?;
    Some((request, digest, encoded))
}

fn send(encoded: &[u8], config: &ReadConfig) -> Option<Value> {
    std::fs::canonicalize(Path::new(&config.guard_home).join("native-runtime"))
        .ok()
        .and_then(|state_dir| {
            crate::managed_resident::client_request(&state_dir, encoded, GATE_TIMEOUT).ok()
        })
        .and_then(|output| serde_json::from_slice::<Value>(&output).ok())
}

fn call(
    method: ApprovalGateMethodV1,
    params: Option<Value>,
    approval_gate_input: Option<ApprovalGateInputWireV1>,
    approval_gate_grant: Option<ApprovalGateGrantWireV1>,
    purpose: Option<&str>,
    config: &ReadConfig,
) -> Option<Gate> {
    let grant_expected = method == ApprovalGateMethodV1::RequireHighRisk;
    config.session_signals.as_ref()?;
    // A state file that cannot be checked goes to the daemon, before the
    // resident has run anything.
    let configured = Path::new(&config.guard_home)
        .join(STATE_FILE)
        .try_exists()
        .ok()?;
    let (request, digest, encoded) = build(
        method,
        params,
        approval_gate_input,
        approval_gate_grant,
        purpose,
        None,
        config,
    )?;
    let envelope = send(&encoded, config);
    match envelope {
        Some(envelope) => answer(
            &envelope,
            &request.request_id,
            &digest,
            configured,
            grant_expected,
        ),
        // Without an answer a home that never set the gate up goes to the
        // daemon, and a configured one fails closed as the daemon would.
        None if configured => Some(unavailable()),
        None => None,
    }
}

/// How the daemon's client reads the resident's answer.
fn answer(
    envelope: &Value,
    request_id: &str,
    digest: &str,
    configured: bool,
    grant_expected: bool,
) -> Option<Gate> {
    let Some(envelope) = envelope.as_object() else {
        return Some(unavailable());
    };
    let error = envelope.get("error").and_then(Value::as_str);
    if envelope.len() == 2
        && envelope.contains_key("retryable")
        && error.is_some_and(|error| UNPROVISIONED.contains(&error))
    {
        // No authority here: an unset gate passes, and a configured home goes
        // to the daemon, whose client may provision the verifier key first.
        return (!configured).then_some(Gate::Passed(None));
    }
    if envelope.get("schema").and_then(Value::as_str) != Some(APPROVAL_GATE_RESULT_SCHEMA)
        || envelope.get("request_id").and_then(Value::as_str) != Some(request_id)
        || envelope.get("request_sha256").and_then(Value::as_str) != Some(digest)
    {
        return Some(unavailable());
    }
    Some(match envelope.get("status").and_then(Value::as_str) {
        Some("error") => refused(envelope).unwrap_or_else(unavailable),
        // A consumer check answers with no grant; the daemon ignores its
        // payload.
        Some("ok") if !grant_expected => Gate::Passed(None),
        Some("ok") => match envelope
            .get("payload")
            .and_then(|payload| payload.get("grant"))
        {
            Some(Value::Null) => Gate::Passed(None),
            Some(grant @ Value::Object(_)) => {
                match serde_json::from_value::<ApprovalGateGrantWireV1>(grant.clone()) {
                    Ok(grant) => Gate::Passed(Some(Box::new(grant))),
                    Err(_) => unavailable(),
                }
            }
            _ => unavailable(),
        },
        _ => unavailable(),
    })
}

/// `ApprovalGateError(code or "approval_gate_required", message or "Approval
/// gate check failed.", status=error_status or 403)`.
fn refused(envelope: &Map<String, Value>) -> Option<Gate> {
    let text = |key, fallback: &str| match envelope.get(key) {
        None | Some(Value::Null) => Some(fallback.to_owned()),
        Some(Value::String(value)) if value.is_empty() => Some(fallback.to_owned()),
        Some(Value::String(value)) => Some(value.clone()),
        Some(_) => None,
    };
    let status = match envelope.get("error_status") {
        None | Some(Value::Null) => 403,
        Some(value) => match value.as_u64()? {
            0 => 403,
            status @ 100..=599 => status as u16,
            _ => return None,
        },
    };
    let mut body = Map::new();
    body.insert(
        "error".to_owned(),
        Value::String(text("code", "approval_gate_required")?),
    );
    body.insert(
        "message".to_owned(),
        Value::String(text("message", "Approval gate check failed.")?),
    );
    Some(Gate::Refused(status, body))
}

pub(super) fn unavailable() -> Gate {
    let mut body = Map::new();
    body.insert(
        "error".to_owned(),
        Value::String("native_approval_gate_unavailable".to_owned()),
    );
    body.insert(
        "message".to_owned(),
        Value::String(
            "The native approval authority did not answer. Retry the approval.".to_owned(),
        ),
    );
    Gate::Refused(503, body)
}

#[cfg(test)]
#[path = "daemon_edge_gate_tests.rs"]
mod tests;

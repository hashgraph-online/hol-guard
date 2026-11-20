//! Yanez Pulse on the edge's high-risk check, as the daemon's
//! `require_high_risk` ran it through `_with_pulse`.
//!
//! A settings write names its change (`settings_change`), so the resident
//! binds the grant, and any YID app approval, to exactly that change. When
//! the caller asks to approve in the YID app (`approval_gate_pulse`) and the
//! gate needs Pulse, the edge asks the resident for a Pulse request for the
//! same action and answers `202` with it. The caller polls the request and
//! sends the write again with `approval_pulse_request_id`; the resident then
//! checks the approved receipt against the action it is granting.

use std::time::Duration;

use guard_contracts::{ApprovalGateInputWireV1, ApprovalGateMethodV1};
use serde_json::{json, Map, Value};

use super::super::super::ReadConfig;
use super::{call_with, operate_with, wire_input, Gate, Options, GATE_TIMEOUT};

/// `_PULSE_TIMEOUT_SECONDS`: a Pulse call waits on the Yanez server.
const PULSE_TIMEOUT: Duration = Duration::from_secs(9);
const PULSE_REQUIRED: &str = "approval_gate_pulse_required";
const PULSE_PENDING: &str = "approval_gate_pulse_pending";
const PENDING_MESSAGE: &str = "Approve this action in the YID app, then submit it again.";

/// `require_high_risk` for `purpose`, bound to `settings_change` when the
/// write names one. `None` hands the request to the daemon.
pub(in super::super) fn require_high_risk_for(
    purpose: &str,
    payload: &Map<String, Value>,
    settings_change: Option<Value>,
    config: &ReadConfig,
) -> Option<Gate> {
    let mut params = json!({
        "action": null,
        "scope": null,
        "subject": null,
        "session_nonce": null,
    });
    if let Some(change) = settings_change {
        params["settings_change"] = change;
    }
    let input = wire_input(payload);
    let request_id = input
        .as_ref()
        .is_some_and(|input| input.pulse_request_id.is_some());
    let checked = call_with(
        ApprovalGateMethodV1::RequireHighRisk,
        Some(params.clone()),
        input.clone(),
        None,
        Some(purpose),
        if request_id {
            PULSE_TIMEOUT
        } else {
            GATE_TIMEOUT
        },
        config,
    )?;
    if wants_pulse(payload) && !request_id && needs_pulse(&checked) {
        return Some(deferred(purpose, params, input, config));
    }
    Some(checked)
}

/// `input_from_mapping`'s `pulse_mode == "defer"`: the caller asked to
/// approve in the YID app.
fn wants_pulse(payload: &Map<String, Value>) -> bool {
    payload.get("approval_gate_pulse") == Some(&Value::Bool(true))
        || payload
            .get("approval_gate")
            .and_then(|gate| gate.get("pulse"))
            == Some(&Value::Bool(true))
}

fn needs_pulse(checked: &Gate) -> bool {
    matches!(checked, Gate::Refused(_, body)
        if body.get("error").and_then(Value::as_str) == Some(PULSE_REQUIRED))
}

/// `request_pulse_approval(strict=True)` for the same action. An open Pulse
/// cooldown that covers it runs the check again; otherwise the answer is the
/// `202` with the request to approve.
fn deferred(
    purpose: &str,
    params: Value,
    input: Option<ApprovalGateInputWireV1>,
    config: &ReadConfig,
) -> Gate {
    let options = Options {
        purpose: Some(purpose),
        strict: true,
        timeout: PULSE_TIMEOUT,
    };
    let request = operate_with(
        ApprovalGateMethodV1::PulseRequest,
        Some(params.clone()),
        None,
        options,
        None,
        config,
    );
    let request = match request {
        Some(Ok(request)) => request,
        Some(Err((status, body))) => return Gate::Refused(status, body),
        None => return super::unavailable(),
    };
    if request.get("status").and_then(Value::as_str) == Some("cooldown_covered") {
        return call_with(
            ApprovalGateMethodV1::RequireHighRisk,
            Some(params),
            input,
            None,
            Some(purpose),
            GATE_TIMEOUT,
            config,
        )
        .unwrap_or_else(super::unavailable);
    }
    pending(&request)
}

/// `ApprovalGateError("approval_gate_pulse_pending", status=202).to_payload()`.
fn pending(request: &Map<String, Value>) -> Gate {
    let field = |key: &str| request.get(key).cloned().unwrap_or(Value::Null);
    let mut body = Map::new();
    body.insert("pulse_request_id".to_owned(), field("request_id"));
    body.insert("pulse_match_code".to_owned(), field("match_code"));
    body.insert("pulse_decide_by".to_owned(), field("decide_by"));
    body.insert("error".to_owned(), Value::from(PULSE_PENDING));
    body.insert("message".to_owned(), Value::from(PENDING_MESSAGE));
    Gate::Refused(202, body)
}

#[cfg(test)]
#[path = "daemon_edge_gate_pulse_tests.rs"]
mod tests;

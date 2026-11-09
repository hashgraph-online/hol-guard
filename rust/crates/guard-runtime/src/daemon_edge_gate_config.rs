//! `POST /v1/approval-gate/cooldown/revoke` and
//! `POST /v1/approval-gate/totp/{enroll,verify,disable}`: one resident
//! configuration call each, answered with the daemon's settings payload and
//! the gate's new public configuration.

use serde_json::{Map, Value};

use guard_contracts::ApprovalGateMethodV1;

use super::super::settings::{response, Loaded};
use super::super::ReadConfig;
use super::gate::{self, Gate};
use super::DROPPED;

#[derive(Debug, PartialEq)]
pub(super) enum Route {
    RevokeCooldown,
    Enroll,
    Verify,
    Disable,
}

impl Route {
    pub(super) fn parse(method: &str, path: &str) -> Option<Self> {
        if method != "POST" {
            return None;
        }
        Some(match path {
            "/v1/approval-gate/cooldown/revoke" => Self::RevokeCooldown,
            "/v1/approval-gate/totp/enroll" => Self::Enroll,
            "/v1/approval-gate/totp/verify" => Self::Verify,
            "/v1/approval-gate/totp/disable" => Self::Disable,
            _ => return None,
        })
    }
}

fn refusal(status: u16, body: Map<String, Value>) -> (u16, Value) {
    (status, Value::Object(body))
}

/// `_settings_response_payload` with `settings["approval_gate"]` replaced.
fn settings_with(config: &ReadConfig, approval_gate: Value) -> (u16, Value) {
    let guard_home = std::path::Path::new(&config.guard_home);
    let Some((status, mut body)) =
        Loaded::read(guard_home).and_then(|loaded| response(config, &loaded))
    else {
        return (DROPPED, Value::Null);
    };
    match body.get_mut("settings").and_then(Value::as_object_mut) {
        Some(settings) => {
            settings.insert("approval_gate".to_owned(), approval_gate);
            (status, body)
        }
        None => (DROPPED, Value::Null),
    }
}

/// The resident answer as a public config, or the daemon's
/// `native_approval_gate_unavailable` when it does not read as one.
fn config_or_unavailable(answer: &Map<String, Value>) -> Result<Value, (u16, Value)> {
    gate::public_config(answer).ok_or_else(|| match gate::unavailable() {
        Gate::Refused(status, body) => refusal(status, body),
        Gate::Passed(_) => (DROPPED, Value::Null),
    })
}

/// `None` goes to the daemon before the resident has run.
pub(super) fn respond(
    route: &Route,
    payload: &Map<String, Value>,
    config: &ReadConfig,
) -> Option<(u16, Value)> {
    // The answer reads the gate under the daemon's session.
    config.session_signals.as_ref()?;
    let empty = Map::new();
    let (method, input, device_label) = match route {
        Route::RevokeCooldown => {
            match gate::require_high_risk("settings_write", payload, config)? {
                Gate::Refused(status, body) => return Some(refusal(status, body)),
                Gate::Passed(_) => {}
            }
            (ApprovalGateMethodV1::RevokeCooldown, &empty, None)
        }
        Route::Enroll => {
            let label = match payload.get("device_label") {
                Some(Value::String(label)) if !label.trim().is_empty() => label.trim().to_owned(),
                _ => "local-device".to_owned(),
            };
            (
                ApprovalGateMethodV1::BeginTotpEnrollment,
                payload,
                Some(label),
            )
        }
        Route::Verify => (ApprovalGateMethodV1::ConfirmTotpEnrollment, payload, None),
        Route::Disable => (ApprovalGateMethodV1::DisableTotp, payload, None),
    };
    let answer = match gate::operate(method, None, input, device_label.as_deref(), config) {
        // The high-risk check has run, so nothing goes to the daemon now.
        None => Err(match gate::unavailable() {
            Gate::Refused(status, body) => refusal(status, body),
            Gate::Passed(_) => (DROPPED, Value::Null),
        }),
        Some(Err((status, body))) => Err(refusal(status, body)),
        Some(Ok(answer)) => Ok(answer),
    };
    let answer = match answer {
        Ok(answer) => answer,
        Err(refused) => return Some(refused),
    };
    if *route != Route::Enroll {
        return Some(match config_or_unavailable(&answer) {
            Ok(gate_config) => settings_with(config, gate_config),
            Err(refused) => refused,
        });
    }
    // `approval_gate_public_config(guard_home)` after the enrollment began.
    let public = match gate::operate(
        ApprovalGateMethodV1::PublicConfig,
        None,
        &empty,
        None,
        config,
    ) {
        Some(Ok(public)) => public,
        Some(Err((status, body))) => return Some(refusal(status, body)),
        None => return Some((DROPPED, Value::Null)),
    };
    let gate_config = match config_or_unavailable(&public) {
        Ok(gate_config) => gate_config,
        Err(refused) => return Some(refused),
    };
    let (status, mut body) = settings_with(config, gate_config);
    if let Some(body) = body.as_object_mut() {
        body.insert("enrollment".to_owned(), Value::Object(answer));
    }
    Some((status, body))
}

#[cfg(all(test, unix))]
#[path = "daemon_edge_gate_config_tests.rs"]
mod tests;

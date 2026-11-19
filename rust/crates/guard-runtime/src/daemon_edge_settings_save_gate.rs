//! What a native settings save hands the approval gate: the proof it offers
//! and the change it names, as the daemon's `settings_input_from_payload` and
//! `require_high_risk(settings_change=...)` built them.

use serde_json::{json, Map, Value};

use super::truthy;

/// The dashboard's Pulse fields on a gated write.
const PULSE_KEYS: [&str; 2] = ["approval_gate_pulse", "approval_pulse_request_id"];

/// The gate input of a settings save. `require_high_risk` reads the proof
/// from the top level only when one is offered there; otherwise from
/// `settings.approval_gate`. The dashboard's Pulse fields are top-level, like
/// on every other gated route (`settings_input_from_payload`).
pub(super) fn save_gate_input(
    json_payload: &Map<String, Value>,
    gate_payload: Option<&Value>,
) -> Map<String, Value> {
    let offered = ["approval_password", "approval_totp_code"]
        .iter()
        .any(|key| json_payload.get(*key).is_some_and(truthy));
    let mut input = match gate_payload {
        _ if offered => json_payload.clone(),
        Some(gate) => Map::from_iter([("approval_gate".to_owned(), gate.clone())]),
        None => Map::new(),
    };
    for key in PULSE_KEYS {
        if let Some(value) = json_payload.get(key) {
            input.insert(key.to_owned(), value.clone());
        }
    }
    input
}

/// The change a settings save names, so one approval (and any YID app
/// approval) covers exactly these settings and cannot be sent again with
/// different ones. The resident derives the binding from it.
pub(super) fn save_change(json_payload: &Map<String, Value>) -> Value {
    json!({
        "kind": "save",
        "settings": json_payload.get("settings").cloned().unwrap_or(Value::Null),
    })
}

#[cfg(test)]
#[path = "daemon_edge_settings_save_gate_tests.rs"]
mod tests;

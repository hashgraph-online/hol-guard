//! The operation a settings-write grant is bound to, named by the resident.
//!
//! A Pulse-protected settings change is bound to its own `action` and
//! `subject`, so an approval for one change (in the YID app or as a grant)
//! cannot complete another. The caller describes the change itself as
//! `params.settings_change`, and the resident derives the binding from it, so
//! what an approval for a settings change covers is decided here. A request
//! that names a change may not also name `action` or `subject`.
//!
//! A settings save is bound to a keyed digest of the change (the daemon's
//! auth token is the key), so a new password inside the change cannot be
//! guessed from a subject that reaches a log. How the change is approved
//! (the current password, a code, a Pulse request) is not part of it.

use std::path::Path;

use hmac::{Hmac, Mac};
use serde_json::{Map, Value};
use sha2::Sha256;

use crate::approval_gate_grants::ApprovalGateErrorV1;
use crate::approval_gate_pulse_disable::{PULSE_DISABLE_ACTION, PULSE_DISABLE_SUBJECT};

pub(crate) const SETTINGS_CHANGE_PARAM: &str = "settings_change";
pub(crate) const SETTINGS_SAVE_ACTION: &str = "settings_save";
pub(crate) const UPDATE_CHANNEL_ACTION: &str = "settings_update_channel";
pub(crate) const SETTINGS_RESET_ACTION: &str = "settings_reset";
const SETTINGS_WRITE_PURPOSE: &str = "settings_write";
/// The approval-gate fields that say how a change is approved, not what it is.
const PROOF_KEYS: [&str; 6] = [
    "password",
    "current_password",
    "totp_code",
    "pulse",
    "pulse_request_id",
    "use_cooldown",
];

/// The params with the derived `action` and `subject` in place of
/// `settings_change`, or `None` when the request names no settings change.
///
/// `settings_scoped` is a `settings_write` request or the settings-write
/// check. Only those may carry a settings change.
pub(crate) fn bind(
    guard_home: &Path,
    settings_scoped: bool,
    params: Option<&Value>,
) -> Result<Option<Value>, ApprovalGateErrorV1> {
    let Some(params) = params.and_then(Value::as_object) else {
        return Ok(None);
    };
    let Some(change) = params
        .get(SETTINGS_CHANGE_PARAM)
        .filter(|change| !change.is_null())
    else {
        return Ok(None);
    };
    if !settings_scoped {
        return Err(invalid("Only a settings write names a settings change."));
    }
    let named = |key: &str| params.get(key).is_some_and(|value| !value.is_null());
    if named("action") || named("subject") {
        return Err(invalid(
            "A settings change is approved under the binding Guard derives from it.",
        ));
    }
    let (action, subject) = binding(guard_home, change)?;
    let mut bound: Map<String, Value> = params
        .iter()
        .filter(|(key, _)| key.as_str() != SETTINGS_CHANGE_PARAM)
        .map(|(key, value)| (key.clone(), value.clone()))
        .collect();
    bound.insert("action".to_owned(), Value::String(action));
    bound.insert("subject".to_owned(), Value::String(subject));
    Ok(Some(Value::Object(bound)))
}

/// Whether a request is a settings write, by purpose.
pub(crate) fn is_settings_write(purpose: Option<&str>) -> bool {
    purpose == Some(SETTINGS_WRITE_PURPOSE)
}

/// The `action` and `subject` one settings change is approved under.
fn binding(guard_home: &Path, change: &Value) -> Result<(String, String), ApprovalGateErrorV1> {
    let change = change
        .as_object()
        .ok_or_else(|| invalid("A settings change is an object."))?;
    match change.get("kind").and_then(Value::as_str) {
        Some("save") => {
            let settings = change
                .get("settings")
                .ok_or_else(|| invalid("A settings save names its settings."))?;
            Ok((
                SETTINGS_SAVE_ACTION.to_owned(),
                save_subject(guard_home, settings)?,
            ))
        }
        Some("update_channel") => {
            let channel = change
                .get("update_channel")
                .ok_or_else(|| invalid("A channel switch names its channel."))?;
            Ok((
                UPDATE_CHANNEL_ACTION.to_owned(),
                format!("update_channel:{}", canonical(channel)?),
            ))
        }
        Some("reset") => Ok((
            SETTINGS_RESET_ACTION.to_owned(),
            SETTINGS_RESET_ACTION.to_owned(),
        )),
        Some("pulse_disable") => Ok((
            PULSE_DISABLE_ACTION.to_owned(),
            PULSE_DISABLE_SUBJECT.to_owned(),
        )),
        _ => Err(invalid("Unknown settings change.")),
    }
}

/// `settings:<hmac-sha256>` of the change without its proof fields.
fn save_subject(guard_home: &Path, settings: &Value) -> Result<String, ApprovalGateErrorV1> {
    let mut changes = settings.as_object().cloned().unwrap_or_default();
    if let Some(Value::Object(gate)) = changes.get_mut("approval_gate") {
        gate.retain(|name, _| !PROOF_KEYS.contains(&name.as_str()));
    }
    let key = crate::daemon_policy_authority::load_guard_daemon_auth_token(guard_home)
        .unwrap_or_default();
    Ok(format!(
        "settings:{}",
        keyed_digest(key.as_bytes(), &canonical(&Value::Object(changes))?)
    ))
}

fn keyed_digest(key: &[u8], message: &str) -> String {
    let Ok(mut mac) = Hmac::<Sha256>::new_from_slice(key) else {
        unreachable!("HMAC accepts a key of any length");
    };
    mac.update(message.as_bytes());
    hex::encode(mac.finalize().into_bytes())
}

fn canonical(value: &Value) -> Result<String, ApprovalGateErrorV1> {
    let mut bytes = Vec::new();
    crate::context_digest_json::write_canonical_json_with_limit(value, &mut bytes, usize::MAX)
        .map_err(|_| invalid("A settings change must be plain JSON."))?;
    String::from_utf8(bytes).map_err(|_| invalid("A settings change must be plain JSON."))
}

fn invalid(message: &str) -> ApprovalGateErrorV1 {
    ApprovalGateErrorV1 {
        code: "approval_gate_settings_change_invalid".to_owned(),
        message: message.to_owned(),
        status: 400,
    }
}

#[cfg(test)]
#[path = "approval_gate_settings_binding_tests.rs"]
mod tests;

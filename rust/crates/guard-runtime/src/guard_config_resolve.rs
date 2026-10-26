//! `guard-config-resolve --stdin`: decisions derived from a loaded Guard
//! configuration.
//!
//! `guard-config-load` produces the configuration; this command answers what
//! callers used to recalculate from it in Python:
//!
//! - `risk_actions` resolves every risk class for one harness from the
//!   projected configuration through the shared resolver, so the CLI, the
//!   dashboard and the resident read one table.
//! - `overlay` composes a synced cloud policy payload onto a loaded
//!   configuration and re-applies the managed policy, returning the fields
//!   that composition decides. Without a payload it only re-applies the
//!   managed policy.
//!
//! Both are pure functions of the request; nothing on disk is read.

use std::collections::BTreeMap;
use std::io::Read;

use guard_command::action_lattice::normalize_guard_action;
use guard_command::effect_decision::GuardAction;
use guard_command::local_supply_chain::VALID_RISK_ACTION_KEYS;
use guard_contracts::RiskActionConfigV1;
use serde::Deserialize;
use serde_json::{json, Map, Value};

use crate::guard_config_coerce as coerce;
use crate::guard_config_harness as harness;
use crate::guard_config_managed::{apply_managed_policy, ManagedInput};
use crate::package_authority_config as base;
use crate::risk_action::configured_risk_action;

const SCHEMA: &str = "guard-config-resolve.v1";
const MAX_REQUEST_BYTES: u64 = 4 * 1024 * 1024;
const INVALID: &str = "guard_config_request_invalid";

/// The action fields a synced payload may set, with their cloud spelling.
const SYNCED_ACTION_FIELDS: [(&str, &str); 5] = [
    ("default_action", "defaultAction"),
    ("unknown_publisher_action", "unknownPublisherAction"),
    ("changed_hash_action", "changedHashAction"),
    ("new_network_domain_action", "newNetworkDomainAction"),
    ("subprocess_action", "subprocessAction"),
];

/// The local settings a managed policy is composed onto.
const MANAGED_LOCAL_FIELDS: [&str; 10] = [
    "mode",
    "security_level",
    "default_action",
    "unknown_publisher_action",
    "changed_hash_action",
    "new_network_domain_action",
    "subprocess_action",
    "telemetry",
    "sync",
    "receipt_redaction_level",
];

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Request {
    schema: String,
    op: String,
    /// `risk_actions`: the projected configuration.
    #[serde(default)]
    facts: Option<RiskActionConfigV1>,
    /// `risk_actions`: the harness to resolve for, spelled as the caller does.
    #[serde(default)]
    harness: Option<String>,
    /// `overlay`: the loaded configuration fields.
    #[serde(default)]
    config: Option<Map<String, Value>>,
    /// `overlay`: the synced cloud policy payload, absent to only re-apply
    /// the managed policy.
    #[serde(default)]
    payload: Option<Map<String, Value>>,
    /// `overlay`: the managed policy the loaded configuration carries.
    #[serde(default)]
    managed: Option<ManagedInput>,
}

pub(crate) fn is_command(command: &str) -> bool {
    command == "guard-config-resolve"
}

pub(crate) fn run_command(reader: impl Read) -> Result<Vec<u8>, String> {
    let mut bytes = Vec::new();
    reader
        .take(MAX_REQUEST_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| "guard_config_request_unreadable".to_owned())?;
    if bytes.len() as u64 > MAX_REQUEST_BYTES {
        return Err("guard_config_request_too_large".to_owned());
    }
    let request: Request = serde_json::from_slice(&bytes).map_err(|_| INVALID.to_owned())?;
    if request.schema != SCHEMA {
        return Err(INVALID.to_owned());
    }
    let response = match resolve(&request) {
        Ok(result) => json!({"ok": true, "result": result}),
        Err(reason) => json!({"ok": false, "error": reason}),
    };
    serde_json::to_vec(&response).map_err(|_| "guard_config_response_encode_failed".to_owned())
}

fn resolve(request: &Request) -> Result<Value, &'static str> {
    match request.op.as_str() {
        "risk_actions" => {
            let facts = request.facts.as_ref().ok_or(INVALID)?;
            Ok(json!({
                "risk_actions": risk_actions(facts, request.harness.as_deref()),
            }))
        }
        "overlay" => {
            let config = request.config.as_ref().ok_or(INVALID)?;
            Ok(json!({
                "config": overlay(config, request.payload.as_ref(), request.managed.as_ref()),
            }))
        }
        _ => Err(INVALID),
    }
}

/// The action every risk class resolves to for `harness`. A class nothing
/// configures and no default names is left out.
pub(crate) fn risk_actions(
    facts: &RiskActionConfigV1,
    harness: Option<&str>,
) -> BTreeMap<String, String> {
    VALID_RISK_ACTION_KEYS
        .iter()
        .filter_map(|class| {
            configured_risk_action(facts, class, harness)
                .map(|action| ((*class).to_owned(), action))
        })
        .collect()
}

/// An absent or null value: the caller keeps its current setting.
fn present(value: Option<&Value>) -> Option<&Value> {
    value.filter(|value| !value.is_null())
}

fn text<'a>(config: &'a Map<String, Value>, key: &str, default: &'a str) -> &'a str {
    config.get(key).and_then(Value::as_str).unwrap_or(default)
}

/// A loaded action field; the loader only stores canonical actions, so
/// anything else fails closed.
fn current_action(config: &Map<String, Value>, key: &str) -> GuardAction {
    normalize_guard_action(
        config.get(key).unwrap_or(&Value::Null),
        GuardAction::RequireReapproval,
    )
}

/// `_coerce_loaded_guard_action_or_default`.
fn action_or(value: Option<&Value>, fallback: GuardAction) -> &'static str {
    coerce::action_or_default(present(value), fallback).as_str()
}

/// `_coerce_loaded_guard_mode` with the current mode as the fallback.
fn mode_or(value: Option<&Value>, fallback: &str) -> String {
    match value.and_then(Value::as_str) {
        Some(mode @ ("observe" | "prompt" | "enforce")) => mode.to_owned(),
        _ => fallback.to_owned(),
    }
}

fn map_or_empty(value: Option<&Value>) -> Value {
    match value {
        None | Some(Value::Null) => Value::Object(Map::new()),
        Some(other) => other.clone(),
    }
}

/// The synced cloud policy over the loaded configuration. Watch is never
/// switched off from the cloud: an observing install keeps its mode.
fn synced(config: &Map<String, Value>, payload: &Map<String, Value>) -> Map<String, Value> {
    let mut next = config.clone();
    if text(config, "mode", "prompt") != "observe" {
        if let Some(mode @ ("observe" | "prompt" | "enforce")) =
            payload.get("mode").and_then(Value::as_str)
        {
            next.insert("mode".to_owned(), Value::from(mode));
        }
    }
    for (field, key) in SYNCED_ACTION_FIELDS {
        let action = action_or(payload.get(key), current_action(config, field));
        next.insert(field.to_owned(), Value::from(action));
    }
    if let Some(Value::Bool(flag)) = payload.get("syncEnabled") {
        next.insert("sync".to_owned(), Value::Bool(*flag));
    }
    if let Some(level @ ("full" | "partial" | "none")) =
        payload.get("receiptRedactionLevel").and_then(Value::as_str)
    {
        next.insert("receipt_redaction_level".to_owned(), Value::from(level));
    }
    next
}

/// `_reapply_managed_config`: compose the managed policy onto the local
/// settings and derive the posture the composition implies.
fn reapply_managed(config: &Map<String, Value>, policy: &ManagedInput) -> Map<String, Value> {
    let mut local = Map::new();
    for key in MANAGED_LOCAL_FIELDS {
        local.insert(
            key.to_owned(),
            config.get(key).cloned().unwrap_or(Value::Null),
        );
    }
    for key in ["risk_actions", "harness_risk_actions"] {
        local.insert(key.to_owned(), map_or_empty(config.get(key)));
    }
    if config.get("protection_posture_explicit") == Some(&Value::Bool(true)) {
        if let Some(posture) = config.get("protection_posture") {
            local.insert("protection_posture".to_owned(), posture.clone());
        }
    }
    let composed = apply_managed_policy(&local, policy);
    let get = |key: &str| composed.get(key);
    let mode = mode_or(get("mode"), text(config, "mode", "prompt"));
    let security_level = base::coerce_security_level(get("security_level"));
    let composed_posture = get("protection_posture").and_then(harness::normalize_posture);
    let managed_locks_level = config
        .get("managed_locked_settings")
        .and_then(Value::as_array)
        .is_some_and(|keys| {
            keys.iter()
                .any(|key| key.as_str() == Some("security_level"))
        });
    let derived = base::derive_posture(Some(&Value::from(mode.as_str())), &security_level);
    let (posture, explicit) = match (managed_locks_level, composed_posture) {
        (false, Some(posture)) => (posture, true),
        _ => (derived, false),
    };
    let mut next = config.clone();
    let mut set = |key: &str, value: Value| {
        next.insert(key.to_owned(), value);
    };
    set("mode", Value::from(mode));
    set("protection_posture", Value::from(posture));
    set("protection_posture_explicit", Value::Bool(explicit));
    set("security_level", Value::from(security_level));
    for (field, _) in SYNCED_ACTION_FIELDS {
        set(
            field,
            Value::from(action_or(get(field), current_action(config, field))),
        );
    }
    set(
        "risk_actions",
        json!(coerce::risk_action_map(get("risk_actions"))),
    );
    set(
        "harness_risk_actions",
        json!(base::coerce_harness_risk_actions(get(
            "harness_risk_actions"
        ))),
    );
    set(
        "telemetry",
        Value::Bool(coerce::loaded_bool(get("telemetry"))),
    );
    set("sync", Value::Bool(coerce::loaded_bool(get("sync"))));
    set(
        "receipt_redaction_level",
        Value::from(coerce::receipt_redaction_level(get(
            "receipt_redaction_level",
        ))),
    );
    next
}

/// The configuration after the synced payload and the managed policy.
pub(crate) fn overlay(
    config: &Map<String, Value>,
    payload: Option<&Map<String, Value>>,
    managed: Option<&ManagedInput>,
) -> Map<String, Value> {
    let overlaid = match payload {
        Some(payload) => synced(config, payload),
        None => config.clone(),
    };
    match managed {
        Some(policy) => reapply_managed(&overlaid, policy),
        None => overlaid,
    }
}

#[cfg(test)]
#[path = "guard_config_resolve_tests.rs"]
mod tests;

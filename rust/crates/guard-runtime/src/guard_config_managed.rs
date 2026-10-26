//! Managed-policy composition for the effective Guard configuration.
//!
//! Mirrors `mdm/policy.py::apply_managed_policy`: a managed requirement is
//! composed into the local payload and can only make it stricter. Action
//! settings take the most restrictive action, mode-like strings the stronger
//! mode, and every other managed value replaces the local one.

use guard_command::action_lattice::{most_restrictive_guard_action, normalize_guard_action};
use guard_command::effect_decision::GuardAction;
use serde::Deserialize;
use serde_json::{Map, Value};

/// The effective managed policy as resolved by the caller; never read here.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ManagedInput {
    pub(crate) settings: Map<String, Value>,
    pub(crate) locked_settings: Vec<String>,
}

fn is_guard_action(value: &str) -> bool {
    matches!(
        value,
        "allow" | "warn" | "review" | "require-reapproval" | "sandbox-required" | "block"
    )
}

fn mode_strength(value: &str) -> Option<u8> {
    match value {
        "observe" => Some(0),
        "prompt" => Some(1),
        "enforce" => Some(2),
        _ => None,
    }
}

fn get_path<'a>(payload: &'a Map<String, Value>, path: &str) -> Option<&'a Value> {
    let mut parts = path.split('.');
    let mut current = payload.get(parts.next()?)?;
    for part in parts {
        current = current.as_object()?.get(part)?;
    }
    Some(current)
}

fn set_path(payload: &mut Map<String, Value>, path: &str, value: Value) {
    let parts: Vec<&str> = path.split('.').collect();
    let Some((leaf, ancestors)) = parts.split_last() else {
        return;
    };
    let mut current = payload;
    for part in ancestors {
        let child = current
            .entry((*part).to_owned())
            .or_insert_with(|| Value::Object(Map::new()));
        if !child.is_object() {
            *child = Value::Object(Map::new());
        }
        let Some(next) = child.as_object_mut() else {
            return;
        };
        current = next;
    }
    current.insert((*leaf).to_owned(), value);
}

fn action_value(action: GuardAction) -> Value {
    Value::String(action.as_str().to_owned())
}

/// `_merge_strongest_actions`; `local` is `None` when the key is absent.
fn strongest_actions(local: Option<&Value>, managed: &Value) -> Value {
    if let Value::Object(managed_map) = managed {
        let mut merged = match local {
            Some(Value::Object(existing)) => existing.clone(),
            _ => Map::new(),
        };
        for (key, value) in managed_map {
            let next = strongest_actions(merged.get(key), value);
            merged.insert(key.clone(), next);
        }
        return Value::Object(merged);
    }
    match local {
        None => action_value(normalize_guard_action(managed, GuardAction::Block)),
        Some(existing) if managed.is_null() => {
            action_value(normalize_guard_action(existing, GuardAction::Block))
        }
        Some(existing) => action_value(most_restrictive_guard_action(
            &[existing.clone(), managed.clone()],
            GuardAction::Block,
        )),
    }
}

/// `_strongest_security_value`.
fn strongest_security_value(local: Option<&Value>, managed: &Value) -> Value {
    if let (Some(Value::String(left)), Value::String(right)) = (local, managed) {
        if is_guard_action(left) || is_guard_action(right) {
            return action_value(most_restrictive_guard_action(
                &[Value::String(left.clone()), managed.clone()],
                GuardAction::Block,
            ));
        }
        if let (Some(a), Some(b)) = (mode_strength(left), mode_strength(right)) {
            return Value::String(if b > a { right.clone() } else { left.clone() });
        }
    }
    managed.clone()
}

/// `_is_action_setting_path`.
fn is_action_setting_path(path: &str) -> bool {
    let parts: Vec<&str> = path.split('.').collect();
    parts
        .iter()
        .any(|part| *part == "actions" || part.ends_with("_actions") || part.ends_with("Actions"))
        || parts
            .last()
            .is_some_and(|last| last.ends_with("_action") || last.ends_with("Action"))
}

/// `_compose_managed_value`.
fn compose_managed_value(local: Option<&Value>, managed: &Value) -> Value {
    if let (Some(Value::Object(existing)), Value::Object(managed_map)) = (local, managed) {
        let mut composed = existing.clone();
        for (key, value) in managed_map {
            let next = compose_managed_value(composed.get(key), value);
            composed.insert(key.clone(), next);
        }
        return Value::Object(composed);
    }
    strongest_security_value(local, managed)
}

/// `apply_managed_policy`.
pub(crate) fn apply_managed_policy(
    local: &Map<String, Value>,
    policy: &ManagedInput,
) -> Map<String, Value> {
    let mut composed = local.clone();
    for (key, managed_value) in &policy.settings {
        let next = if is_action_setting_path(key) {
            strongest_actions(composed.get(key), managed_value)
        } else if composed.contains_key(key) {
            compose_managed_value(composed.get(key), managed_value)
        } else {
            managed_value.clone()
        };
        composed.insert(key.clone(), next);
    }
    for path in &policy.locked_settings {
        let Some(managed_value) = get_path(&policy.settings, path) else {
            continue;
        };
        let local_value = get_path(&composed, path);
        let strongest = if is_action_setting_path(path) {
            strongest_actions(local_value, managed_value)
        } else {
            strongest_security_value(local_value, managed_value)
        };
        set_path(&mut composed, path, strongest);
    }
    composed
}

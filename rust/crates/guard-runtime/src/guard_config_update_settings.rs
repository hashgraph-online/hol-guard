//! The dashboard and CLI settings write (`update_guard_settings`).
//!
//! Mirrors `_update_guard_settings_locked` in `guard/config.py`: validate the
//! incoming payload, fold it into the stored `config.toml` table, keep the
//! protection posture and its legacy mode/level pair in step, and refuse any
//! write a managed policy would weaken or an unentitled cloud sync enable.

use guard_command::local_supply_chain::{posture_risk_actions, security_level_risk_actions};
use serde_json::{json, Map, Value};

use crate::guard_config_managed::{apply_managed_policy, ManagedInput};
use crate::guard_config_update_coerce::{
    coerce_editable, coerce_harness_patch, invalid, normalize_posture,
};
use crate::guard_config_update_harness::{apply_harness_patch, apply_named_policy, string_table};
use crate::guard_config_update_value::{
    get, is_str, py_eq, py_json_eq_int, py_str, remove, set, table_to_json, to_json, truthy, Table,
    Tv,
};
use crate::pyjson::PyVal;

pub(crate) const EDITABLE_KEYS: [&str; 27] = [
    "mode",
    "presentation_mode",
    "presentation_mode_explicit",
    "presentation_schema_version",
    "protection_posture",
    "protection_posture_explicit",
    "watch_auto_revert_hours",
    "harness_postures",
    "security_level",
    "default_action",
    "unknown_publisher_action",
    "changed_hash_action",
    "new_network_domain_action",
    "subprocess_action",
    "risk_actions",
    "harness_risk_actions",
    "approval_wait_timeout_seconds",
    "approval_surface_policy",
    "blocked_request_mode",
    "approval_browser_delay_seconds",
    "approval_browser_immediate_severity",
    "desktop_notifications",
    "update_channel",
    "telemetry",
    "sync",
    "billing",
    "receipt_redaction_level",
];
const PRESENTATION_KEYS: [&str; 3] = [
    "presentation_mode",
    "presentation_mode_explicit",
    "presentation_schema_version",
];
const FULL_SAVE_KEYS: [&str; 4] = [
    "mode",
    "security_level",
    "risk_actions",
    "protection_posture_explicit",
];
const HARNESS_POSTURE_LOCK_KEYS: [&str; 4] = [
    "protection_posture",
    "mode",
    "security_level",
    "harness_postures",
];
/// The posture state the caller records audit events from.
pub(crate) struct SettingsWrite {
    pub(crate) next: Table,
    pub(crate) previous: Value,
}

type Payload = [(String, PyVal)];

fn incoming<'a>(payload: &'a Payload, key: &str) -> Option<&'a PyVal> {
    payload
        .iter()
        .find(|(name, _)| name == key)
        .map(|(_, value)| value)
}

fn has(payload: &Payload, key: &str) -> bool {
    incoming(payload, key).is_some()
}

fn incoming_str<'a>(payload: &'a Payload, key: &str) -> Option<&'a str> {
    incoming(payload, key).and_then(PyVal::as_str)
}

fn current_str<'a>(current: &'a Value, key: &str) -> &'a str {
    current.get(key).and_then(Value::as_str).unwrap_or_default()
}

fn current_bool(current: &Value, key: &str) -> bool {
    current.get(key).and_then(Value::as_bool).unwrap_or(false)
}

fn requests_watch_restart(payload: &Payload) -> bool {
    !FULL_SAVE_KEYS.iter().any(|key| has(payload, key))
}

/// `derive_protection_posture`.
fn derive_posture(mode: &Tv, level: &Tv) -> &'static str {
    if is_str(Some(mode), "observe") {
        "watch"
    } else if is_str(Some(level), "strict") || is_str(Some(level), "paranoid") {
        "extra_careful"
    } else {
        "protected"
    }
}

/// `_incoming_selects_protection_posture`.
fn incoming_selects(payload: &Payload, current: &Value, next_mode: &Tv, next_level: &Tv) -> bool {
    let Some(posture) = incoming(payload, "protection_posture") else {
        return false;
    };
    let posture = normalize_posture(posture.as_str());
    let current_posture = current_str(current, "protection_posture");
    let current_explicit = current_bool(current, "protection_posture_explicit");
    match incoming(payload, "protection_posture_explicit") {
        Some(PyVal::Bool(false)) => return false,
        Some(PyVal::Bool(true)) => {
            return !current_explicit
                || posture != Some(current_posture)
                || (posture == Some("watch") && requests_watch_restart(payload));
        }
        _ => {}
    }
    if !["mode", "security_level", "risk_actions"]
        .iter()
        .any(|key| has(payload, key))
    {
        return true;
    }
    if current_explicit {
        return posture != Some(current_posture);
    }
    posture != Some(derive_posture(next_mode, next_level))
}

fn current_or(next: &Table, key: &str, current: &Value) -> Tv {
    get(next, key)
        .cloned()
        .unwrap_or_else(|| Tv::Str(current_str(current, key).to_owned()))
}

/// `_sync_protection_posture_payload`.
fn sync_posture(next: &mut Table, current: &Value, payload: &Payload, selected: bool, now: &str) {
    remove(next, "protection_posture_explicit");
    let next_level = current_or(next, "security_level", current);
    let current_posture = current_str(current, "protection_posture");
    if selected {
        let posture =
            normalize_posture(incoming_str(payload, "protection_posture")).unwrap_or("protected");
        set(next, "protection_posture", Tv::Str(posture.to_owned()));
        let (dual_mode, dual_level) = match posture {
            "watch" => {
                let level = if truthy(&next_level) {
                    py_str(&next_level)
                } else {
                    current_str(current, "security_level").to_owned()
                };
                ("observe", level)
            }
            "extra_careful" => ("enforce", "strict".to_owned()),
            _ => ("enforce", "balanced".to_owned()),
        };
        if posture == "watch" {
            set(next, "mode", Tv::Str("observe".to_owned()));
            let entered = current
                .get("watch_entered_at")
                .and_then(Value::as_str)
                .is_some_and(|stamp| !stamp.is_empty());
            if current_posture != "watch" || !entered || requests_watch_restart(payload) {
                set(next, "watch_entered_at", Tv::Str(now.to_owned()));
            }
        } else {
            remove(next, "watch_entered_at");
            if !has(payload, "mode") {
                set(next, "mode", Tv::Str(dual_mode.to_owned()));
            }
        }
        if !has(payload, "security_level") {
            set(next, "security_level", Tv::Str(dual_level));
        }
        return;
    }
    if has(payload, "security_level") && !has(payload, "protection_posture") {
        remove(next, "protection_posture");
        return;
    }
    if current_bool(current, "protection_posture_explicit") {
        let level_changed = !is_str(Some(&next_level), current_str(current, "security_level"));
        let next_mode = current_or(next, "mode", current);
        if has(payload, "security_level") && level_changed {
            remove(next, "protection_posture");
            return;
        }
        if current_posture == "watch" && !is_str(Some(&next_mode), "observe") {
            remove(next, "protection_posture");
            return;
        }
        set(
            next,
            "protection_posture",
            Tv::Str(current_posture.to_owned()),
        );
        if current_posture == "watch" {
            set(next, "mode", Tv::Str("observe".to_owned()));
        }
        return;
    }
    remove(next, "protection_posture");
}

/// `_effective_risk_actions`: posture or level defaults, then local overrides.
fn effective_risk_actions(current: &Value, managed: Option<&ManagedInput>) -> Tv {
    let locks_level = managed.is_some_and(|policy| {
        policy
            .locked_settings
            .iter()
            .any(|key| key == "security_level")
    });
    let posture_defaults = if current_bool(current, "protection_posture_explicit") && !locks_level {
        posture_risk_actions(current_str(current, "protection_posture"))
    } else {
        None
    };
    let mut actions = posture_defaults
        .unwrap_or_else(|| security_level_risk_actions(current_str(current, "security_level")));
    if let Some(Value::Object(overrides)) = current.get("risk_actions") {
        for (key, action) in overrides {
            if let Some(action) = action.as_str() {
                actions.insert(key.clone(), action.to_owned());
            }
        }
    }
    string_table(actions)
}

fn nested<'a>(table: &'a Table, path: &str) -> Option<&'a Tv> {
    let mut parts = path.split('.');
    let mut value = get(table, parts.next()?)?;
    for part in parts {
        let Tv::Table(inner) = value else { return None };
        value = get(inner, part)?;
    }
    Some(value)
}

fn nested_json<'a>(map: &'a Map<String, Value>, path: &str) -> Option<&'a Value> {
    let mut parts = path.split('.');
    let mut value = map.get(parts.next()?)?;
    for part in parts {
        value = value.as_object()?.get(part)?;
    }
    Some(value)
}

/// Locked paths whose requested value the managed composition overrides.
fn weakened_locks(
    next: &Table,
    effective: &Map<String, Value>,
    policy: &ManagedInput,
) -> Vec<String> {
    let mut weakened: Vec<String> = policy
        .locked_settings
        .iter()
        .filter(|path| {
            let Some(requested) = nested(next, path) else {
                return false;
            };
            // Python compares the same float object, and `nan != nan`.
            let nan = matches!(requested, Tv::Float(number) if number.is_nan());
            nan || !nested_json(effective, path)
                .is_some_and(|value| py_eq(&to_json(requested), value))
        })
        .cloned()
        .collect();
    weakened.sort();
    weakened
}

/// The presentation preference keys, coerced, and whether they change it.
fn presentation_change(payload: &Payload, current: &Value) -> Result<(Table, bool), String> {
    let mut coerced = Table::new();
    for key in PRESENTATION_KEYS {
        if let Some(value) = incoming(payload, key) {
            set(&mut coerced, key, coerce_editable(key, value)?);
        }
    }
    let has_preference =
        has(payload, "presentation_mode") || has(payload, "presentation_mode_explicit");
    if has(payload, "presentation_revision") && !has_preference {
        return Err(invalid(
            "presentation_revision requires a presentation preference change.",
        ));
    }
    let mode_changed = get(&coerced, "presentation_mode")
        .is_some_and(|mode| !is_str(Some(mode), current_str(current, "presentation_mode")));
    let explicit_changed = get(&coerced, "presentation_mode_explicit").is_some_and(|explicit| {
        *explicit != Tv::Bool(current_bool(current, "presentation_mode_explicit"))
    });
    let change = has_preference && (mode_changed || explicit_changed);
    let revision = current
        .get("presentation_revision")
        .and_then(Value::as_i64)
        .unwrap_or(0);
    if change {
        if let Some(expected) = incoming(payload, "presentation_revision") {
            if *expected != PyVal::Null && !py_json_eq_int(expected, revision) {
                return Err(invalid(
                    "Presentation preference changed on another surface. Reload settings and try again.",
                ));
            }
        }
    }
    Ok((coerced, change))
}

/// `_update_guard_settings_locked` up to the write.
pub(crate) fn update(
    stored: &Table,
    current: &Value,
    payload: &Payload,
    managed: Option<&ManagedInput>,
    cloud_sync_entitled: bool,
    now: &str,
) -> Result<SettingsWrite, String> {
    let mut next = stored.clone();
    let (presentation, presentation_changed) = presentation_change(payload, current)?;
    let switching_to_custom = incoming_str(payload, "security_level") == Some("custom")
        && !has(payload, "risk_actions")
        && !has(payload, "harness_risk_actions");
    if switching_to_custom {
        set(
            &mut next,
            "risk_actions",
            effective_risk_actions(current, managed),
        );
    }
    apply_named_policy(&mut next, payload);
    let locked: &[String] = managed.map_or(&[], |policy| &policy.locked_settings);
    let mut harness_patch = Vec::new();
    for (key, value) in payload {
        if !EDITABLE_KEYS.contains(&key.as_str()) {
            continue;
        }
        if key == "harness_postures" {
            harness_patch = coerce_harness_patch(value)?;
            let locks = locked
                .iter()
                .any(|key| HARNESS_POSTURE_LOCK_KEYS.contains(&key.as_str()));
            if locks
                && harness_patch
                    .iter()
                    .any(|(_, posture)| !matches!(posture, None | Some("extra_careful")))
            {
                return Err(invalid(
                    "Managed policy locks prevent per-harness protection overrides.",
                ));
            }
            continue;
        }
        if PRESENTATION_KEYS.contains(&key.as_str()) {
            if presentation_changed {
                if let Some(value) = get(&presentation, key) {
                    set(&mut next, key, value.clone());
                }
            }
            continue;
        }
        set(&mut next, key, coerce_editable(key, value)?);
    }
    if presentation_changed {
        let revision = current
            .get("presentation_revision")
            .and_then(Value::as_i64)
            .unwrap_or(0);
        set(&mut next, "presentation_mode_explicit", Tv::Bool(true));
        set(&mut next, "presentation_schema_version", Tv::Int(1));
        set(&mut next, "presentation_revision", Tv::Int(revision + 1));
    }
    let selected = incoming_selects(
        payload,
        current,
        &current_or(&next, "mode", current),
        &current_or(&next, "security_level", current),
    );
    sync_posture(&mut next, current, payload, selected, now);
    if !harness_patch.is_empty() {
        apply_harness_patch(&mut next, &harness_patch, now);
    }
    let next_json = table_to_json(&next);
    let effective = match managed {
        Some(policy) => {
            let effective = apply_managed_policy(&next_json, policy);
            let weakened = weakened_locks(&next, &effective, policy);
            if !weakened.is_empty() {
                return Err(format!(
                    "Managed policy locks prevent weakening: {}",
                    weakened.join(", ")
                ));
            }
            effective
        }
        None => next_json,
    };
    let enables_sync = matches!(get(&next, "sync"), Some(Tv::Bool(true)));
    let preserving_existing_sync = matches!(get(stored, "sync"), Some(Tv::Bool(true)))
        && current_bool(current, "sync")
        && enables_sync
        && (incoming_str(payload, "mode") != Some("observe")
            || effective.get("mode").and_then(Value::as_str) == Some("observe"));
    if enables_sync
        && matches!(incoming(payload, "sync"), Some(PyVal::Bool(true)))
        && !cloud_sync_entitled
        && !preserving_existing_sync
    {
        return Err(invalid("Cloud sync requires a paid team plan."));
    }
    let previous = json!({
        "previous": current_str(current, "protection_posture"),
        "previous_explicit": current_bool(current, "protection_posture_explicit"),
        "selected": selected,
        "harness_postures": current.get("harness_postures").cloned().unwrap_or_else(|| json!({})),
    });
    Ok(SettingsWrite { next, previous })
}

/// `reset_guard_settings`: drop every editable key and the harness stamps.
pub(crate) fn reset(stored: &Table) -> Table {
    stored
        .iter()
        .filter(|(key, _)| {
            !EDITABLE_KEYS.contains(&key.as_str()) && key != "harness_watch_entered_at"
        })
        .cloned()
        .collect()
}

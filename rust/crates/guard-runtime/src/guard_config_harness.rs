//! Per-harness protection posture overrides loaded from `config.toml`.
//!
//! Mirrors the loaders in `guard/harness_posture.py`.

use std::collections::BTreeMap;

use serde_json::{json, Map, Value};

use guard_command::harness_identity::REGISTERED_HARNESS_COUNT;

use crate::guard_config_iso::is_valid_iso_datetime;

const MAX_HARNESS_POSTURES: usize = REGISTERED_HARNESS_COUNT * 2;
const POSTURE_LOCK_KEYS: [&str; 4] = [
    "protection_posture",
    "mode",
    "security_level",
    "harness_postures",
];

/// `canonical_harness_id`: a registry id or install alias, else `None`.
/// The table itself lives in `guard-command` so the risk-action resolver can
/// canonicalize without a second copy.
pub(crate) use guard_command::harness_identity::canonical_harness_id;

use guard_command::harness_identity::registered_harness_ids;

/// `normalize_protection_posture`, shared with the package authority loader.
pub(crate) fn normalize_posture(value: &Value) -> Option<&'static str> {
    match crate::package_authority_config::explicit_posture(Some(value))?.as_str() {
        "protected" => Some("protected"),
        "extra_careful" => Some("extra_careful"),
        "watch" => Some("watch"),
        _ => None,
    }
}

/// Stored per-harness postures; malformed entries are dropped.
pub(crate) fn loaded_postures(value: Option<&Value>) -> BTreeMap<String, String> {
    let mut postures = BTreeMap::new();
    let Some(Value::Object(map)) = value else {
        return postures;
    };
    for (key, raw) in map {
        let (Some(harness), Some(posture)) = (canonical_harness_id(key), normalize_posture(raw))
        else {
            continue;
        };
        if postures.len() < MAX_HARNESS_POSTURES {
            postures.insert(harness.to_owned(), posture.to_owned());
        }
    }
    postures
}

/// Stored watch stamps; only watch overrides carry a stamp.
pub(crate) fn loaded_watch_stamps(
    value: Option<&Value>,
    postures: &BTreeMap<String, String>,
) -> BTreeMap<String, String> {
    let mut stamps = BTreeMap::new();
    let Some(Value::Object(map)) = value else {
        return stamps;
    };
    for (key, raw) in map {
        let Some(harness) = canonical_harness_id(key) else {
            continue;
        };
        let Some(stamp) = raw.as_str() else { continue };
        if postures.get(harness).map(String::as_str) != Some("watch")
            || stamp.trim().is_empty()
            || !is_valid_iso_datetime(stamp)
        {
            continue;
        }
        stamps.insert(harness.to_owned(), stamp.trim().to_owned());
    }
    stamps
}

/// `managed_effective_harness_postures`: apply managed locks to the local map.
pub(crate) fn managed_effective(
    local: BTreeMap<String, String>,
    locked_settings: &[String],
    managed_settings: &Map<String, Value>,
) -> BTreeMap<String, String> {
    if locked_settings.iter().any(|key| key == "harness_postures") {
        return loaded_postures(managed_settings.get("harness_postures"));
    }
    if locked_settings
        .iter()
        .any(|key| POSTURE_LOCK_KEYS.contains(&key.as_str()))
    {
        return local
            .into_iter()
            .filter(|(_, posture)| posture == "extra_careful")
            .collect();
    }
    local
}

/// `_POSTURE_STRENGTH`: an unreadable posture ranks with `protected`, so a
/// malformed value can neither weaken nor strengthen the baseline.
fn strength(posture: &str) -> u8 {
    match posture {
        "watch" => 0,
        "extra_careful" => 2,
        _ => 1,
    }
}

/// `global_effective_posture`: protection that is off reads as Watch.
pub(crate) fn global_effective<'a>(posture: &'a str, mode: &str) -> &'a str {
    if posture == "watch" || mode == "observe" {
        "watch"
    } else {
        posture
    }
}

/// `effective_harness_posture` for one override over a baseline.
///
/// Watch is always honored. A non-Watch override can turn protection back on
/// under a global Watch, but never weakens a stricter global baseline.
fn effective(baseline: &str, over: &str) -> String {
    if over == "watch" || baseline == "watch" || strength(over) > strength(baseline) {
        return over.to_owned();
    }
    baseline.to_owned()
}

/// `dual_write_from_posture`.
fn dual_write(posture: &str, security_level: &str) -> (&'static str, String) {
    match posture {
        "watch" => ("observe", security_level.to_owned()),
        "extra_careful" => ("enforce", "strict".to_owned()),
        _ => ("enforce", "balanced".to_owned()),
    }
}

/// `effective_harness_postures`: the posture governing every registered harness.
pub(crate) fn effective_map(
    baseline: &str,
    postures: &BTreeMap<String, String>,
) -> BTreeMap<String, String> {
    let mut resolved: BTreeMap<String, String> = registered_harness_ids()
        .map(|harness| (harness.to_owned(), baseline.to_owned()))
        .collect();
    // A stored override is always keyed canonically, but a caller may hold a
    // configuration built by hand; an unregistered key still governs the
    // harness that spells its name that way, so it is resolved too.
    for (harness, over) in postures {
        resolved.insert(harness.clone(), effective(baseline, over));
    }
    resolved
}

/// The `config_for_harness` fields of each harness that carries an override.
///
/// A harness without one reads the loaded configuration unchanged, so it is
/// deliberately absent here rather than present with copied values.
pub(crate) fn posture_views(
    baseline: &str,
    postures: &BTreeMap<String, String>,
    security_level: &str,
) -> Map<String, Value> {
    postures
        .iter()
        .map(|(harness, over)| {
            let posture = effective(baseline, over);
            let (mode, level) = dual_write(&posture, security_level);
            (
                harness.clone(),
                json!({"posture": posture, "mode": mode, "security_level": level}),
            )
        })
        .collect()
}

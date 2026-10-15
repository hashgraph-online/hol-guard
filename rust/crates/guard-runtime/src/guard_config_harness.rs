//! Per-harness protection posture overrides loaded from `config.toml`.
//!
//! Mirrors the loaders in `guard/harness_posture.py`.

use std::collections::BTreeMap;

use serde_json::{Map, Value};

use crate::guard_config_iso::is_valid_iso_datetime;

/// `(harness id, install aliases)` of every registered harness contract.
const HARNESS_ALIASES: [(&str, &[&str]); 17] = [
    ("codex", &["codex"]),
    ("claude-code", &["claude-code", "claude"]),
    ("opencode", &["opencode"]),
    ("copilot", &["copilot"]),
    ("cursor", &["cursor"]),
    ("cline", &["cline", "cline-cli", "cline-vscode"]),
    ("gemini", &["gemini"]),
    ("hermes", &["hermes"]),
    ("openclaw", &["openclaw"]),
    ("antigravity", &["antigravity"]),
    ("kimi", &["kimi", "kimi-code", "kimi-cli"]),
    (
        "grok",
        &["grok", "grok-build", "grok-build-cli", "xai-grok"],
    ),
    ("pi", &["pi", "pi-agent", "pi-coding-agent"]),
    ("omp", &["omp", "oh-my-pi"]),
    ("zcode", &["zcode", "zai", "z-code", "zai-zcode"]),
    ("devin", &["devin", "devin-cli", "cognition-devin"]),
    ("paseo", &["paseo"]),
];
const MAX_HARNESS_POSTURES: usize = HARNESS_ALIASES.len() * 2;
const POSTURE_LOCK_KEYS: [&str; 4] = [
    "protection_posture",
    "mode",
    "security_level",
    "harness_postures",
];

/// `canonical_harness_id`: a registry id or install alias, else `None`.
pub(crate) fn canonical_harness_id(value: &str) -> Option<&'static str> {
    let key = value.trim().to_lowercase().replace('_', "-");
    HARNESS_ALIASES
        .iter()
        .find(|(_, aliases)| aliases.contains(&key.as_str()))
        .map(|(harness, _)| *harness)
}

/// `normalize_protection_posture`, shared with the package authority loader.
pub(crate) fn normalize_posture(value: &Value) -> Option<&'static str> {
    match crate::package_authority_config::explicit_posture(Some(value))?.as_str() {
        "protected" => Some("protected"),
        "extra_careful" => Some("extra_careful"),
        "watch" => Some("watch"),
        _ => None,
    }
}

/// `coerce_loaded_harness_postures`: malformed entries are dropped.
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

/// `coerce_loaded_harness_watch_entered_at`: only watch overrides carry a stamp.
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

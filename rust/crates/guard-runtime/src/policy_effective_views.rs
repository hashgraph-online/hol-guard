//! The direct-lane views a publication binds beside its composed policy.
//!
//! The resident answers some hooks with settings the daemon reads from Guard
//! config rather than from the snapshot. A binding covers the home and every
//! settled workspace, so it carries such a setting only when every compiled
//! config agrees on it; anything else is left out and the hooks that need it
//! defer to the daemon.
//!
//! - `blocked_request_mode`: how a blocked request is answered.
//! - `mcp_relay_harnesses`: per relayed harness, the tool-call configuration
//!   and approval-hash fields the MCP proxy evaluates a `tools/call` under
//!   (`config_for_harness`), plus the receipt redaction level a queued call's
//!   inbox row is written with when every config agrees on it.
//!
//! A view is bound only when the resident reads it back unchanged: plain JSON
//! (string keys, no floats, safe integers) within the snapshot codec's limits.

use std::collections::BTreeMap;

use serde_json::{json, Map, Value};

use crate::guard_config_harness::{global_effective, posture_views};

/// The harnesses whose MCP proxy the relay replaces.
const MCP_RELAY_HARNESSES: [&str; 6] =
    ["cline", "codex", "copilot", "cursor", "hermes", "opencode"];
const BLOCKED_REQUEST_MODES: [&str; 2] = ["ask", "safe-alternative"];
const REDACTION_LEVELS: [&str; 3] = ["full", "partial", "none"];
const REDACTION_LEVEL_KEY: &str = "receipt_redaction_level";
/// `_tool_call_configuration`: the fields the proxy's tool policy reads.
const TOOL_CALL_FIELDS: [&str; 11] = [
    "mode",
    "default_action",
    "artifact_actions",
    "publisher_actions",
    "harness_actions",
    "risk_actions",
    "harness_risk_actions",
    "security_level",
    "protection_posture",
    "protection_posture_explicit",
    "managed_locked_settings",
];
/// Fields the approval hash binds beyond the tool-call configuration.
const HASH_FIELDS: [&str; 3] = [
    "managed_policy_hash",
    "managed_policy_status",
    "sandbox_analysis",
];
const MAX_VIEW_BYTES: usize = 262_144;
const MAX_SAFE_INTEGER: i64 = (1 << 53) - 1;
const MAX_JSON_DEPTH: usize = 32;
const MAX_JSON_COLLECTION_ITEMS: usize = 4_096;
const MAX_JSON_STRING_BYTES: usize = 1024 * 1024;

pub(super) fn views(configs: &[Map<String, Value>]) -> Value {
    json!({
        "blocked_request_mode": uniform_blocked_request_mode(configs),
        "mcp_relay_harnesses": uniform_harness_views(configs),
    })
}

/// The one value every config holds for `name`, if they all agree.
fn uniform_text<'a>(configs: &'a [Map<String, Value>], name: &str) -> Option<&'a str> {
    let (first, rest) = configs.split_first()?;
    let value = first.get(name);
    if rest.iter().any(|config| config.get(name) != value) {
        return None;
    }
    value?.as_str()
}

fn uniform_blocked_request_mode(configs: &[Map<String, Value>]) -> Value {
    uniform_text(configs, "blocked_request_mode")
        .filter(|mode| BLOCKED_REQUEST_MODES.contains(mode))
        .map_or(Value::Null, Value::from)
}

fn uniform_harness_views(configs: &[Map<String, Value>]) -> Map<String, Value> {
    let mut harnesses = Map::new();
    if configs.is_empty() {
        return harnesses;
    }
    let level =
        uniform_text(configs, REDACTION_LEVEL_KEY).filter(|level| REDACTION_LEVELS.contains(level));
    for harness in MCP_RELAY_HARNESSES {
        let views: Vec<Option<Value>> = configs
            .iter()
            .map(|config| harness_view(config, harness))
            .collect();
        let Some(Some(bound)) = views.first() else {
            continue;
        };
        if views[1..].iter().any(|view| view.as_ref() != Some(bound)) {
            continue;
        }
        let mut bound = bound.clone();
        if let (Some(level), Some(object)) = (level, bound.as_object_mut()) {
            object.insert(REDACTION_LEVEL_KEY.into(), level.into());
        }
        harnesses.insert(harness.to_owned(), bound);
    }
    harnesses
}

/// The well-formed overrides, as `harness_posture_override` reads them.
fn overrides(config: &Map<String, Value>) -> BTreeMap<String, String> {
    match config.get("harness_postures") {
        Some(Value::Object(map)) => map
            .iter()
            .filter_map(|(harness, posture)| Some((harness.clone(), posture.as_str()?.to_owned())))
            .collect(),
        _ => BTreeMap::new(),
    }
}

/// `config_for_harness`: the config unchanged unless the harness carries an
/// override, else with the posture, mode and security level it implies.
fn config_for_harness(config: &Map<String, Value>, harness: &str) -> Option<Map<String, Value>> {
    let overrides = overrides(config);
    if !overrides.contains_key(harness) {
        return Some(config.clone());
    }
    let posture = config.get("protection_posture")?.as_str()?;
    let mode = config.get("mode")?.as_str()?;
    let security_level = config.get("security_level")?.as_str()?;
    let baseline = global_effective(posture, mode);
    let resolved = posture_views(baseline, &overrides, security_level);
    let view = resolved.get(harness)?;
    let mut effective = config.clone();
    effective.insert("protection_posture".into(), view.get("posture")?.clone());
    effective.insert("protection_posture_explicit".into(), Value::Bool(true));
    effective.insert("mode".into(), view.get("mode")?.clone());
    let level = view.get("security_level")?.as_str()?;
    if !level.is_empty() {
        effective.insert("security_level".into(), level.into());
    }
    Some(effective)
}

fn fields(config: &Map<String, Value>, names: &[&str]) -> Option<Map<String, Value>> {
    names
        .iter()
        .map(|name| Some(((*name).to_owned(), config.get(*name)?.clone())))
        .collect()
}

/// `harness_view`: the proxy's tool-call configuration and hash fields for
/// one harness, or `None` when the config cannot express them.
fn harness_view(config: &Map<String, Value>, harness: &str) -> Option<Value> {
    let effective = config_for_harness(config, harness)?;
    let tool_call = fields(&effective, &TOOL_CALL_FIELDS)?;
    let mut hash_config = tool_call.clone();
    hash_config.extend(fields(&effective, &HASH_FIELDS)?);
    let mut configuration = tool_call;
    let mut postures = Map::new();
    if let Some(posture) = overrides(config).remove(harness) {
        postures.insert(harness.to_owned(), posture.into());
    }
    configuration.insert("harness_postures".into(), Value::Object(postures));
    let view = json!({"config": configuration, "hash_config": hash_config});
    (stable(&view) && view["config"]["mode"].is_string()).then_some(view)
}

/// Whether the resident reads `value` back unchanged within its limits.
fn stable(value: &Value) -> bool {
    plain(value, 0) && encoded_len(value) <= MAX_VIEW_BYTES
}

fn plain(value: &Value, depth: usize) -> bool {
    if depth > MAX_JSON_DEPTH {
        return false;
    }
    match value {
        Value::Null | Value::Bool(_) => true,
        Value::String(text) => text.len() <= MAX_JSON_STRING_BYTES,
        Value::Number(number) => number
            .as_i64()
            .is_some_and(|value| (-MAX_SAFE_INTEGER..=MAX_SAFE_INTEGER).contains(&value)),
        Value::Array(items) => {
            items.len() <= MAX_JSON_COLLECTION_ITEMS
                && items.iter().all(|item| plain(item, depth + 1))
        }
        Value::Object(map) => {
            map.len() <= MAX_JSON_COLLECTION_ITEMS
                && map
                    .iter()
                    .all(|(key, item)| key.len() <= MAX_JSON_STRING_BYTES && plain(item, depth + 1))
        }
    }
}

/// The UTF-8 length of `json.dumps(value, ensure_ascii=False)`, whose item
/// and key separators are `", "` and `": "`: the size the daemon bounded.
fn encoded_len(value: &Value) -> usize {
    match value {
        Value::Array(items) => {
            2 + items.iter().map(encoded_len).sum::<usize>() + 2 * items.len().saturating_sub(1)
        }
        Value::Object(map) => {
            2 + map
                .iter()
                .map(|(key, item)| string_len(key) + 2 + encoded_len(item))
                .sum::<usize>()
                + 2 * map.len().saturating_sub(1)
        }
        Value::String(text) => string_len(text),
        other => other.to_string().len(),
    }
}

fn string_len(text: &str) -> usize {
    Value::String(text.to_owned()).to_string().len()
}

#[cfg(test)]
#[path = "policy_effective_views_tests.rs"]
mod tests;

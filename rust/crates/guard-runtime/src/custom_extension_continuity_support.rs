//! Shared helpers for continuity planning: authority updates, observation
//! preconditions, overrides and value checks.

use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};

use super::*;

/// Exact settings for one matched local; `None` when the grant already matches.
pub(super) fn plan_exact_settings(
    authority: &Authority<'_>,
    local: &Map<String, Value>,
    state: &str,
    commands: &Map<String, Value>,
) -> Planned<Option<Value>> {
    let cli_id = local["cli_id"].as_str().unwrap_or_default();
    let catalog: BTreeSet<&str> = authority
        .detail(cli_id, "catalog_ids")
        .and_then(Value::as_array)
        .map(|ids| ids.iter().filter_map(Value::as_str).collect())
        .unwrap_or_default();
    if !commands
        .keys()
        .all(|command| catalog.contains(command.as_str()))
    {
        return refuse("continuity settings reference an unobserved command");
    }
    let identity = identity_from_local(local)?;
    let empty = Map::new();
    let current_commands = authority
        .detail(cli_id, "command_states")
        .and_then(Value::as_object)
        .unwrap_or(&empty);
    let unchanged = authority.grant(cli_id).is_some_and(|grant| {
        grant.get("identity_hash") == local.get("identity_hash")
            && grant.get("state").and_then(Value::as_str) == Some(state)
            && current_commands == commands
    });
    if unchanged {
        return Ok(None);
    }
    Ok(Some(authority_update(identity, state, commands.clone())))
}

pub(super) fn unset_update(local: &Map<String, Value>) -> Planned<Value> {
    Ok(authority_update(
        identity_from_local(local)?,
        "unset",
        Map::new(),
    ))
}

fn authority_update(
    mut identity: Map<String, Value>,
    state: &str,
    commands: Map<String, Value>,
) -> Value {
    identity.insert("state".to_owned(), json!(state));
    identity.insert("commands".to_owned(), Value::Object(commands));
    Value::Object(identity)
}

fn identity_from_local(local: &Map<String, Value>) -> Planned<Map<String, Value>> {
    if !matches!(
        local.get("kind").and_then(Value::as_str),
        Some("executable" | "script")
    ) {
        return refuse("local continuity identity kind is invalid");
    }
    Ok(pick(
        local,
        &[
            "cli_id",
            "name",
            "kind",
            "identity_hash",
            "example_label",
            "interpreter_name",
        ],
    ))
}

pub(super) fn observation_precondition(local: Option<&Map<String, Value>>) -> Value {
    let Some(local) = local.filter(|local| observed(local)) else {
        return Value::Null;
    };
    let mut precondition = pick(
        local,
        &[
            "identity_hash",
            "kind",
            "name",
            "interpreter_name",
            "example_label",
            "observed_count",
            "surface",
        ],
    );
    let command_ids: Vec<&Value> = local
        .get("command_ids")
        .and_then(Value::as_array)
        .map(|ids| ids.iter().filter(|id| id.is_string()).collect())
        .unwrap_or_default();
    precondition.insert("command_ids".to_owned(), json!(command_ids));
    Value::Object(precondition)
}

fn pick(local: &Map<String, Value>, keys: &[&str]) -> Map<String, Value> {
    keys.iter()
        .map(|key| {
            (
                (*key).to_owned(),
                local.get(*key).cloned().unwrap_or(Value::Null),
            )
        })
        .collect()
}

pub(super) fn observed(local: &Map<String, Value>) -> bool {
    py_int(local.get("observed_count")).is_some_and(|count| count >= 1)
}

pub(super) fn require_monotonic(previous: &Value, revision: i128, digest: &str) -> Planned<()> {
    let Some(previous) = previous.as_object() else {
        return Ok(());
    };
    let Some(previous_revision) = py_int(previous.get("cloud_revision")) else {
        return Ok(());
    };
    if revision < previous_revision {
        return refuse("continuity revision cannot move backwards");
    }
    let previous_digest = previous.get("observation_digest").and_then(Value::as_str);
    if revision == previous_revision && previous_digest.is_some_and(|previous| previous != digest) {
        return refuse("continuity revision payload changed");
    }
    Ok(())
}

pub(super) fn override_matches(value: Option<&Value>, identity_hash: &str, revision: i128) -> bool {
    value.and_then(Value::as_object).is_some_and(|value| {
        value.get("identity_hash").and_then(Value::as_str) == Some(identity_hash)
            && py_int(value.get("cloud_revision")).is_some_and(|stored| stored >= revision)
    })
}

pub(super) fn local_override_status(value: Option<&Value>) -> (&'static str, &'static str) {
    let state = value
        .and_then(|value| value.get("state"))
        .and_then(Value::as_str);
    if matches!(state, Some("allowed" | "blocked")) {
        ("locally_overridden", "local_authority_preserved")
    } else {
        ("removed", "removed_locally")
    }
}

/// `datetime.fromisoformat(value.replace("Z", "+00:00"))` as UTC microseconds.
pub(super) fn timestamp(value: &str, label: &str) -> Planned<i64> {
    let Some(parsed) = from_isoformat(&value.replace('Z', "+00:00")) else {
        return refuse(format!("invalid continuity {label}"));
    };
    if !parsed.is_aware() {
        return refuse(format!("continuity {label} must include a timezone"));
    }
    match parsed.utc_micros() {
        Some(micros) => Ok(micros),
        None => refuse(format!("invalid continuity {label}")),
    }
}

/// A Python `int` (not `bool`, not `float`) that fits in 128 bits.
pub(super) fn py_int(value: Option<&Value>) -> Option<i128> {
    let Some(Value::Number(number)) = value else {
        return None;
    };
    let text = number.to_string();
    let digits = text.strip_prefix('-').unwrap_or(&text);
    if digits.is_empty() || !digits.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    text.parse().ok()
}

pub(super) fn has_exact_keys(object: &Map<String, Value>, keys: &[&str]) -> bool {
    object.len() == keys.len() && keys.iter().all(|key| object.contains_key(*key))
}

pub(super) fn is_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
}

pub(super) fn is_command_id(value: &str) -> bool {
    if matches!(value, "root" | "other") {
        return true;
    }
    let parts: Vec<&str> = value.split('.').collect();
    parts.len() <= MAX_COMMAND_DEPTH
        && parts.iter().all(|part| {
            let mut bytes = part.bytes();
            bytes
                .next()
                .is_some_and(|first| first.is_ascii_alphabetic())
                && part.len() <= 41
                && bytes.all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
        })
}

pub(super) fn scoped_identity(workspace: &str, identity_hash: &str) -> String {
    sha256_hex(&format!("{SCHEMA_V1}:{workspace}:{identity_hash}"))
}

pub(super) fn sha256_hex(text: &str) -> String {
    hex::encode(Sha256::digest(text.as_bytes()))
}

pub(super) fn string_list(value: Option<&Value>) -> Planned<Vec<String>> {
    match value {
        None | Some(Value::Null) => Ok(Vec::new()),
        Some(Value::Array(items)) => items
            .iter()
            .map(|item| item.as_str().map(str::to_owned).ok_or(Fail::Request))
            .collect(),
        Some(_) => Err(Fail::Request),
    }
}

/// Keys of `map` in the client's stored order, then any others sorted.
pub(super) fn ordered_keys(map: &Map<String, Value>, order: &[String]) -> Vec<String> {
    let mut keys: Vec<String> = Vec::with_capacity(map.len());
    for key in order {
        if map.contains_key(key) && !keys.contains(key) {
            keys.push(key.clone());
        }
    }
    for key in map.keys() {
        if !keys.contains(key) {
            keys.push(key.clone());
        }
    }
    keys
}

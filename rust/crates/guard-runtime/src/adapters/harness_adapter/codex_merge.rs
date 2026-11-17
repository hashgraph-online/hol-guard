//! Codex: the config rewrites an install plans over payloads read from TOML.
//!
//! A payload crosses as order-preserving JSON text in which every scalar JSON
//! cannot carry (a TOML date, an integer past 64 bits) is a token naming its
//! meaning, the form `native_codex_hook_identity` sends. Equal meanings share
//! a token, so comparing tokens compares the values. Python renders the TOML
//! from the payload these ops return, mapping each token back.
//!
//! `migrate` folds the user's legacy `hooks.json` groups into the config,
//! and `readback` and `subset` prove a rendered config kept them.

use std::collections::{BTreeMap, BTreeSet};

use serde_json::{json, Map, Value};

use super::codex::{dict, text};
use super::{Failure, Step};
use crate::codex_hook_identity_op::group_digests;
use crate::guard_store_json::py_repr_str;
use crate::pyjson::{self, PyVal};

const CONFLICT: &str = "codex_hook_migration_conflict";
const MISMATCH: &str = "codex_hook_migration_readback_mismatch";
/// `_MAX_DEFINITION_DEPTH`: the deepest value a definition may hold, the
/// definition mapping itself counting as the first level.
const MAX_DEFINITION_DEPTH: usize = 29;

type Tokens = BTreeMap<String, Value>;
pub(super) type Entries = Vec<(String, PyVal)>;

pub(super) fn dispatch(op: &str, fields: &Map<String, Value>) -> Step<Value> {
    let tokens: Tokens = fields
        .get("tokens")
        .and_then(Value::as_object)
        .map(|tokens| tokens.iter().map(|(k, v)| (k.clone(), v.clone())).collect())
        .unwrap_or_default();
    let scope = fields
        .get("scope")
        .and_then(Value::as_str)
        .unwrap_or("global");
    match op {
        "migrate" => migrate(fields, scope, &tokens),
        "readback" => readback(fields, scope, &tokens),
        "subset" => subset(fields, scope, &tokens),
        _ => Err(Failure::Invalid),
    }
}

pub(super) fn payload(fields: &Map<String, Value>, key: &str) -> Step<Entries> {
    dict(fields, key)
}

pub(super) fn get<'a>(entries: &'a [(String, PyVal)], key: &str) -> Option<&'a PyVal> {
    entries
        .iter()
        .find_map(|(name, value)| (name == key).then_some(value))
}

pub(super) fn set(entries: &mut Entries, key: &str, value: PyVal) {
    match entries.iter_mut().find(|(name, _)| name == key) {
        Some(entry) => entry.1 = value,
        None => entries.push((key.to_owned(), value)),
    }
}

pub(super) fn pop(entries: &mut Entries, key: &str) -> Option<PyVal> {
    let index = entries.iter().position(|(name, _)| name == key)?;
    Some(entries.remove(index).1)
}

pub(super) fn render(entries: Entries) -> String {
    super::codex::compact(&PyVal::Dict(entries), false)
}

/// `_payload_has_hooks_feature_enabled`.
fn hooks_enabled(entries: &[(String, PyVal)]) -> bool {
    match get(entries, "features").and_then(PyVal::as_dict) {
        Some(features) => !matches!(get(features, "hooks"), Some(PyVal::Bool(false))),
        None => true,
    }
}

/// Python `==` over the values a payload holds.
pub(super) fn py_eq(left: &PyVal, right: &PyVal) -> bool {
    match (number(left), number(right)) {
        (Some(left), Some(right)) => return left == right,
        (Some(_), None) | (None, Some(_)) => return false,
        (None, None) => {}
    }
    match (left, right) {
        (PyVal::Null, PyVal::Null) => true,
        (PyVal::Str(left), PyVal::Str(right)) => left == right,
        (PyVal::List(left), PyVal::List(right)) => {
            left.len() == right.len() && left.iter().zip(right).all(|(a, b)| py_eq(a, b))
        }
        (PyVal::Dict(left), PyVal::Dict(right)) => {
            left.len() == right.len()
                && left
                    .iter()
                    .all(|(key, value)| get(right, key).is_some_and(|other| py_eq(value, other)))
        }
        _ => false,
    }
}

/// A number as Python compares it: `True == 1 == 1.0`.
#[derive(PartialEq)]
enum Number {
    Whole(i128),
    Real(f64),
}

fn number(value: &PyVal) -> Option<Number> {
    Some(match value {
        PyVal::Bool(flag) => Number::Whole(i128::from(*flag)),
        PyVal::Int(digits) => Number::Whole(digits.parse().ok()?),
        PyVal::Float(real) if real.fract() == 0.0 && real.abs() < 1e38 =>
        {
            #[allow(clippy::cast_possible_truncation)]
            Number::Whole(*real as i128)
        }
        PyVal::Float(real) => Number::Real(*real),
        _ => return None,
    })
}

fn depth(value: &Value) -> usize {
    match value {
        Value::Object(map) => 1 + map.values().map(depth).max().unwrap_or(0),
        Value::Array(items) => 1 + items.iter().map(depth).max().unwrap_or(0),
        _ => 1,
    }
}

/// `_group_identities` and `_group_conflict_keys` for one mapping group.
fn digests(
    scope: &str,
    enabled: bool,
    event: &str,
    group: &PyVal,
    tokens: &Tokens,
) -> Step<(String, Vec<String>)> {
    let Some(Value::Object(group)) = group.to_json() else {
        return Err(unidentified("native_codex_hook_identity_unavailable"));
    };
    let group = Value::Object(group);
    if depth(&group) > MAX_DEFINITION_DEPTH {
        return Err(unidentified("native_codex_hook_definition_too_deep"));
    }
    let Value::Object(group) = group else {
        return Err(Failure::Invalid);
    };
    Ok(group_digests(scope, enabled, event, &group, tokens))
}

fn unidentified(code: &str) -> Failure {
    Failure::Runtime(format!(
        "{code}: Guard's native runtime did not identify the Codex hooks this migration compares. \
         Repair whichever the code names, the Guard installation or the hook definition, before \
         retrying migration."
    ))
}

/// `_append_unique_hook_groups`; `None` when nothing was appended.
fn append_unique(
    existing: Option<&PyVal>,
    incoming: &PyVal,
    event: &str,
    scope: &str,
    enabled: bool,
    tokens: &Tokens,
) -> Step<(Vec<PyVal>, bool)> {
    let mut merged: Vec<PyVal> = existing
        .and_then(PyVal::as_list)
        .unwrap_or_default()
        .to_vec();
    let Some(incoming) = incoming.as_list() else {
        return Ok((merged, false));
    };
    let mut identities = BTreeSet::new();
    let mut conflicts = BTreeSet::new();
    for group in merged.iter().filter(|group| group.as_dict().is_some()) {
        let (identity, keys) = digests(scope, enabled, event, group, tokens)?;
        identities.insert(identity);
        conflicts.extend(keys);
    }
    let mut appended = false;
    for group in incoming {
        if group.as_dict().is_none() {
            if !merged.iter().any(|member| py_eq(member, group)) {
                merged.push(group.clone());
                appended = true;
            }
            continue;
        }
        let (identity, keys) = digests(scope, enabled, event, group, tokens)?;
        if identities.contains(&identity) {
            continue;
        }
        if keys.iter().any(|key| conflicts.contains(key)) {
            return Err(Failure::Runtime(format!(
                "{CONFLICT}: Codex hook sources define the same {} matcher and command with \
                 different execution-affecting fields. Reconcile the definitions before retrying \
                 migration.",
                py_repr_str(event)
            )));
        }
        merged.push(group.clone());
        appended = true;
        identities.insert(identity);
        conflicts.extend(keys);
    }
    Ok((merged, appended))
}

/// `_migrate_hooks_json_into_config` after Python's ownership strips.
fn migrate(fields: &Map<String, Value>, scope: &str, tokens: &Tokens) -> Step<Value> {
    let mut config = payload(fields, "config")?;
    let hooks = match fields.get("hooks").and_then(Value::as_str) {
        Some(raw) => pyjson::parse(raw).map_err(|_| Failure::Invalid)?,
        None => PyVal::Null,
    };
    let Some(hooks) = hooks.as_dict() else {
        return Ok(json!({ "config": render(config), "changed": false }));
    };
    let mut config_hooks: Entries = get(&config, "hooks")
        .and_then(PyVal::as_dict)
        .map(<[_]>::to_vec)
        .unwrap_or_default();
    let enabled = hooks_enabled(&config);
    let mut changed = false;
    for (event, groups) in hooks {
        let existing = get(&config_hooks, event);
        let was_list = existing.is_some_and(|value| value.as_list().is_some());
        let (merged, appended) = append_unique(existing, groups, event, scope, enabled, tokens)?;
        changed |= appended || !was_list;
        set(&mut config_hooks, event, PyVal::List(merged));
    }
    if !config_hooks.is_empty() {
        set(&mut config, "hooks", PyVal::Dict(config_hooks));
    }
    Ok(json!({ "config": render(config), "changed": changed }))
}

/// Each event's group identities in order, as `_canonical_hook_semantics`.
fn semantics(
    entries: &[(String, PyVal)],
    scope: &str,
    enabled: bool,
    tokens: &Tokens,
) -> Step<BTreeMap<String, Vec<String>>> {
    let mut out = BTreeMap::new();
    let Some(hooks) = get(entries, "hooks").and_then(PyVal::as_dict) else {
        return Ok(out);
    };
    for (event, groups) in hooks {
        let Some(groups) = groups.as_list() else {
            continue;
        };
        let mut identities = Vec::new();
        for group in groups.iter().filter(|group| group.as_dict().is_some()) {
            identities.push(digests(scope, enabled, event, group, tokens)?.0);
        }
        out.insert(event.clone(), identities);
    }
    Ok(out)
}

/// `_require_hook_semantics_readback`.
fn readback(fields: &Map<String, Value>, scope: &str, tokens: &Tokens) -> Step<Value> {
    let expected = payload(fields, "expected")?;
    let actual = payload(fields, "actual")?;
    let before = semantics(&expected, scope, hooks_enabled(&expected), tokens)?;
    let after = semantics(&actual, scope, hooks_enabled(&actual), tokens)?;
    if before != after {
        return Err(Failure::Runtime(format!(
            "{MISMATCH}: Rendered Codex hooks at {} did not preserve their canonical event, \
             matcher, handler, environment, timeout, status, and command semantics. The legacy \
             source was retained; repair the config and retry migration.",
            text(fields, "source_path")?
        )));
    }
    Ok(json!({}))
}

/// Every migrated identity the expected payload holds is in the actual one,
/// both read with the actual config's hooks feature.
fn subset(fields: &Map<String, Value>, scope: &str, tokens: &Tokens) -> Step<Value> {
    let expected = payload(fields, "expected")?;
    let actual = payload(fields, "actual")?;
    let enabled = hooks_enabled(&actual);
    let wanted = semantics(&expected, scope, enabled, tokens)?;
    let present: BTreeSet<String> = semantics(&actual, scope, enabled, tokens)?
        .into_values()
        .flatten()
        .collect();
    if wanted
        .into_values()
        .flatten()
        .all(|id| present.contains(&id))
    {
        return Ok(json!({}));
    }
    Err(Failure::Runtime(
        match fields.get("hooks_path").and_then(Value::as_str) {
            Some(hooks_path) => format!(
            "{MISMATCH}: {} does not contain every canonical hook migrated from {hooks_path}. The \
             legacy JSON source was retained; repair the config and retry migration.",
            text(fields, "config_path")?
        ),
            None => format!("{MISMATCH}: planned Codex migration lost user hooks."),
        },
    ))
}

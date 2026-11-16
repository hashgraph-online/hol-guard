//! Codex: `CodexHarnessAdapter._install_config_hooks`, the step that turns
//! Codex hooks on and writes Guard's own hook groups into a config payload.
//!
//! `features.hooks` is set (the retired `codex_hooks` flag dropped), Guard's earlier handlers are stripped (holding back one a config cleanup
//! still records), the managed groups are appended once every remaining Guard
//! handler is proven this install's, each hook's `[hooks.state]` entry follows
//! its handler to the position it now holds, and trust is recorded for the
//! Guard handlers just written. Codex skips a hook it has no trusted hash for,
//! so an install that cannot record trust refuses.
//!
//! Request fields: `payload` (config JSON text whose exotic scalars are
//! tokens), `tokens`, `owned` (JSON text of the manifest bindings), `managed`
//! (JSON text of the groups to install), `config` (the config path) and the
//! owner fields. Answer: `{"payload": <JSON text>}`, in the same tokens.

use std::collections::BTreeSet;
use std::path::Path;

use serde_json::{json, Map, Value};

use super::codex::{compact, text};
use super::codex_merge::get;
use super::codex_migration::{owner_fields, owners_op, strip_owned};
use super::{path_text, Ctx, Failure, Step};
use crate::codex_hook_trust;
use crate::pyjson::{self, PyVal};

const TRUST_SCHEMA: &str = "codex-hook-trust.v1";
const TRUST_UNAVAILABLE: &str = "codex_hook_trust_unavailable";
/// The owner fields `install` does not take.
const LEGACY: [&str; 4] = ["expected", "argv", "legacy_argv", "statuses"];

pub(super) fn config_hooks(ctx: &Ctx, fields: &Map<String, Value>) -> Step<Value> {
    let PyVal::Dict(payload) = parse(fields, "payload")? else {
        return Err(Failure::Invalid);
    };
    let PyVal::List(owned) = parse(fields, "owned")? else {
        return Err(Failure::Invalid);
    };
    let managed = parse(fields, "managed")?;
    if !matches!(managed, PyVal::Dict(_)) {
        return Err(Failure::Invalid);
    }
    let tokens = fields
        .get("tokens")
        .and_then(Value::as_object)
        .ok_or(Failure::Invalid)?;
    let config_path = Path::new(text(fields, "config")?);
    let base = owner_fields(fields)?;
    let payload = install(ctx, &base, payload, (&owned, &managed), tokens, config_path)?;
    Ok(json!({ "payload": compact(&PyVal::Dict(payload), false) }))
}

fn parse(fields: &Map<String, Value>, key: &str) -> Step<PyVal> {
    pyjson::parse(text(fields, key)?).map_err(|_| Failure::Invalid)
}

/// The payload with Guard's groups installed, their state moved and trusted.
pub(super) fn install(
    ctx: &Ctx,
    base: &Map<String, Value>,
    mut payload: Vec<(String, PyVal)>,
    (owned, managed): (&[PyVal], &PyVal),
    tokens: &Map<String, Value>,
    config_path: &Path,
) -> Step<Vec<(String, PyVal)>> {
    enable_hooks(&mut payload);
    let hooks = match get(&payload, "hooks") {
        Some(hooks @ PyVal::Dict(_)) => hooks.clone(),
        _ => PyVal::Dict(Vec::new()),
    };
    let stripped = strip_owned(base, &hooks, owned, false, true)?;
    let installed = install_groups(base, &stripped, managed)?;
    let PyVal::Dict(mut cleaned) = pyjson::parse(&installed).map_err(|_| Failure::Invalid)? else {
        return Err(Failure::Invalid);
    };
    let PyVal::Dict(before) = &hooks else {
        return Err(Failure::Invalid);
    };
    remap(ctx, base, before, &mut cleaned, tokens, config_path)?;
    set(&mut payload, "hooks", PyVal::Dict(cleaned));
    record(ctx, base, &mut payload, tokens, config_path)?;
    Ok(payload)
}

/// `features.hooks = true`, with the retired `codex_hooks` flag dropped; a
/// `features` value that is not a table is replaced.
fn enable_hooks(payload: &mut Vec<(String, PyVal)>) {
    let mut features = match get(payload, "features") {
        Some(PyVal::Dict(features)) => features.clone(),
        _ => Vec::new(),
    };
    features.retain(|(key, _)| key != "codex_hooks");
    set(&mut features, "hooks", PyVal::Bool(true));
    set(payload, "features", PyVal::Dict(features));
}

/// `install_managed_codex_hook_groups`: the hooks with the managed groups.
fn install_groups(base: &Map<String, Value>, hooks: &str, managed: &PyVal) -> Step<String> {
    let mut request = base.clone();
    for key in LEGACY {
        request.remove(key);
    }
    let mut extra = Map::new();
    extra.insert("hooks".into(), json!(hooks));
    extra.insert("managed".into(), json!(compact(managed, false)));
    let answer = owners_op(&request, "install", extra)?;
    if let Some(conflict) = answer.get("conflict").and_then(Value::as_str) {
        return Err(Failure::Runtime(conflict.to_owned()));
    }
    answer
        .get("hooks")
        .and_then(Value::as_str)
        .map(str::to_owned)
        .ok_or_else(|| Failure::Runtime("codex_hook_owners answered without hooks".into()))
}

/// `remap_hook_state`: each state entry follows its handler. Without an
/// answer the table is left as it was.
pub(super) fn remap(
    ctx: &Ctx,
    base: &Map<String, Value>,
    before: &[(String, PyVal)],
    hooks: &mut Vec<(String, PyVal)>,
    tokens: &Map<String, Value>,
    config_path: &Path,
) -> Step<()> {
    let state = match get(hooks, "state") {
        Some(PyVal::Dict(state)) if !state.is_empty() => state.clone(),
        _ => return Ok(()),
    };
    let mut request = table_request(ctx, base, "remap", hooks, Some(before), tokens, config_path)?;
    request.insert("before_events".into(), events(before, tokens));
    let Ok(answer) = codex_hook_trust::answer_value(Value::Object(request)) else {
        return Ok(());
    };
    let Some(moved) = answer.get("state").and_then(Value::as_array) else {
        return Ok(());
    };
    let mut remapped = Vec::with_capacity(moved.len());
    for pair in moved {
        let (key, source) = match pair.as_array().map(Vec::as_slice) {
            Some([key, source]) => (key, source),
            _ => return Err(Failure::Invalid),
        };
        let key = key.as_str().ok_or(Failure::Invalid)?.to_owned();
        let entry = match source.as_str() {
            Some(source) => get(&state, source).cloned().ok_or(Failure::Invalid)?,
            None => PyVal::Dict(vec![("enabled".into(), PyVal::Bool(false))]),
        };
        remapped.push((key, entry));
    }
    set(hooks, "state", PyVal::Dict(remapped));
    Ok(())
}

/// `record_guard_hook_trust`: the trusted hash of each Guard handler written.
fn record(
    ctx: &Ctx,
    base: &Map<String, Value>,
    payload: &mut [(String, PyVal)],
    tokens: &Map<String, Value>,
    config_path: &Path,
) -> Step<()> {
    let Some((_, PyVal::Dict(hooks))) = payload.iter_mut().find(|(key, _)| key == "hooks") else {
        return Ok(());
    };
    let request = table_request(ctx, base, "record", hooks, None, tokens, config_path)?;
    let unavailable = || Failure::Runtime(TRUST_UNAVAILABLE.into());
    let answer =
        codex_hook_trust::answer_value(Value::Object(request)).map_err(|_| unavailable())?;
    let recorded = answer
        .get("recorded")
        .and_then(Value::as_array)
        .ok_or_else(unavailable)?;
    let had_state = matches!(get(hooks, "state"), Some(PyVal::Dict(_)));
    let mut state = match get(hooks, "state") {
        Some(PyVal::Dict(state)) => state.clone(),
        _ => Vec::new(),
    };
    for row in recorded {
        let (key, source, digest) = match row.as_array().map(Vec::as_slice) {
            Some([key, source, digest]) => (key, source, digest),
            _ => return Err(unavailable()),
        };
        let key = key.as_str().ok_or_else(unavailable)?.to_owned();
        let digest = digest.as_str().ok_or_else(unavailable)?.to_owned();
        let mut entry = match source.as_str().and_then(|source| get(&state, source)) {
            Some(PyVal::Dict(existing)) => existing.clone(),
            _ => Vec::new(),
        };
        set(&mut entry, "trusted_hash", PyVal::Str(digest));
        set(&mut state, &key, PyVal::Dict(entry));
    }
    if !recorded.is_empty() || had_state {
        set(hooks, "state", PyVal::Dict(state));
    }
    Ok(())
}

/// `codex_hook_trust_stale`: whether a Guard hook's stored trust is missing
/// or stale. Unknown trust reads as stale, so doctor never calls the hooks
/// active on a guess; a short name to expand is still asked for.
pub(super) fn trust_stale(
    ctx: &Ctx,
    base: &Map<String, Value>,
    hooks: &[(String, PyVal)],
    tokens: &Map<String, Value>,
    config_path: &Path,
) -> Step<bool> {
    let request = match table_request(ctx, base, "stale", hooks, None, tokens, config_path) {
        Ok(request) => request,
        Err(reply @ Failure::Reply(_)) => return Err(reply),
        Err(_) => return Ok(true),
    };
    let Ok(answer) = codex_hook_trust::answer_value(Value::Object(request)) else {
        return Ok(true);
    };
    Ok(answer
        .get("stale")
        .and_then(Value::as_array)
        .is_none_or(|stale| !stale.is_empty()))
}

/// `codex_hook_trust._table_request`.
fn table_request(
    ctx: &Ctx,
    base: &Map<String, Value>,
    op: &str,
    hooks: &[(String, PyVal)],
    before: Option<&[(String, PyVal)]>,
    tokens: &Map<String, Value>,
    config_path: &Path,
) -> Step<Map<String, Value>> {
    let state = match get(hooks, "state") {
        Some(PyVal::Dict(state)) => state
            .iter()
            .map(|(key, entry)| json!([key, jsonable(entry, tokens)]))
            .collect(),
        _ => Vec::new(),
    };
    let mut prefixes = vec![path_text(&ctx.resolved(config_path))];
    let given = path_text(config_path);
    if !prefixes.contains(&given) {
        prefixes.push(given);
    }
    let mut commands = BTreeSet::new();
    guard_commands(base, hooks, &mut commands)?;
    if let Some(before) = before {
        guard_commands(base, before, &mut commands)?;
    }
    let mut request = Map::new();
    request.insert("schema".into(), json!(TRUST_SCHEMA));
    request.insert("op".into(), json!(op));
    request.insert("events".into(), events(hooks, tokens));
    request.insert("state".into(), Value::Array(state));
    request.insert("prefixes".into(), json!(prefixes));
    request.insert("guard_commands".into(), json!(commands));
    Ok(request)
}

fn events(hooks: &[(String, PyVal)], tokens: &Map<String, Value>) -> Value {
    Value::Array(
        hooks
            .iter()
            .filter(|(_, groups)| matches!(groups, PyVal::List(_)))
            .map(|(name, groups)| json!([name, jsonable(groups, tokens)]))
            .collect(),
    )
}

/// Each live Guard handler command in `hooks`.
fn guard_commands(
    base: &Map<String, Value>,
    hooks: &[(String, PyVal)],
    found: &mut BTreeSet<String>,
) -> Step<()> {
    let mut request = Map::new();
    for key in ["windows", "long_paths"] {
        request.insert(key.into(), base.get(key).cloned().ok_or(Failure::Invalid)?);
    }
    for (_, groups) in hooks {
        let PyVal::List(groups) = groups else {
            continue;
        };
        for group in groups {
            let Some(PyVal::List(handlers)) = dict_get(group, "hooks") else {
                continue;
            };
            for handler in handlers {
                let Some(PyVal::Str(command)) = dict_get(handler, "command") else {
                    continue;
                };
                if found.contains(command) {
                    continue;
                }
                let mut extra = Map::new();
                extra.insert("command".into(), json!(command));
                let answer = owners_op(&request, "live", extra)?;
                if answer.get("live") == Some(&Value::Bool(true)) {
                    found.insert(command.clone());
                }
            }
        }
    }
    Ok(())
}

fn dict_get<'a>(value: &'a PyVal, key: &str) -> Option<&'a PyVal> {
    match value {
        PyVal::Dict(entries) => get(entries, key),
        _ => None,
    }
}

/// `codex_hook_trust._jsonable`: every distinction trust reads, with a
/// float, date or time made opaque.
fn jsonable(value: &PyVal, tokens: &Map<String, Value>) -> Value {
    let opaque = || json!(["opaque"]);
    match value {
        PyVal::Null => Value::Null,
        PyVal::Bool(flag) => json!(flag),
        PyVal::Int(digits) => serde_json::from_str(digits).unwrap_or_else(|_| opaque()),
        PyVal::Float(_) => opaque(),
        PyVal::Str(text) if tokens.contains_key(text) => opaque(),
        PyVal::Str(text) => json!(text),
        PyVal::List(items) => {
            Value::Array(items.iter().map(|item| jsonable(item, tokens)).collect())
        }
        PyVal::Dict(entries) => Value::Object(
            entries
                .iter()
                .map(|(key, item)| (key.clone(), jsonable(item, tokens)))
                .collect(),
        ),
    }
}

/// `payload[key] = value`, in place when the key is already there.
fn set(entries: &mut Vec<(String, PyVal)>, key: &str, value: PyVal) {
    match entries.iter_mut().find(|(existing, _)| existing == key) {
        Some((_, slot)) => *slot = value,
        None => entries.push((key.to_owned(), value)),
    }
}

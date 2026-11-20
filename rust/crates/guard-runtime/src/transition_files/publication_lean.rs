//! `publication_lean_sessions`: the Codex compaction limit Guard writes for
//! the user, ported from `codex_lean_sessions`.
//!
//! Codex's `model_auto_compact_token_limit` makes it summarize a session once
//! it passes that size. Guard writes the size the user asks for and never
//! touches a value the user set themselves: it records the value it wrote,
//! per config file, and only removes that exact value. The caller holds the
//! Codex install lock and has finished any interrupted hook publication.
//!
//! Request: `{"action": "path" | "status" | "enable" | "disable" | "check", "home":
//! <guard home>, "home_dir": <user home>, "codex_home": text | null,
//! "limit": <int>}`. Answer: the switch's view, or `{"error": <code>}` for a
//! refusal the user can act on. A failed write is a fault, after the record
//! is put back so Guard never claims a value it did not write.

use std::fs;
use std::path::{Path, PathBuf};

use serde_json::{json, Map, Value};

use super::output::managed_write;
use super::publication::Call;
use super::Step;
use crate::codex_value::HookVal;

const KEY: &str = "model_auto_compact_token_limit";
/// Below this Codex would summarize before a session has done any real work.
const MIN_LIMIT: i64 = 10_000;
const MAX_LIMIT: i64 = 10_000_000;
const SCHEMA: &str = "guard-codex-lean-sessions.v1";
const RECORD_NAME: &str = "codex-lean-sessions.json";
const PRIVATE_MODE: u32 = 0o600;

/// A refusal reported to the user by its stable code.
pub(super) struct Refusal(pub(super) &'static str);

pub(super) type Checked<T> = Result<T, Refusal>;

pub(super) fn lean_sessions(call: &mut Call<'_>) -> Step<Value> {
    let action = call.text("action")?.to_owned();
    let answer = match action.as_str() {
        "check" => check_limit(call.args.get("limit")).map(|limit| json!(limit)),
        "path" => {
            let (_, path) = paths(call)?;
            Ok(json!(path.to_string_lossy()))
        }
        "status" => {
            let (guard_home, path) = paths(call)?;
            status(&guard_home, &path)
        }
        "enable" => match check_limit(call.args.get("limit")) {
            Ok(limit) => {
                let (guard_home, path) = paths(call)?;
                return enable(call, &guard_home, &path, limit).map(answer_of);
            }
            Err(refusal) => Err(refusal),
        },
        "disable" => {
            let (guard_home, path) = paths(call)?;
            return disable(call, &guard_home, &path).map(answer_of);
        }
        _ => return Err(super::Fault::Transition("files_invalid")),
    };
    Ok(answer_of(answer))
}

fn answer_of(answer: Checked<Value>) -> Value {
    answer.unwrap_or_else(|Refusal(code)| json!({ "error": code }))
}

fn paths(call: &Call<'_>) -> Step<(PathBuf, PathBuf)> {
    let guard_home = call.home()?;
    let home_dir = call.path("home_dir")?;
    let codex_home = call.args.get("codex_home").and_then(Value::as_str);
    Ok((guard_home, config_path(&home_dir, codex_home)))
}

/// The config file Codex reads: `CODEX_HOME` when the environment sets it,
/// as Codex does, else `~/.codex`.
pub(super) fn config_path(home_dir: &Path, codex_home: Option<&str>) -> PathBuf {
    let base = codex_home.map(str::trim).unwrap_or_default();
    let base = if base.is_empty() {
        home_dir.join(".codex")
    } else if base == "~" {
        home_dir.to_path_buf()
    } else if let Some(rest) = base.strip_prefix("~/") {
        home_dir.join(rest)
    } else {
        PathBuf::from(base)
    };
    base.join("config.toml")
}

pub(super) fn check_limit(limit: Option<&Value>) -> Checked<i64> {
    match limit {
        None | Some(Value::Null) => Err(Refusal("codex_lean_limit_required")),
        Some(Value::Number(number)) => number
            .as_i64()
            .filter(|limit| (MIN_LIMIT..=MAX_LIMIT).contains(limit))
            .ok_or(Refusal("codex_lean_limit_invalid")),
        Some(_) => Err(Refusal("codex_lean_limit_invalid")),
    }
}

fn status(guard_home: &Path, path: &Path) -> Checked<Value> {
    let (_text, payload) = read_config(path)?;
    Ok(view(path, current(&payload), recorded(guard_home, path)))
}

fn enable(call: &mut Call<'_>, guard_home: &Path, path: &Path, limit: i64) -> Step<Checked<Value>> {
    let (text, mut payload) = match read_config(path) {
        Ok(read) => read,
        Err(refusal) => return Ok(Err(refusal)),
    };
    let recorded = recorded(guard_home, path);
    let current = current(&payload).cloned();
    let guard_owned =
        matches!((&current, recorded), (Some(value), Some(wrote)) if py_equals(value, wrote));
    let already = current
        .as_ref()
        .is_some_and(|value| py_equals(value, limit));
    if (current.is_some() && !guard_owned) || already {
        return Ok(Ok(view(path, current.as_ref(), recorded)));
    }
    // The record goes first: if Guard stops between the two writes, the
    // config still holds the earlier value and Guard never claims a value it
    // did not write.
    write_record(call, guard_home, path, Some(limit))?;
    set(&mut payload, HookVal::Int(limit.to_string()));
    if let Err(fault) = write_config(call, path, &payload, text.as_deref()) {
        write_record(call, guard_home, path, recorded.filter(|_| guard_owned))?;
        return Err(fault);
    }
    let written = HookVal::Int(limit.to_string());
    Ok(Ok(view(path, Some(&written), Some(limit))))
}

fn disable(call: &mut Call<'_>, guard_home: &Path, path: &Path) -> Step<Checked<Value>> {
    let (text, mut payload) = match read_config(path) {
        Ok(read) => read,
        Err(refusal) => return Ok(Err(refusal)),
    };
    let recorded = recorded(guard_home, path);
    let current = current(&payload).cloned();
    let ours =
        matches!((&current, recorded), (Some(value), Some(wrote)) if py_equals(value, wrote));
    if !ours {
        write_record(call, guard_home, path, None)?;
        return Ok(Ok(view(path, current.as_ref(), None)));
    }
    remove(&mut payload);
    write_config(call, path, &payload, text.as_deref())?;
    // A record left behind would claim a value the user sets later, so a
    // failed removal puts the config back as it was.
    if let Err(fault) = write_record(call, guard_home, path, None) {
        if let Some(original) = text.as_deref() {
            call.events
                .push(managed_write(path, original.as_bytes(), PRIVATE_MODE)?);
        }
        return Err(fault);
    }
    Ok(Ok(view(path, None, None)))
}

fn view(path: &Path, current: Option<&HookVal>, recorded: Option<i64>) -> Value {
    let state = match (current, recorded) {
        (None, _) => "off",
        (Some(value), Some(wrote)) if py_equals(value, wrote) => "on",
        _ => "yours",
    };
    json!({
        "schema": SCHEMA,
        "state": state,
        "limit": current.map_or(Value::Null, to_json),
        "config_path": path.to_string_lossy(),
    })
}

/// The config text and its parsed form. A file Guard cannot read stops the
/// change: writing a fresh file over it would lose the user's settings.
pub(super) fn read_config(path: &Path) -> Checked<(Option<String>, HookVal)> {
    // `Path.exists()` follows a link: a dangling one reads as no file.
    if fs::metadata(path).is_err() {
        return Ok((None, HookVal::Dict(Vec::new())));
    }
    let linked = fs::symlink_metadata(path).is_ok_and(|meta| meta.file_type().is_symlink());
    if linked || !path.is_file() {
        return Err(Refusal("codex_config_not_regular_file"));
    }
    let bytes = fs::read(path).map_err(|_| Refusal("codex_config_unreadable"))?;
    let text = String::from_utf8(bytes).map_err(|_| Refusal("codex_config_unreadable"))?;
    if crate::codex_toml_read::read(&text).is_err() {
        return Err(Refusal("codex_config_unreadable"));
    }
    let document = text
        .parse::<toml_edit::DocumentMut>()
        .map_err(|_| Refusal("codex_config_unreadable"))?;
    let payload = HookVal::from_document(document.as_table());
    Ok((Some(text), payload))
}

pub(super) fn write_config(
    call: &mut Call<'_>,
    path: &Path,
    payload: &HookVal,
    original: Option<&str>,
) -> Step<()> {
    let entries = payload.as_dict().unwrap_or_default();
    let rendered = crate::codex_toml_render::render(entries, original);
    call.events
        .push(managed_write(path, rendered.as_bytes(), PRIVATE_MODE)?);
    Ok(())
}

fn current(payload: &HookVal) -> Option<&HookVal> {
    payload.get(KEY)
}

fn set(payload: &mut HookVal, value: HookVal) {
    if let HookVal::Dict(entries) = payload {
        match entries.iter_mut().find(|(key, _)| key == KEY) {
            Some((_, slot)) => *slot = value,
            None => entries.push((KEY.to_owned(), value)),
        }
    }
}

fn remove(payload: &mut HookVal) {
    if let HookVal::Dict(entries) = payload {
        entries.retain(|(key, _)| key != KEY);
    }
}

/// Python `value == limit` for a value `tomllib` produced.
fn py_equals(value: &HookVal, limit: i64) -> bool {
    match value {
        HookVal::Int(digits) => *digits == limit.to_string(),
        HookVal::Float(number) => *number == limit as f64,
        HookVal::Bool(flag) => i64::from(*flag) == limit,
        _ => false,
    }
}

fn to_json(value: &HookVal) -> Value {
    match value {
        HookVal::Null => Value::Null,
        HookVal::Bool(flag) => json!(flag),
        HookVal::Int(digits) => serde_json::from_str(digits).unwrap_or_else(|_| json!(digits)),
        HookVal::Float(number) => json!(number),
        HookVal::Str(text) | HookVal::Temporal(_, text) => json!(text),
        HookVal::List(items) => Value::Array(items.iter().map(to_json).collect()),
        HookVal::Dict(entries) => Value::Object(
            entries
                .iter()
                .map(|(key, item)| (key.clone(), to_json(item)))
                .collect(),
        ),
    }
}

fn record_path(guard_home: &Path) -> PathBuf {
    guard_home.join(RECORD_NAME)
}

/// `str(path.expanduser().absolute())`.
pub(super) fn record_key(path: &Path) -> String {
    std::path::absolute(path)
        .unwrap_or_else(|_| path.to_path_buf())
        .to_string_lossy()
        .into_owned()
}

/// The value Guard wrote to each Codex config, keyed by the config's path:
/// with `CODEX_HOME`, one Guard home can edit more than one.
pub(super) fn records(guard_home: &Path) -> Map<String, Value> {
    let parsed = fs::read(record_path(guard_home))
        .ok()
        .and_then(|bytes| serde_json::from_slice::<Value>(&bytes).ok());
    let Some(Value::Object(configs)) = parsed.as_ref().and_then(|value| value.get("configs"))
    else {
        return Map::new();
    };
    configs
        .iter()
        .filter(|(_, value)| value.is_i64() || value.is_u64())
        .map(|(key, value)| (key.clone(), value.clone()))
        .collect()
}

fn recorded(guard_home: &Path, path: &Path) -> Option<i64> {
    records(guard_home)
        .get(&record_key(path))
        .and_then(Value::as_i64)
}

/// Record `value` for this config, or forget it when `value` is `None`.
fn write_record(
    call: &mut Call<'_>,
    guard_home: &Path,
    path: &Path,
    value: Option<i64>,
) -> Step<()> {
    let mut records = records(guard_home);
    match value {
        Some(value) => {
            records.insert(record_key(path), json!(value));
        }
        None => {
            records.remove(&record_key(path));
        }
    }
    let record = record_path(guard_home);
    if records.is_empty() {
        return match fs::remove_file(&record) {
            Err(error) if error.kind() != std::io::ErrorKind::NotFound => Err(error.into()),
            _ => Ok(()),
        };
    }
    call.events.push(managed_write(
        &record,
        record_text(&records).as_bytes(),
        PRIVATE_MODE,
    )?);
    Ok(())
}

/// `json.dumps({"configs": records}, sort_keys=True) + "\n"`.
pub(super) fn record_text(records: &Map<String, Value>) -> String {
    let mut keys: Vec<&String> = records.keys().collect();
    keys.sort();
    let body: Vec<String> = keys
        .into_iter()
        .map(|key| format!("{}: {}", ascii_string(key), records[key]))
        .collect();
    format!("{{\"configs\": {{{}}}}}\n", body.join(", "))
}

/// A JSON string with every non-ASCII character escaped, as `ensure_ascii`.
pub(super) fn ascii_string(text: &str) -> String {
    let quoted = Value::String(text.to_owned()).to_string();
    let mut out = String::with_capacity(quoted.len());
    for character in quoted.chars() {
        if character.is_ascii() {
            out.push(character);
        } else {
            let mut units = [0_u16; 2];
            for unit in character.encode_utf16(&mut units) {
                out.push_str(&format!("\\u{unit:04x}"));
            }
        }
    }
    out
}

#[cfg(test)]
#[path = "tests_publication_lean.rs"]
mod tests;

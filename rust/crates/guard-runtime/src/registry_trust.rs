//! `registry-trust --stdin`: the HOL Registry trust score cache and what
//! Guard Cloud's plugin search reply means. Ported from `registry_trust.py`
//! (`_fresh`, `_recently_unreachable`, `_load_cache`, `_store_cache` and
//! `_match_plugin_score`).
//!
//! A one-shot command rather than a resident kind: the resident asks Python
//! for a score while it composes the low-trust floor, so the lookup cannot
//! call back into it. Python still sends the search request; this command
//! keeps the cache under Guard's home and reads the reply:
//!
//! - `{"op": "lookup", "home", "artifact_type", "name", "now"}` answers
//!   `{"score"}` from the cache, or `{"fetch": name}` when Guard Cloud must
//!   be asked;
//! - `{"op": "record", ..., "status", "body"}` reads the search reply (the
//!   HTTP status, `null` when Guard Cloud could not be reached, and the body
//!   as base64, read up to one byte past the limit), records it and answers
//!   `{"score"}`.
//!
//! A score is an integer from 0 to 100; `null` is no score, which never
//! triggers a review.

use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};

use base64::{engine::general_purpose::STANDARD, Engine};
use guard_runtime_pyjson::{parse, PyVal};
use serde::Deserialize;
use serde_json::{json, Map, Number, Value};

use crate::daemon_lifecycle_text::py_strip;

const CACHE_FILE_NAME: &str = "registry-trust-cache.json";
const CACHE_SCHEMA: &str = "guard-registry-trust-cache.v1";
const SCORED_TTL_SECONDS: f64 = 24.0 * 60.0 * 60.0;
const UNSCORED_TTL_SECONDS: f64 = 6.0 * 60.0 * 60.0;
/// After a transport failure the network is skipped for a few minutes, so an
/// offline device does not wait on every evaluation.
const UNREACHABLE_KEY: &str = "origin:unreachable";
const UNREACHABLE_TTL_SECONDS: f64 = 5.0 * 60.0;
const MAX_CACHE_ENTRIES: usize = 512;
const MAX_NAME_CHARACTERS: usize = 256;
/// The reply limit, in bytes; a longer reply is not read as an answer.
const MAX_RESPONSE_BYTES: usize = 65_536;
/// The base64 body plus the request's other members.
const MAX_REQUEST_BYTES: u64 = 128 * 1024;

#[derive(Debug, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case", deny_unknown_fields)]
enum Request {
    Lookup {
        home: Option<String>,
        artifact_type: Option<String>,
        name: Option<String>,
        now: Number,
    },
    Record {
        home: Option<String>,
        artifact_type: Option<String>,
        name: Option<String>,
        now: Number,
        status: Option<u16>,
        body: String,
    },
}

pub(crate) fn is_command(command: &str) -> bool {
    command == "registry-trust"
}

pub(crate) fn run_command(reader: impl Read) -> Result<Vec<u8>, String> {
    let mut bytes = Vec::new();
    reader
        .take(MAX_REQUEST_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| "registry_trust_request_unreadable".to_owned())?;
    if bytes.len() as u64 > MAX_REQUEST_BYTES {
        return Err("registry_trust_request_too_large".to_owned());
    }
    let request: Value = serde_json::from_slice(&bytes).map_err(|_| invalid())?;
    serde_json::to_vec(&answer(request)?)
        .map_err(|_| "registry_trust_response_encode_failed".to_owned())
}

fn invalid() -> String {
    "registry_trust_request_invalid".to_owned()
}

fn answer(request: Value) -> Result<Value, String> {
    let request: Request = serde_json::from_value(request).map_err(|_| invalid())?;
    let (home, artifact_type, name, now, reply) = match request {
        Request::Lookup {
            home,
            artifact_type,
            name,
            now,
        } => (home, artifact_type, name, now, None),
        Request::Record {
            home,
            artifact_type,
            name,
            now,
            status,
            body,
        } => (
            home,
            artifact_type,
            name,
            now,
            Some(read_reply(status, &body)?),
        ),
    };
    let cache_path = match home {
        Some(home) if Path::new(&home).is_absolute() => {
            Some(Path::new(&home).join(CACHE_FILE_NAME))
        }
        Some(_) => return Err("registry_trust_home_invalid".to_owned()),
        None => None,
    };
    let clock = now.as_f64().ok_or_else(invalid)?;
    let Some(name) = lookup_name(artifact_type.as_deref(), name.as_deref()) else {
        return Ok(json!({"score": null}));
    };
    let key = format!("plugin:{}", name.to_lowercase());
    let mut cache = load_cache(cache_path.as_deref());
    let Some(reply) = reply else {
        if let Some(entry) = cache.get(&key).filter(|entry| fresh(entry, clock)) {
            return Ok(json!({"score": entry.get("score").filter(|score| is_int(score))}));
        }
        if recently_unreachable(cache.get(UNREACHABLE_KEY), clock) {
            return Ok(json!({"score": null}));
        }
        return Ok(json!({"fetch": name}));
    };
    let Some(payload) = reply else {
        // A transport failure is not an answer: keep any stale entry and
        // retry once the marker expires.
        cache.insert(UNREACHABLE_KEY.to_owned(), json!({"checked_at": now}));
        store_cache(cache_path.as_deref(), cache);
        return Ok(json!({"score": null}));
    };
    let score = match_plugin_score(&payload, name);
    cache.remove(UNREACHABLE_KEY);
    cache.insert(key, json!({"score": score, "checked_at": now}));
    store_cache(cache_path.as_deref(), cache);
    Ok(json!({"score": score}))
}

/// The name to look up, or `None` when the registry scores no such artifact.
/// Guard Cloud exposes plugin trust today; skill and MCP scores need a
/// registry route the origin does not serve yet.
fn lookup_name<'a>(artifact_type: Option<&str>, name: Option<&'a str>) -> Option<&'a str> {
    let name = py_strip(name.unwrap_or_default());
    let scored = matches!(artifact_type, Some("plugin" | "extension"));
    (scored && !name.is_empty() && name.chars().count() <= MAX_NAME_CHARACTERS).then_some(name)
}

/// The parsed search reply, or `Ok(None)` when Guard Cloud gave no usable answer.
fn read_reply(status: Option<u16>, body: &str) -> Result<Option<PyVal>, String> {
    let raw = STANDARD.decode(body).map_err(|_| invalid())?;
    if status != Some(200) || raw.len() > MAX_RESPONSE_BYTES {
        return Ok(None);
    }
    let Ok(text) = std::str::from_utf8(&raw) else {
        return Ok(None);
    };
    Ok(parse(text.strip_prefix('\u{feff}').unwrap_or(text)).ok())
}

/// Score of the one catalog plugin whose slug or display name is `name`.
///
/// Search is fuzzy, so only an exact, unambiguous name match counts; anything
/// else is an unknown plugin, which never triggers review.
fn match_plugin_score(payload: &PyVal, name: &str) -> Option<i64> {
    let plugins = payload.get("plugins").and_then(PyVal::as_list)?;
    let wanted = name.to_lowercase();
    let mut matched = 0;
    let mut scores: Vec<i64> = Vec::new();
    for plugin in plugins {
        if plugin.as_dict().is_none() || !plugin_names(plugin).contains(&wanted) {
            continue;
        }
        matched += 1;
        if let Some(score) = plugin.get("trustScore").and_then(trust_score) {
            if !scores.contains(&score) {
                scores.push(score);
            }
        }
    }
    if matched == 1 && scores.len() == 1 {
        scores.first().copied()
    } else {
        None
    }
}

/// `round(score)` for a number from 0 to 100; Python rounds half to even.
fn trust_score(value: &PyVal) -> Option<i64> {
    let number = match value {
        PyVal::Int(digits) => digits.parse::<i64>().ok()? as f64,
        PyVal::Float(number) => *number,
        _ => return None,
    };
    (0.0..=100.0)
        .contains(&number)
        .then_some(number.round_ties_even() as i64)
}

fn plugin_names(plugin: &PyVal) -> Vec<String> {
    let mut names = Vec::new();
    if let Some(slug) = plugin.get("slug").and_then(PyVal::as_str) {
        let slug = py_strip(slug).to_lowercase();
        if !slug.is_empty() {
            names.push(slug.rsplit('/').next().unwrap_or_default().to_owned());
            names.push(slug);
        }
    }
    if let Some(display) = plugin.get("displayName").and_then(PyVal::as_str) {
        let display = py_strip(display).to_lowercase();
        if !display.is_empty() {
            names.push(display);
        }
    }
    names
}

/// An integer score, as Python's `isinstance(score, int)` reads the cache.
fn is_int(value: &Value) -> bool {
    value.is_i64() || value.is_u64()
}

/// When the entry was written, unless it is missing or in the future.
fn checked_before(entry: &Value, now: f64) -> Option<f64> {
    let checked_at = entry.get("checked_at")?.as_f64()?;
    (checked_at <= now).then_some(checked_at)
}

fn fresh(entry: &Value, now: f64) -> bool {
    let ttl = if entry.get("score").is_some_and(is_int) {
        SCORED_TTL_SECONDS
    } else {
        UNSCORED_TTL_SECONDS
    };
    checked_before(entry, now).is_some_and(|checked_at| now - checked_at < ttl)
}

fn recently_unreachable(entry: Option<&Value>, now: f64) -> bool {
    entry
        .and_then(|entry| checked_before(entry, now))
        .is_some_and(|checked_at| now - checked_at < UNREACHABLE_TTL_SECONDS)
}

/// The cached entries, or none when the cache is missing or not Guard's.
fn load_cache(path: Option<&Path>) -> Map<String, Value> {
    let Some(document) = path
        .and_then(|path| fs::read(path).ok())
        .and_then(|bytes| serde_json::from_slice::<Value>(&bytes).ok())
    else {
        return Map::new();
    };
    if document.get("schema").and_then(Value::as_str) != Some(CACHE_SCHEMA) {
        return Map::new();
    }
    let Some(Value::Object(entries)) = document.get("entries") else {
        return Map::new();
    };
    entries
        .iter()
        .filter(|(_, entry)| entry.is_object())
        .map(|(key, entry)| (key.clone(), entry.clone()))
        .collect()
}

/// Keep the newest entries and replace the cache file in one rename. The
/// cache is best effort: a write that fails leaves the old file.
fn store_cache(path: Option<&Path>, cache: Map<String, Value>) {
    let Some(path) = path else {
        return;
    };
    let mut entries: Vec<(String, Value)> = cache.into_iter().collect();
    let checked_at = |entry: &Value| {
        entry
            .get("checked_at")
            .and_then(Value::as_f64)
            .unwrap_or(0.0)
    };
    entries.sort_by(|left, right| checked_at(&right.1).total_cmp(&checked_at(&left.1)));
    entries.truncate(MAX_CACHE_ENTRIES);
    let document = json!({"schema": CACHE_SCHEMA, "entries": Map::from_iter(entries)});
    let Ok(bytes) = serde_json::to_vec(&document) else {
        return;
    };
    let temporary = temporary_path(path);
    let written = path
        .parent()
        .map_or(Ok(()), fs::create_dir_all)
        .and_then(|()| fs::write(&temporary, bytes))
        .and_then(|()| fs::rename(&temporary, path));
    if written.is_err() {
        let _ = fs::remove_file(&temporary);
    }
}

fn temporary_path(path: &Path) -> PathBuf {
    path.with_file_name(format!(".{CACHE_FILE_NAME}.{}.tmp", std::process::id()))
}

#[cfg(test)]
#[path = "registry_trust_tests.rs"]
mod tests;

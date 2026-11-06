//! `codex-hook-trust --stdin`: Codex's hook trust hash, and the stale, record
//! and remap operations Guard runs over `[hooks.state]`
//! (`guard/codex_hook_trust.py` frames the request).
//!
//! Codex (`codex-rs/hooks/src/engine/discovery.rs` `hook_hash` and
//! `codex-rs/config/src/fingerprint.rs` `version_for_toml`) only runs a
//! user-layer hook when `[hooks.state."<key>"].trusted_hash` equals the hash
//! of the hook's normalized identity.
//!
//! - Python sends the hooks table as `[event, groups]` pairs and the state
//!   table as `[key, entry]` pairs, so the answers keep the config's order.
//!   Values TOML can hold but JSON cannot arrive as an opaque list, which no
//!   check below mistakes for a table, string, integer or boolean.
//! - Python names the commands it recognizes as Guard's own handlers in
//!   `guard_commands`; this module never parses a command line.
//! - Answers name state keys, never state entries, so Python edits its own
//!   table and nothing it holds is round-tripped through JSON.

use std::collections::{BTreeMap, BTreeSet};
use std::io::Read;

use serde::Deserialize;
use serde_json::{json, Map, Number, Value};
use sha2::{Digest, Sha256};

use crate::context_digest::python_strip;

const SCHEMA: &str = "codex-hook-trust.v1";
const MAX_REQUEST_BYTES: u64 = 8 * 1024 * 1024;
const MATCHERLESS_EVENTS: [&str; 3] = ["UserPromptSubmit", "Stop", "Interrupt"];
const SHORT_TIMEOUT_EVENTS: [&str; 2] = ["SessionEnd", "Interrupt"];
const CONTEXT_LIMIT_EVENTS: [&str; 5] = [
    "PreToolUse",
    "PostToolUse",
    "SessionStart",
    "UserPromptSubmit",
    "SubagentStart",
];
const DEFAULT_TIMEOUT_SEC: i64 = 600;
const SHORT_DEFAULT_TIMEOUT_SEC: i64 = 1;
const SHORT_MAX_TIMEOUT_SEC: i64 = 3;
const DEFAULT_CONTEXT_LIMIT: &str = "2500";

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Request {
    schema: String,
    op: String,
    #[serde(default)]
    event: String,
    #[serde(default)]
    matcher: Value,
    #[serde(default)]
    handler: Value,
    #[serde(default)]
    events: Vec<(String, Value)>,
    #[serde(default)]
    before_events: Vec<(String, Value)>,
    #[serde(default)]
    state: Vec<(String, Value)>,
    #[serde(default)]
    prefixes: Vec<String>,
    #[serde(default)]
    guard_commands: BTreeSet<String>,
}

pub(crate) fn is_command(command: &str) -> bool {
    command == "codex-hook-trust"
}

pub(crate) fn run_command(reader: impl Read) -> Result<Vec<u8>, String> {
    let mut bytes = Vec::new();
    reader
        .take(MAX_REQUEST_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| "codex_hook_trust_request_unreadable".to_owned())?;
    if bytes.len() as u64 > MAX_REQUEST_BYTES {
        return Err("codex_hook_trust_request_too_large".to_owned());
    }
    let request: Request = serde_json::from_slice(&bytes).map_err(|_| invalid())?;
    if request.schema != SCHEMA {
        return Err(invalid());
    }
    let answer = answer(&request)?;
    Ok(answer.to_string().into_bytes())
}

fn invalid() -> String {
    "codex_hook_trust_request_invalid".to_owned()
}

fn answer(request: &Request) -> Result<Value, String> {
    let mut prefixes: Vec<&str> = Vec::new();
    for prefix in &request.prefixes {
        if !prefixes.contains(&prefix.as_str()) {
            prefixes.push(prefix.as_str());
        }
    }
    match request.op.as_str() {
        "hash" => {
            let hash = request
                .handler
                .as_object()
                .and_then(|handler| command_hook_hash(&request.event, &request.matcher, handler));
            Ok(json!({ "hash": hash }))
        }
        "stale" if !prefixes.is_empty() => Ok(json!({ "stale": stale(request, &prefixes) })),
        "record" if !prefixes.is_empty() => Ok(json!({ "recorded": record(request, &prefixes) })),
        "remap" if !prefixes.is_empty() => Ok(json!({ "state": remap(request, &prefixes) })),
        _ => Err(invalid()),
    }
}

fn event_label(event: &str) -> Option<&'static str> {
    Some(match event {
        "PreToolUse" => "pre_tool_use",
        "PermissionRequest" => "permission_request",
        "PostToolUse" => "post_tool_use",
        "PreCompact" => "pre_compact",
        "PostCompact" => "post_compact",
        "SessionStart" => "session_start",
        "SessionEnd" => "session_end",
        "UserPromptSubmit" => "user_prompt_submit",
        "SubagentStart" => "subagent_start",
        "SubagentStop" => "subagent_stop",
        "Stop" => "stop",
        "Interrupt" => "interrupt",
        _ => return None,
    })
}

/// A Python `int`: JSON digits with an optional sign, never a float spelling
/// such as `5.0` or `1e3`.
fn integer(value: &Value) -> Option<&Number> {
    let Value::Number(number) = value else {
        return None;
    };
    let text = number.to_string();
    let digits = text.strip_prefix('-').unwrap_or(&text);
    (!digits.is_empty() && digits.bytes().all(|byte| byte.is_ascii_digit())).then_some(number)
}

/// `max(value, 1)`, kept exact for integers wider than 64 bits.
fn at_least_one(number: &Number) -> Value {
    let text = number.to_string();
    if text.starts_with('-') || text.bytes().all(|byte| byte == b'0') {
        json!(1)
    } else {
        Value::Number(number.clone())
    }
}

/// `min(max(value, 1), 3)` for the events Codex gives a short budget.
fn short_timeout(number: &Number) -> i64 {
    let text = number.to_string();
    if text.starts_with('-') {
        return SHORT_DEFAULT_TIMEOUT_SEC;
    }
    text.parse::<i64>()
        .unwrap_or(i64::MAX)
        .clamp(SHORT_DEFAULT_TIMEOUT_SEC, SHORT_MAX_TIMEOUT_SEC)
}

/// `codex_command_hook_hash`: Codex's `current_hash` for one command
/// handler, or `None` when Codex would not hash it.
fn command_hook_hash(event: &str, matcher: &Value, handler: &Map<String, Value>) -> Option<String> {
    let label = event_label(event)?;
    if handler.get("type").and_then(Value::as_str) != Some("command") {
        return None;
    }
    let mut command = handler.get("command")?.as_str()?;
    if cfg!(windows) {
        if let Some(windows) = handler.get("commandWindows").and_then(Value::as_str) {
            command = windows;
        }
    }
    if python_strip(command).is_empty() {
        return None;
    }
    let timeout = match handler.get("timeout") {
        None | Some(Value::Null) => None,
        Some(value) => Some(integer(value)?),
    };
    let normalized_timeout = if SHORT_TIMEOUT_EVENTS.contains(&event) {
        json!(timeout.map_or(SHORT_DEFAULT_TIMEOUT_SEC, short_timeout))
    } else {
        timeout.map_or(json!(DEFAULT_TIMEOUT_SEC), at_least_one)
    };
    let mut normalized = Map::new();
    normalized.insert("type".into(), json!("command"));
    normalized.insert("command".into(), json!(command));
    normalized.insert("timeout".into(), normalized_timeout);
    normalized.insert(
        "async".into(),
        json!(handler.get("async") == Some(&Value::Bool(true))),
    );
    if let Some(Value::String(message)) = handler.get("statusMessage") {
        normalized.insert("statusMessage".into(), json!(message));
    }
    if CONTEXT_LIMIT_EVENTS.contains(&event) {
        if let Some(limit) = handler.get("additionalContextLimit").and_then(integer) {
            if limit.to_string() != DEFAULT_CONTEXT_LIMIT {
                normalized.insert(
                    "additionalContextLimit".into(),
                    Value::Number(limit.clone()),
                );
            }
        }
    }
    let mut identity = Map::new();
    identity.insert("event_name".into(), json!(label));
    identity.insert(
        "hooks".into(),
        Value::Array(vec![Value::Object(normalized)]),
    );
    if let (false, Value::String(matcher)) = (MATCHERLESS_EVENTS.contains(&event), matcher) {
        identity.insert("matcher".into(), json!(matcher));
    }
    let serialized = Value::Object(identity).to_string();
    Some(format!(
        "sha256:{}",
        hex::encode(Sha256::digest(serialized.as_bytes()))
    ))
}

/// `_hook_entry_is_active`.
fn active(entry: &Map<String, Value>) -> bool {
    entry.get("enabled") != Some(&Value::Bool(false))
        && entry.get("disabled") != Some(&Value::Bool(true))
}

/// One command handler in the hooks table.
struct Handler<'a> {
    event: &'a str,
    label: &'static str,
    coordinate: String,
    matcher: &'a Value,
    group_active: bool,
    handler: &'a Map<String, Value>,
}

/// Every mapping handler of every labelled event, in config order.
fn handlers(events: &[(String, Value)]) -> Vec<Handler<'_>> {
    let mut found = Vec::new();
    for (event, groups) in events {
        let (Some(label), Some(groups)) = (event_label(event), groups.as_array()) else {
            continue;
        };
        for (group_index, group) in groups.iter().enumerate() {
            let Some(group) = group.as_object() else {
                continue;
            };
            let Some(entries) = group.get("hooks").and_then(Value::as_array) else {
                continue;
            };
            for (handler_index, handler) in entries.iter().enumerate() {
                let Some(handler) = handler.as_object() else {
                    continue;
                };
                found.push(Handler {
                    event,
                    label,
                    coordinate: format!("{label}:{group_index}:{handler_index}"),
                    matcher: group.get("matcher").unwrap_or(&Value::Null),
                    group_active: active(group),
                    handler,
                });
            }
        }
    }
    found
}

impl Handler<'_> {
    fn guard(&self, request: &Request) -> bool {
        self.handler
            .get("command")
            .and_then(Value::as_str)
            .is_some_and(|command| request.guard_commands.contains(command))
    }

    fn hash(&self) -> Option<String> {
        command_hook_hash(self.event, self.matcher, self.handler)
    }
}

/// `_guard_hook_coordinates`: the state keys and expected hash of each live
/// Guard handler. Codex keys state by the canonical config path; the alias
/// key only answers whether the user switched the hook off.
fn guard_hooks(request: &Request, prefixes: &[&str]) -> Vec<(Vec<String>, String)> {
    handlers(&request.events)
        .into_iter()
        .filter(|found| found.group_active && active(found.handler) && found.guard(request))
        .filter_map(|found| {
            let expected = found.hash()?;
            let keys = prefixes
                .iter()
                .map(|prefix| format!("{prefix}:{}", found.coordinate))
                .collect();
            Some((keys, expected))
        })
        .collect()
}

fn state_map(request: &Request) -> BTreeMap<&str, &Value> {
    request
        .state
        .iter()
        .map(|(key, entry)| (key.as_str(), entry))
        .collect()
}

fn disabled(entry: &Map<String, Value>) -> bool {
    entry.get("enabled") == Some(&Value::Bool(false))
}

fn trusts(entry: &Map<String, Value>, expected: &str) -> bool {
    entry.get("trusted_hash").and_then(Value::as_str) == Some(expected)
}

/// `stale_guard_hook_coordinates`: canonical keys of live Guard hooks whose
/// trust is missing or stale. A hook switched off in `/hooks` never runs, so
/// its trust is irrelevant.
fn stale(request: &Request, prefixes: &[&str]) -> Vec<String> {
    let state = state_map(request);
    let mut stale = Vec::new();
    for (keys, expected) in guard_hooks(request, prefixes) {
        let entries: Vec<&Map<String, Value>> = keys
            .iter()
            .filter_map(|key| state.get(key.as_str()).and_then(|entry| entry.as_object()))
            .collect();
        if entries.iter().any(|entry| disabled(entry)) {
            continue;
        }
        if !entries.iter().any(|entry| trusts(entry, &expected)) {
            stale.extend(keys.into_iter().next());
        }
    }
    stale
}

/// `record_guard_hook_trust`: `[key, source, hash]` for each live Guard hook
/// whose canonical key lacks the current hash. Python copies the entry at
/// `source` (or starts an empty one), sets `trusted_hash`, and stores it at
/// `key`. A hook the user switched off keeps that choice.
fn record(request: &Request, prefixes: &[&str]) -> Vec<Value> {
    let state = state_map(request);
    let mut recorded = Vec::new();
    for (keys, expected) in guard_hooks(request, prefixes) {
        let existing = keys.iter().find_map(|key| {
            state
                .get(key.as_str())
                .and_then(|entry| entry.as_object())
                .map(|entry| (key.as_str(), entry))
        });
        if existing.is_some_and(|(_, entry)| disabled(entry)) {
            continue;
        }
        let canonical = &keys[0];
        let current = state
            .get(canonical.as_str())
            .and_then(|entry| entry.as_object())
            .is_some_and(|entry| trusts(entry, &expected));
        if current {
            continue;
        }
        recorded.push(json!([canonical, existing.map(|(key, _)| key), expected]));
    }
    recorded
}

/// `remap_hook_state`: `[key, source]` for the state table after each hook's
/// state follows its handler to the coordinate it now occupies, or `None`
/// when there is no state to move. A `null` source stands for
/// `{"enabled": false}`, the one choice a replaced Guard handler hands to its
/// sole replacement on the same event.
fn remap(request: &Request, prefixes: &[&str]) -> Option<Vec<Value>> {
    if request.state.is_empty() {
        return None;
    }
    let (was, was_guard) = coordinates(request, &request.before_events);
    let (now, now_guard) = coordinates(request, &request.events);
    let mut kept: Vec<(String, Option<&str>)> = Vec::new();
    let mut moves: Vec<(String, Option<&str>)> = Vec::new();
    for (key, entry) in &request.state {
        let found = prefixes.iter().find_map(|prefix| {
            key.strip_prefix(prefix)
                .and_then(|rest| rest.strip_prefix(':'))
                .map(|coordinate| (*prefix, coordinate))
        });
        let digest = found.and_then(|(_, coordinate)| was.get(coordinate));
        let (Some((prefix, coordinate)), Some(digest)) = (found, digest) else {
            kept.push((key.clone(), Some(key.as_str())));
            continue;
        };
        if now.get(coordinate) == Some(digest) {
            kept.push((key.clone(), Some(key.as_str())));
            continue;
        }
        let moved: Vec<&String> = now
            .iter()
            .filter(|(_, hash)| *hash == digest)
            .map(|(name, _)| name)
            .collect();
        // Only an unambiguous move carries the user's choice. A handler that
        // is gone, or now matches several coordinates, leaves its state behind.
        if let [target] = moved.as_slice() {
            moves.push((format!("{prefix}:{target}"), Some(key.as_str())));
            continue;
        }
        let Some(label) = was_guard.get(coordinate) else {
            continue;
        };
        if !moved.is_empty() || !entry.as_object().is_some_and(disabled) {
            continue;
        }
        let targets: Vec<&String> = now_guard
            .iter()
            .filter(|(_, event)| *event == label)
            .map(|(name, _)| name)
            .collect();
        if let [target] = targets.as_slice() {
            moves.push((format!("{prefix}:{target}"), None));
        }
    }
    for (key, source) in moves {
        if !kept.iter().any(|(name, _)| *name == key) {
            kept.push((key, source));
        }
    }
    Some(
        kept.into_iter()
            .map(|(key, source)| json!([key, source]))
            .collect(),
    )
}

/// `_handler_coordinates` and `_guard_coordinates`: each hashable handler's
/// hash, and each Guard handler's event label, by coordinate. A handler the
/// user switched off still counts: that choice is what the remap carries.
type Coordinates = (BTreeMap<String, String>, BTreeMap<String, &'static str>);

fn coordinates(request: &Request, events: &[(String, Value)]) -> Coordinates {
    let mut all = BTreeMap::new();
    let mut guard = BTreeMap::new();
    for found in handlers(events) {
        if found.guard(request) {
            guard.insert(found.coordinate.clone(), found.label);
        }
        if let Some(hash) = found.hash() {
            all.insert(found.coordinate, hash);
        }
    }
    (all, guard)
}

#[cfg(test)]
#[path = "codex_hook_trust_tests.rs"]
mod tests;

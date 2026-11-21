//! The MCP server helpers `guard/adapters/mcp_servers.py` and
//! `guard/adapters/harness_mcp_discovery.py` held beside the harness adapters:
//! the Guard companion test, the configured server names, the source label
//! overlay and the servers a managed install skips.
//!
//! None of these ops reads a context: each answers from the fields the
//! request carries. Python still projects its typed artifact metadata into
//! JSON-safe request rows and renders the answers.

use std::collections::{HashMap, HashSet};

use serde_json::{json, Map, Value};

use super::{Failure, Step};
use crate::cloud_request_text::py_strip;
use crate::cursor_editor_plan::is_guard_proxy;
use crate::harness_mcp_discovery;

/// `GUARD_MCP_COMPANION_PREFIX`.
const COMPANION_PREFIX: &str = "hol-guard::";

pub(super) fn handles(op: &str) -> bool {
    matches!(
        op,
        "mcp_companion" | "mcp_server_names" | "mcp_source_labels" | "mcp_skipped"
    )
}

pub(super) fn dispatch(op: &str, fields: &Map<String, Value>) -> Step<Value> {
    match op {
        "mcp_companion" => companion(fields),
        "mcp_server_names" => server_names(fields),
        "mcp_source_labels" => source_labels(fields),
        "mcp_skipped" => skipped(fields),
        _ => Err(Failure::Invalid),
    }
}

fn text<'a>(map: &'a Map<String, Value>, key: &str) -> Step<&'a str> {
    map.get(key).and_then(Value::as_str).ok_or(Failure::Invalid)
}

fn list<'a>(map: &'a Map<String, Value>, key: &str) -> Step<&'a Vec<Value>> {
    map.get(key)
        .and_then(Value::as_array)
        .ok_or(Failure::Invalid)
}

fn object(value: &Value) -> Step<&Map<String, Value>> {
    value.as_object().ok_or(Failure::Invalid)
}

/// `is_guard_mcp_companion_name` and `is_verified_guard_mcp_companion`: a
/// companion carries the Guard prefix, and is verified when its launch is
/// also a Guard MCP proxy.
fn companion(fields: &Map<String, Value>) -> Step<Value> {
    let name = text(fields, "name")?;
    let command = match fields.get("command") {
        None | Some(Value::Null) => None,
        Some(Value::String(command)) => Some(command.as_str()),
        Some(_) => return Err(Failure::Invalid),
    };
    let args = list(fields, "args")?
        .iter()
        .map(|arg| arg.as_str().map(str::to_owned).ok_or(Failure::Invalid))
        .collect::<Step<Vec<_>>>()?;
    let named = name.starts_with(COMPANION_PREFIX);
    Ok(json!({
        "companion": named,
        "verified": named && is_guard_proxy(command, &args),
    }))
}

/// `configured_mcp_server_names`: each harness, in first-seen order, with the
/// stripped names of its `mcp_server` artifacts in first-seen order.
fn server_names(fields: &Map<String, Value>) -> Step<Value> {
    let mut harnesses: Vec<(&str, Vec<&str>)> = Vec::new();
    let mut index: HashMap<&str, usize> = HashMap::new();
    let mut seen: HashSet<(usize, &str)> = HashSet::new();
    for row in list(fields, "artifacts")? {
        let row = object(row)?;
        let (harness, kind, name) = (
            text(row, "harness")?,
            text(row, "artifact_type")?,
            text(row, "name")?,
        );
        let name = py_strip(name);
        if kind != "mcp_server" || name.is_empty() {
            continue;
        }
        let slot = *index.entry(harness).or_insert_with(|| {
            harnesses.push((harness, Vec::new()));
            harnesses.len() - 1
        });
        if seen.insert((slot, name)) {
            harnesses[slot].1.push(name);
        }
    }
    Ok(json!({ "names": harnesses }))
}

/// `apply_source_labels`: the label each listed item takes, or null when its
/// `cli_id` is not text or has no non-empty label.
fn source_labels(fields: &Map<String, Value>) -> Step<Value> {
    let labels = object(fields.get("labels").ok_or(Failure::Invalid)?)?;
    if !labels.values().all(Value::is_string) {
        return Err(Failure::Invalid);
    }
    let chosen = list(fields, "cli_ids")?
        .iter()
        .map(|cli_id| match cli_id {
            Value::Null => Ok(Value::Null),
            Value::String(cli_id) => Ok(labels
                .get(cli_id)
                .filter(|label| label.as_str().is_some_and(|label| !label.is_empty()))
                .cloned()
                .unwrap_or(Value::Null)),
            _ => Err(Failure::Invalid),
        })
        .collect::<Step<Vec<_>>>()?;
    Ok(json!({ "labels": chosen }))
}

/// `skipped_stdio_server_names`: the positions of the named artifacts Guard
/// cannot run behind its proxy. Each entry is `{name, request}` where
/// `request` is the `select` row Python built, or null for one it could not
/// encode; an entry with a blank name is not considered. Python keeps the
/// names themselves. No `select` runs when no request is left.
pub(super) fn skipped(fields: &Map<String, Value>) -> Step<Value> {
    let mut named: Vec<(usize, Option<&Value>)> = Vec::new();
    for (position, entry) in list(fields, "entries")?.iter().enumerate() {
        let entry = object(entry)?;
        let name = text(entry, "name")?;
        let request = match entry.get("request") {
            Some(Value::Null) => None,
            Some(request) if request.is_object() => Some(request),
            _ => return Err(Failure::Invalid),
        };
        if !py_strip(name).is_empty() {
            named.push((position, request));
        }
    }
    let requests: Vec<&Value> = named.iter().filter_map(|(_, request)| *request).collect();
    let mut found = Vec::new();
    if !requests.is_empty() {
        let answer = harness_mcp_discovery::dispatch(&json!({
            "op": "select",
            "include_proxy": false,
            "artifacts": requests,
        }))
        .map_err(|_| Failure::Invalid)?;
        found = answer
            .get("servers")
            .and_then(Value::as_array)
            .filter(|servers| servers.len() == requests.len())
            .ok_or(Failure::Invalid)?
            .clone();
    }
    let mut selected = found.iter();
    let mut positions = Vec::new();
    for (position, request) in named {
        let server = request.and_then(|_| selected.next());
        if server.is_none_or(Value::is_null) {
            positions.push(position);
        }
    }
    Ok(json!({ "skipped": positions }))
}

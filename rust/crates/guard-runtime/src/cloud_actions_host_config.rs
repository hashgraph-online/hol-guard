//! The one settings entry that adds Cloud actions to an AI tool.
//!
//! The plan renders the whole settings file as it would be written and checks
//! that, apart from the `hol-guard-cloud` entry, it reads back exactly as
//! before; the undo puts that entry back as it was, or removes it, under the
//! same check. Reading and writing the file is `cloud_actions_host_apply`.
//! JSON files keep their own indentation, line endings and key order; TOML
//! files are edited in place, so comments and layout are kept.

use std::io::Read;

use serde::Deserialize;
use serde_json::{json, Map, Value};

#[path = "cloud_actions_host_config_url.rs"]
mod address;
#[path = "cloud_actions_host_config_fields.rs"]
mod fields;
#[path = "cloud_actions_host_config_json.rs"]
mod json_text;
#[path = "cloud_actions_host_config_toml.rs"]
mod toml_text;

use self::address::{display_url, points_at};
use self::fields::{guard_fields, Fields};
use self::json_text::{dump_like, is_blank, json_root, lookup, parse_json, set, upsert, Node};
use self::toml_text::{toml_edit_entry, toml_remove_entry};

const SERVER_NAME: &str = "hol-guard-cloud";
const MAX_SETTINGS_BYTES: u64 = 32 * 1024 * 1024;
// Two settings texts, each at most six times longer once escaped as JSON.
const MAX_REQUEST_BYTES: u64 = 12 * MAX_SETTINGS_BYTES + 1024 * 1024;
const BRIDGE_ARGS: [&str; 2] = ["cloud-actions", "bridge"];
const DUPLICATE_KEY: &str = "guard-duplicate-key";

const NOT_JSON: &str = "The settings file is not valid JSON.";
const NOT_OBJECT: &str = "The settings file does not hold a JSON object.";
const NOT_TOML: &str = "The settings file is not valid TOML.";
const REPEATED_KEY: &str =
    "The settings file repeats a key, so rewriting it could change what it means.";
const UNWRITABLE_TEXT: &str = "The settings file holds text that cannot be written back unchanged.";
const EDIT_ERROR: &str = "Guard could not edit the settings file without changing other settings.";

#[derive(Clone, Copy, PartialEq, Eq)]
enum Format {
    Json,
    Toml,
}

struct Tool {
    slug: &'static str,
    format: Format,
    table: &'static str,
    typed: bool,
}

const TOOLS: [Tool; 3] = [
    Tool {
        slug: "claude-code",
        format: Format::Json,
        table: "mcpServers",
        typed: true,
    },
    Tool {
        slug: "codex",
        format: Format::Toml,
        table: "mcp_servers",
        typed: false,
    },
    Tool {
        slug: "cursor",
        format: Format::Json,
        table: "mcpServers",
        typed: false,
    },
];

pub(crate) fn is_command(command: &str) -> bool {
    command == "cloud-actions-host-config"
}

pub(crate) fn run_command(reader: impl Read) -> Result<Vec<u8>, String> {
    let mut bytes = Vec::new();
    reader
        .take(MAX_REQUEST_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| "cloud_actions_host_config_request_unreadable".to_owned())?;
    if bytes.len() as u64 > MAX_REQUEST_BYTES {
        return Err("cloud_actions_host_config_request_too_large".to_owned());
    }
    let invalid = || "cloud_actions_host_config_request_invalid".to_owned();
    let request: Value = serde_json::from_slice(&bytes).map_err(|_| invalid())?;
    let answer = answer(request).ok_or_else(invalid)?;
    serde_json::to_vec(&answer)
        .map_err(|_| "cloud_actions_host_config_response_encode_failed".to_owned())
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PlanRequest {
    #[serde(rename = "op")]
    _op: String,
    ai_tool: String,
    before: Option<String>,
    entry: Value,
    url: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct UndoRequest {
    #[serde(rename = "op")]
    _op: String,
    ai_tool: String,
    current: String,
    written: Value,
    prior: Option<String>,
}

fn answer(request: Value) -> Option<Value> {
    let op = request.get("op").and_then(Value::as_str)?.to_owned();
    match op.as_str() {
        "plan" => {
            let request: PlanRequest = serde_json::from_value(request).ok()?;
            plan_text(
                &request.ai_tool,
                request.before.as_deref(),
                &request.entry,
                &request.url,
            )
        }
        "undo" => {
            let request: UndoRequest = serde_json::from_value(request).ok()?;
            let undone = undo_text(
                &request.ai_tool,
                &request.current,
                &request.written,
                request.prior.as_deref(),
            )?;
            Some(match undone {
                Ok((after, removed)) => json!({"after": after, "removed": removed}),
                Err(problem) => json!({"problem": problem}),
            })
        }
        _ => crate::cloud_actions_host_apply::answer(&op, request),
    }
}

/// Whether `slug` names an AI tool with a Cloud actions setup.
pub(crate) fn supports(slug: &str) -> bool {
    tool(slug).is_some()
}

/// The plan for one settings text; `None` when the AI tool or the entry is not one Guard writes.
pub(crate) fn plan_text(
    ai_tool: &str,
    before: Option<&str>,
    entry: &Value,
    url: &str,
) -> Option<Value> {
    let wanted = Fields::from_request(entry)?;
    Some(plan(tool(ai_tool)?, before, &wanted, url))
}

/// `undo` for one settings text; `None` when the AI tool is not supported.
pub(crate) fn undo_text(
    ai_tool: &str,
    current: &str,
    written: &Value,
    prior: Option<&str>,
) -> Option<Result<(String, bool), String>> {
    Some(undo(tool(ai_tool)?, current, written, prior))
}

fn tool(slug: &str) -> Option<&'static Tool> {
    TOOLS.iter().find(|tool| tool.slug == slug)
}

fn plan(tool: &Tool, before: Option<&str>, wanted: &Fields, url: &str) -> Value {
    let answer = |action: &str, others: usize, problem: Option<&str>| {
        json!({
            "action": action,
            "other_entries": others,
            "previous_url": null,
            "configured_as": [],
            "problem": problem,
            "after": null,
        })
    };
    let Some(before) = before else {
        let mut created = answer("create_file", 0, None);
        match render_edit(tool, "", wanted) {
            Ok(after) => created["after"] = json!(after),
            Err(problem) => return answer("unreadable", 0, Some(problem.as_str())),
        }
        return created;
    };
    let (document, servers) = match document(tool, before)
        .and_then(|document| servers(tool, &document).map(|servers| (document, servers)))
    {
        Ok(read) => read,
        Err(problem) => return answer("unreadable", 0, Some(problem.as_str())),
    };
    let others = servers.len() - usize::from(servers.contains_key(SERVER_NAME));
    let mut previous_url = None;
    let existing = servers.get(SERVER_NAME).and_then(Value::as_object);
    if let Some(existing) = existing {
        match guard_fields(tool, existing) {
            None => {
                let problem =
                    format!("An entry named {SERVER_NAME} already exists with other settings.");
                return answer("conflict", others, Some(problem.as_str()));
            }
            Some(current) if current == *wanted => {
                let mut unchanged = answer("unchanged", others, None);
                unchanged["after"] = json!(before);
                return unchanged;
            }
            Some(Fields::Url(current)) => previous_url = display_url(&current),
            Some(Fields::Bridge { .. }) => {}
        }
    }
    // Another entry already reaching this server is left as the one in use,
    // so pointing ours at it too would not add a second connection.
    let same_server: Vec<&String> = servers
        .iter()
        .filter(|(name, entry)| {
            *name != SERVER_NAME && entry.as_object().is_some_and(|entry| points_at(entry, url))
        })
        .map(|(name, _)| name)
        .collect();
    if !same_server.is_empty() {
        let mut configured = answer("already_configured", others, None);
        configured["configured_as"] = json!(same_server);
        return configured;
    }
    let rendered = render_edit(tool, before, wanted)
        .and_then(|after| check_only_changed(tool, &document, &after, wanted).map(|()| after));
    match rendered {
        Ok(after) => {
            let action = if existing.is_some() { "update" } else { "add" };
            let mut changed = answer(action, others, None);
            changed["previous_url"] = json!(previous_url);
            changed["after"] = json!(after);
            changed
        }
        Err(problem) => answer("unreadable", others, Some(problem.as_str())),
    }
}

/// `current` with Guard's entry put back as it was in `prior`, or removed;
/// true when removed. Only while the entry is still exactly `written`.
fn undo(
    tool: &Tool,
    current: &str,
    written: &Value,
    prior: Option<&str>,
) -> Result<(String, bool), String> {
    let current_document = document(tool, current)?;
    let entry = servers(tool, &current_document)?
        .get(SERVER_NAME)
        .and_then(Value::as_object)
        .and_then(|entry| guard_fields(tool, entry));
    if entry.map(|fields| fields.value()).as_ref() != Some(written) {
        return Err(format!(
            "The {SERVER_NAME} entry changed after Guard wrote it."
        ));
    }
    let prior_document = match prior {
        Some(prior) => document(tool, prior)?,
        None => Map::new(),
    };
    let prior_servers = servers(tool, &prior_document)?;
    if let Some(prior_entry) = prior_servers.get(SERVER_NAME).and_then(Value::as_object) {
        let prior_fields = guard_fields(tool, prior_entry)
            .ok_or_else(|| format!("The earlier {SERVER_NAME} entry was not one Guard wrote."))?;
        let after = render_edit(tool, current, &prior_fields)?;
        check_only_changed(tool, &current_document, &after, &prior_fields)?;
        return Ok((after, false));
    }
    let drop_empty_table = !prior_document.contains_key(tool.table);
    let after = render_removal(tool, current, drop_empty_table)?;
    let new = document(tool, &after)?;
    if servers(tool, &new)?.contains_key(SERVER_NAME)
        || without_guard_entry(tool, &new) != without_guard_entry(tool, &current_document)
    {
        return Err(EDIT_ERROR.to_owned());
    }
    Ok((after, true))
}

/// The settings file's values, as the AI tool reads them.
fn document(tool: &Tool, text: &str) -> Result<Map<String, Value>, String> {
    match tool.format {
        Format::Toml => {
            // Python's TOML reader refuses a byte order mark; keep refusing it.
            if text.starts_with('\u{feff}') {
                return Err(NOT_TOML.to_owned());
            }
            toml::from_str(text).map_err(|_| NOT_TOML.to_owned())
        }
        Format::Json if is_blank(text) => Ok(Map::new()),
        Format::Json => match parse_json(text)?.value() {
            Value::Object(document) => Ok(document),
            _ => Err(NOT_OBJECT.to_owned()),
        },
    }
}

/// The servers by name; an entry that is not a table reads as an empty one.
fn servers(tool: &Tool, document: &Map<String, Value>) -> Result<Map<String, Value>, String> {
    match document.get(tool.table) {
        None | Some(Value::Null) => Ok(Map::new()),
        Some(Value::Object(servers)) => Ok(servers
            .iter()
            .map(|(name, entry)| {
                let entry = if entry.is_object() {
                    entry.clone()
                } else {
                    json!({})
                };
                (name.clone(), entry)
            })
            .collect()),
        Some(_) => Err(format!(
            "{} in the settings file is not a table of servers.",
            tool.table
        )),
    }
}

/// Refuse a rendering that changes anything but Guard's own entry.
fn check_only_changed(
    tool: &Tool,
    old: &Map<String, Value>,
    after: &str,
    fields: &Fields,
) -> Result<(), String> {
    let new = document(tool, after)?;
    let entry = new
        .get(tool.table)
        .and_then(Value::as_object)
        .and_then(|servers| servers.get(SERVER_NAME));
    if entry != Some(&fields.wanted(tool))
        || without_guard_entry(tool, &new) != without_guard_entry(tool, old)
    {
        return Err(EDIT_ERROR.to_owned());
    }
    Ok(())
}

fn without_guard_entry(tool: &Tool, document: &Map<String, Value>) -> Map<String, Value> {
    let mut rest = document.clone();
    if let Some(Value::Object(servers)) = rest.get_mut(tool.table) {
        servers.remove(SERVER_NAME);
        if servers.is_empty() {
            rest.remove(tool.table);
        }
    }
    rest
}

fn render_edit(tool: &Tool, text: &str, fields: &Fields) -> Result<String, String> {
    match tool.format {
        Format::Toml => toml_edit_entry(tool, text, fields),
        Format::Json => {
            let mut root = json_root(text)?;
            let entry = Node::Object(
                fields
                    .entry(Some(tool))
                    .into_iter()
                    .map(|(key, value)| (key.to_owned(), Node::Leaf(value)))
                    .collect(),
            );
            let servers = upsert(&mut root, tool.table, None);
            if !matches!(servers, Node::Object(_)) {
                *servers = Node::Object(Vec::new());
            }
            if let Node::Object(servers) = servers {
                set(servers, SERVER_NAME, entry);
            }
            Ok(dump_like(&Node::Object(root), text))
        }
    }
}

fn render_removal(tool: &Tool, text: &str, drop_empty_table: bool) -> Result<String, String> {
    match tool.format {
        Format::Toml => toml_remove_entry(tool, text, drop_empty_table),
        Format::Json => {
            let mut root = json_root(text)?;
            let Some(Node::Object(servers)) = lookup(&mut root, tool.table) else {
                return Err(EDIT_ERROR.to_owned());
            };
            servers.retain(|(name, _)| name != SERVER_NAME);
            if servers.is_empty() && drop_empty_table {
                root.retain(|(name, _)| name != tool.table);
            }
            Ok(dump_like(&Node::Object(root), text))
        }
    }
}

#[cfg(test)]
#[path = "cloud_actions_host_config_tests.rs"]
mod tests;

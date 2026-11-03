//! `runner_authority` kind `cursor_editor_plan`: the planning half of the
//! Cursor editor install (`_install_editor` and `_prepare_editor`).
//!
//! It merges the managed MCP origins Guard records in its state file, picks
//! which `mcpServers` entries are Guard proxies to refresh, and returns the
//! install notes. Python keeps the file reads and writes, detection, the proxy
//! launch rendering and the hook install, and applies this plan.
//!
//! serde_json does not keep object order, so the previous origins travel as
//! `[[name, value], ...]` pairs, `servers` is the `mcpServers` values in order
//! (only their `command` and `args`, or `null` for a non-object entry), and the
//! answer names refreshed entries by index into that list.

use serde_json::{json, Value};

use super::codex_detect::{is_guard_launcher, PROXY_COMMANDS};
use super::runner_authority_detector::args_object;
use super::runner_authority_op::{KindResult, ERR_INVALID};

const KEYS: [&str; 5] = [
    "previous_origins",
    "observed",
    "managed",
    "servers",
    "workspace",
];
const NOTES: [&str; 2] = [
    "Guard Cursor editor MCP proxies added to the global Cursor mcp.json config.",
    "Guard native Cursor hooks installed globally for shell, MCP, and file-read interception.",
];
const WORKSPACE_NOTE: &str = "Workspace policy context uses the detected project directory; \
                              Guard does not write project-local hook files.";
const RELAY_COMMAND: &str = "mcp-relay";

type Pairs = Vec<(String, Value)>;

pub(crate) fn plan(args: &Value) -> KindResult {
    let map = args_object(args)?;
    if map.len() != KEYS.len() || !KEYS.iter().all(|key| map.contains_key(*key)) {
        return Err(ERR_INVALID);
    }
    let workspace = map["workspace"].as_bool().ok_or(ERR_INVALID)?;
    let mut origins: Pairs = Vec::new();
    for (name, value) in pairs(&map["previous_origins"])?.unwrap_or_default() {
        set(&mut origins, &name, value);
    }
    for [name, scope, path] in rows(&map["observed"])? {
        if scope == "project" {
            set(&mut origins, name, json!([scope, path]));
        }
    }
    for [name, scope, path] in rows(&map["managed"])? {
        if scope == "project" {
            set(&mut origins, name, json!([scope, path]));
        } else {
            origins.retain(|pair| pair.0 != name);
        }
    }
    let refresh = refresh(&map["servers"])?;
    let mut notes: Vec<&str> = NOTES.to_vec();
    if workspace {
        notes.push(WORKSPACE_NOTE);
    }
    let origins: Vec<Value> = origins
        .into_iter()
        .map(|(name, value)| json!([name, value]))
        .collect();
    Ok(json!({ "origins": origins, "refresh": refresh, "notes": notes }))
}

/// A Python dict assignment: an existing key keeps its position.
fn set(origins: &mut Pairs, name: &str, value: Value) {
    match origins.iter_mut().find(|pair| pair.0 == name) {
        Some(found) => found.1 = value,
        None => origins.push((name.to_string(), value)),
    }
}

/// `[[name, value], ...]` in the caller's order, or `None` for `null`.
fn pairs(value: &Value) -> Result<Option<Pairs>, &'static str> {
    if value.is_null() {
        return Ok(None);
    }
    let list = value.as_array().ok_or(ERR_INVALID)?;
    let mut found = Vec::new();
    for pair in list {
        match pair.as_array().map(Vec::as_slice) {
            Some([Value::String(name), value]) => found.push((name.clone(), value.clone())),
            _ => return Err(ERR_INVALID),
        }
    }
    Ok(Some(found))
}

/// `[[name, source_scope, config_path], ...]` for detected servers.
fn rows(value: &Value) -> Result<Vec<[&str; 3]>, &'static str> {
    let list = value.as_array().ok_or(ERR_INVALID)?;
    let mut found = Vec::new();
    for row in list {
        match row.as_array().map(Vec::as_slice) {
            Some([Value::String(name), Value::String(scope), Value::String(path)]) => {
                found.push([name.as_str(), scope.as_str(), path.as_str()]);
            }
            _ => return Err(ERR_INVALID),
        }
    }
    Ok(found)
}

/// Indices of the `mcpServers` entries that are Guard proxy launches.
fn refresh(value: &Value) -> Result<Vec<usize>, &'static str> {
    let mut found = Vec::new();
    if value.is_null() {
        return Ok(found);
    }
    let entries = value.as_array().ok_or(ERR_INVALID)?;
    for (index, config) in entries.iter().enumerate() {
        let config = match config {
            Value::Object(config) => config,
            Value::Null => continue,
            _ => return Err(ERR_INVALID),
        };
        if config.keys().any(|key| key != "command" && key != "args") {
            return Err(ERR_INVALID);
        }
        let command = config.get("command").and_then(Value::as_str);
        let args = iterated_strings(config.get("args"))?;
        if is_guard_proxy(command, &args) {
            found.push(index);
        }
    }
    Ok(found)
}

/// `tuple(str(v) for v in config.get("args", []) if isinstance(v, str))`.
/// Python cannot iterate `null`, a number or a bool, and the install fails.
fn iterated_strings(value: Option<&Value>) -> Result<Vec<String>, &'static str> {
    let strings = match value {
        None => Vec::new(),
        Some(Value::Array(items)) => items
            .iter()
            .filter_map(|item| item.as_str().map(str::to_string))
            .collect(),
        Some(Value::String(text)) => text.chars().map(|item| item.to_string()).collect(),
        Some(Value::Object(map)) => map.keys().cloned().collect(),
        Some(_) => return Err(ERR_INVALID),
    };
    Ok(strings)
}

/// `is_guard_proxy_command`, with `proxy_argument_tail`'s native relay form.
fn is_guard_proxy(command: Option<&str>, args: &[String]) -> bool {
    let Some(command) = command else {
        return false;
    };
    if is_guard_launcher(command) {
        return has_proxy_tail(args);
    }
    args.iter().any(|arg| arg == "codex_plugin_scanner.cli")
        && args.iter().any(|arg| arg == "guard")
        && args.iter().any(|arg| is_proxy_command(arg))
}

fn is_proxy_command(arg: &str) -> bool {
    PROXY_COMMANDS.contains(&arg)
}

fn is_module_tail(args: &[String]) -> bool {
    args.len() >= 4
        && args[0] == "-m"
        && args[1] == "codex_plugin_scanner.cli"
        && args[2] == "guard"
        && is_proxy_command(&args[3])
}

/// `proxy_argument_tail(args, _GUARD_PROXY_COMMANDS) is not None`.
fn has_proxy_tail(args: &[String]) -> bool {
    if args.len() > 2 && args[0] == RELAY_COMMAND {
        return is_module_tail(&args[2..]);
    }
    let command_at = |index: usize| -> bool {
        args.get(index)
            .is_some_and(|arg| is_proxy_command(arg.as_str()))
    };
    command_at(0)
        || (args.len() >= 2 && args[0] == "guard" && command_at(1))
        || is_module_tail(args)
}

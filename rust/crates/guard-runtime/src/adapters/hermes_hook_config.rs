//! `runner_authority` kind `hermes_hook_config`: which `hooks.pre_tool_call`
//! entries and allowlist approvals Guard owns in a Hermes home.
//!
//! Python keeps the YAML and JSON I/O, the safe writes and the command string
//! (`shlex.join` of the hook argv). Answers index into the caller's own lists,
//! so user entries are never rebuilt here.
//!
//! - `pretool_plan`: the entries to keep and the commands of the Guard
//!   entries dropped. With `expected_command` it is the install merge, which
//!   also drops an entry running that exact command; without it, uninstall.
//! - `registered`: whether a fail-closed, match-everything Guard entry is
//!   present and, when `approvals` is given, allowlisted.
//! - `allowlist_plan`: the approvals to keep and whether Guard's own approval
//!   must be appended.

use std::path::{Path, PathBuf};

use serde_json::{json, Map, Value};

use crate::claude_hook_bridge_url::resolve_absolute;
use crate::guard_store_json::py_strip;
use crate::local_mcp_grant_identity::shlex_split;
use crate::runner_authority_detector::args_object;
use crate::runner_authority_op::{KindResult, ERR_INVALID};

const PRETOOL_EVENT: &str = "pre_tool_call";
const GUARD_HOOK_ID: &str = "hol-guard-pretool";
const BOUNDED_HOOK_FLAG: &str = "__guard-bounded-hook";
const BOUNDED_BRIDGE_MODULE: &str = "bounded_cli_hook_bridge";

pub(crate) fn dispatch(args: &Value) -> KindResult {
    let fields = args_object(args)?;
    match fields.get("op").and_then(Value::as_str) {
        Some("pretool_plan") => pretool_plan(fields),
        Some("registered") => registered(fields),
        Some("allowlist_plan") => allowlist_plan(fields),
        _ => Err(ERR_INVALID),
    }
}

fn pretool_plan(fields: &Map<String, Value>) -> KindResult {
    let entries = array(fields, "entries")?;
    let expected = optional_str(fields, "expected_command")?;
    let cwd = cwd(fields)?;
    let mut keep = Vec::new();
    let mut removed = Vec::new();
    for (index, entry) in entries.iter().enumerate() {
        let legacy = entry
            .as_object()
            .is_some_and(|object| legacy_command(object.get("command"), expected, cwd.as_deref()));
        if !(is_guard_entry(entry, expected) || legacy) {
            keep.push(index);
            continue;
        }
        if let Some(command) = entry.get("command").and_then(Value::as_str) {
            if !py_strip(command).is_empty() {
                removed.push(command.to_owned());
            }
        }
    }
    Ok(json!({"keep": keep, "removed": removed}))
}

fn registered(fields: &Map<String, Value>) -> KindResult {
    let entries = array(fields, "entries")?;
    let expected = optional_str(fields, "expected_command")?;
    // `null` skips the allowlist check; `false` is an allowlist that could
    // not be read, which allowlists nothing.
    let approvals = match fields.get("approvals") {
        Some(Value::Null) => None,
        Some(Value::Bool(false)) => Some(&[][..]),
        Some(Value::Array(items)) => Some(items.as_slice()),
        _ => return Err(ERR_INVALID),
    };
    let found = entries.iter().filter_map(Value::as_object).any(|entry| {
        let fail_closed = entry.get("fail_closed") == Some(&Value::Bool(true))
            || entry.get("failClosed") == Some(&Value::Bool(true));
        let Some(command) = entry.get("command").and_then(Value::as_str) else {
            return false;
        };
        fail_closed
            && entry.get("matcher").and_then(Value::as_str) == Some(".*")
            && is_guard_object(entry, expected)
            && !py_strip(command).is_empty()
            && approvals.is_none_or(|items| items.iter().any(|item| approves(item, command)))
    });
    Ok(json!({ "registered": found }))
}

fn allowlist_plan(fields: &Map<String, Value>) -> KindResult {
    let approvals = array(fields, "approvals")?;
    let command = fields
        .get("command")
        .and_then(Value::as_str)
        .ok_or(ERR_INVALID)?;
    let retired: Vec<&str> = match fields.get("retire") {
        Some(Value::Array(items)) => items
            .iter()
            .map(|item| item.as_str().ok_or(ERR_INVALID))
            .collect::<Result<Vec<_>, _>>()?
            .into_iter()
            .filter(|item| !item.is_empty() && *item != command)
            .collect(),
        None | Some(Value::Null) => Vec::new(),
        _ => return Err(ERR_INVALID),
    };
    let merge = match fields.get("mode").and_then(Value::as_str) {
        Some("merge") => true,
        Some("remove") => false,
        _ => return Err(ERR_INVALID),
    };
    let mut keep = Vec::new();
    for (index, item) in approvals.iter().enumerate() {
        let Some(object) = item.as_object() else {
            continue;
        };
        let pretool = object.get("event").and_then(Value::as_str) == Some(PRETOOL_EVENT);
        let item_command = object.get("command").and_then(Value::as_str);
        let dropped = if merge {
            item_command.is_some_and(|text| retired.contains(&text))
        } else {
            item_command == Some(command)
        };
        if !(pretool && dropped) {
            keep.push(index);
        }
    }
    let append = merge
        && !keep
            .iter()
            .any(|&index| approves(&approvals[index], command));
    Ok(json!({"keep": keep, "append": append}))
}

fn approves(item: &Value, command: &str) -> bool {
    item.get("event").and_then(Value::as_str) == Some(PRETOOL_EVENT)
        && item.get("command").and_then(Value::as_str) == Some(command)
}

fn is_guard_entry(entry: &Value, expected: Option<&str>) -> bool {
    entry
        .as_object()
        .is_some_and(|object| is_guard_object(object, expected))
}

fn is_guard_object(entry: &Map<String, Value>, expected: Option<&str>) -> bool {
    if entry.get("id").and_then(Value::as_str) == Some(GUARD_HOOK_ID) {
        return true;
    }
    match expected.filter(|text| !text.is_empty()) {
        Some(text) => entry.get("command").and_then(Value::as_str) == Some(text),
        None => false,
    }
}

/// A command an earlier Guard release registered: the bounded hook flag, an
/// inline bridge bootstrap, or `<python> -I <script>` naming the same script
/// as the command about to be installed.
fn legacy_command(command: Option<&Value>, expected: Option<&str>, cwd: Option<&Path>) -> bool {
    let Some(command) = command.and_then(Value::as_str) else {
        return false;
    };
    if py_strip(command).is_empty() {
        return false;
    }
    let Some(tokens) = shlex_split(command) else {
        return false;
    };
    if tokens.iter().any(|token| token == BOUNDED_HOOK_FLAG) {
        return true;
    }
    if let Some(inline) = tokens.iter().position(|token| token == "-c") {
        if tokens
            .get(inline + 1)
            .is_some_and(|code| code.contains(BOUNDED_BRIDGE_MODULE))
        {
            return true;
        }
    }
    // Without a working directory a script path cannot be resolved the way
    // the caller would, so no script is claimed.
    let Some(cwd) = cwd else {
        return false;
    };
    if tokens.len() != 3 || tokens[1] != "-I" {
        return false;
    }
    let Some(expected_tokens) = expected.and_then(shlex_split) else {
        return false;
    };
    if expected_tokens.len() != 3 || expected_tokens[1] != "-I" {
        return false;
    }
    resolved(cwd, &tokens[2]) == resolved(cwd, &expected_tokens[2])
}

/// `str(Path(value).resolve())` from the caller's working directory.
fn resolved(cwd: &Path, value: &str) -> String {
    resolve_absolute(&cwd.join(value).to_string_lossy())
}

/// The caller's absolute working directory; `null` when it has none, as on
/// uninstall or from a deleted directory.
fn cwd(fields: &Map<String, Value>) -> Result<Option<PathBuf>, &'static str> {
    let Some(text) = optional_str(fields, "cwd")? else {
        return Ok(None);
    };
    let path = PathBuf::from(text);
    if path.is_absolute() {
        Ok(Some(path))
    } else {
        Err(ERR_INVALID)
    }
}

fn array<'a>(fields: &'a Map<String, Value>, key: &str) -> Result<&'a [Value], &'static str> {
    fields
        .get(key)
        .and_then(Value::as_array)
        .map(Vec::as_slice)
        .ok_or(ERR_INVALID)
}

fn optional_str<'a>(
    fields: &'a Map<String, Value>,
    key: &str,
) -> Result<Option<&'a str>, &'static str> {
    match fields.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(text)) => Ok(Some(text)),
        _ => Err(ERR_INVALID),
    }
}

//! `runner_authority` kind `copilot_mcp_plan`: the MCP half of the Copilot
//! install (the target loop of `_render_install`, `_mcp_payload_key`,
//! `_mcp_servers_payload`, `_command_parts`, `_managed_servers_for_target`,
//! the workspace override check and `_proxy_server_entry`'s fields in
//! `guard/adapters/copilot.py` before they moved here).
//!
//! For each MCP target it picks the key Guard writes, the servers object it
//! starts from, the entries that are Guard proxies to relaunch (with the
//! Python proxy argv each one carries) and the managed servers to add. Python
//! keeps the file reads and writes, detection, the proxy launch rendering and
//! every env value.
//!
//! serde_json does not keep object order, so a target's `mcpServers` and
//! `servers` values travel as `[[name, launch], ...]` pairs (`launch` holds
//! only an entry's `command` and `args`, or is `null` for a non-object entry),
//! `false` for a present non-object value and `null` for an absent key. The
//! answer names entries by index into those pairs and managed servers by index
//! into `managed`; added entries take `fields` in order.

use std::collections::BTreeSet;

use serde_json::{json, Map, Value};

use super::cursor_editor_plan::is_guard_proxy;
use super::runner_authority_detector::args_object;
use super::runner_authority_op::{KindResult, ERR_INVALID};

const KEYS: [&str; 3] = ["workspace", "managed", "targets"];
const TARGET_KEYS: [&str; 4] = ["path", "name", "mcpServers", "servers"];
const NOTES: [&str; 3] = [
    "Guard hook entries added to ~/.copilot/config.json for Copilot CLI.",
    "Guard workspace hook entries added to .github/hooks/hol-guard-copilot.json for VS Code Copilot.",
    "Guard MCP proxies added to Copilot CLI and VS Code workspace MCP config files.",
];
/// The Copilot CLI config files, which name servers under `mcpServers` and
/// launch Guard's proxy as a `local` server.
const CLI_FILE_NAMES: [&str; 2] = [".mcp.json", "mcp-config.json"];
const RELAY_COMMAND: &str = "mcp-relay";
const PYTHON_PROXY_PREFIX: [&str; 3] = ["-m", "codex_plugin_scanner.cli", "guard"];
/// The proxies the native relay launches (`RELAY_PROXY_COMMANDS`).
const RELAY_PROXY_COMMANDS: [&str; 6] = [
    "cline-mcp-proxy",
    "codex-mcp-proxy",
    "copilot-mcp-proxy",
    "cursor-mcp-proxy",
    "hermes-mcp-proxy",
    "opencode-mcp-proxy",
];

type Entry<'a> = (&'a str, Option<&'a Map<String, Value>>);

/// One servers key of a target's payload.
enum Slot<'a> {
    Absent,
    NotObject,
    Object(Vec<Entry<'a>>),
}

impl Slot<'_> {
    fn present(&self) -> bool {
        !matches!(self, Slot::Absent)
    }
}

pub(crate) fn plan(args: &Value) -> KindResult {
    let map = exact(args_object(args)?, &KEYS)?;
    let workspace = map["workspace"].as_bool().ok_or(ERR_INVALID)?;
    let managed = rows(&map["managed"])?;
    let targets = map["targets"].as_array().ok_or(ERR_INVALID)?;
    let plans = targets
        .iter()
        .map(|target| target_plan(target, workspace, &managed))
        .collect::<Result<Vec<_>, _>>()?;
    Ok(json!({ "targets": plans, "notes": NOTES }))
}

fn exact<'a>(
    map: &'a Map<String, Value>,
    keys: &[&str],
) -> Result<&'a Map<String, Value>, &'static str> {
    if map.len() == keys.len() && keys.iter().all(|key| map.contains_key(*key)) {
        Ok(map)
    } else {
        Err(ERR_INVALID)
    }
}

/// `[[name, source_scope, path], ...]` for the managed servers detection found.
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

fn slot(value: &Value) -> Result<Slot<'_>, &'static str> {
    let pairs = match value {
        Value::Null => return Ok(Slot::Absent),
        Value::Bool(false) => return Ok(Slot::NotObject),
        Value::Array(pairs) => pairs,
        _ => return Err(ERR_INVALID),
    };
    let mut names = BTreeSet::new();
    let mut entries = Vec::new();
    for pair in pairs {
        let entry: Entry<'_> = match pair.as_array().map(Vec::as_slice) {
            Some([Value::String(name), Value::Null]) => (name.as_str(), None),
            Some([Value::String(name), Value::Object(launch)])
                if launch.keys().all(|key| key == "command" || key == "args") =>
            {
                (name.as_str(), Some(launch))
            }
            _ => return Err(ERR_INVALID),
        };
        if !names.insert(entry.0) {
            return Err(ERR_INVALID);
        }
        entries.push(entry);
    }
    Ok(Slot::Object(entries))
}

/// The entries of `key`'s value when it is an object.
fn object<'s, 'a>(
    key: &str,
    mcp_servers: &'s Slot<'a>,
    servers: &'s Slot<'a>,
) -> Option<&'s [Entry<'a>]> {
    let slot = if key == "mcpServers" {
        mcp_servers
    } else {
        servers
    };
    match slot {
        Slot::Object(entries) => Some(entries.as_slice()),
        _ => None,
    }
}

fn target_plan(target: &Value, workspace: bool, managed: &[[&str; 3]]) -> KindResult {
    let map = exact(target.as_object().ok_or(ERR_INVALID)?, &TARGET_KEYS)?;
    let (Some(path), Some(name)) = (map["path"].as_str(), map["name"].as_str()) else {
        return Err(ERR_INVALID);
    };
    let mcp_servers = slot(&map["mcpServers"])?;
    let servers = slot(&map["servers"])?;
    let cli_file = CLI_FILE_NAMES.contains(&name);
    // `_mcp_payload_key`: the only key present, else the file's own key.
    let key = match (mcp_servers.present(), servers.present()) {
        (true, false) => "mcpServers",
        (false, true) => "servers",
        _ if cli_file => "mcpServers",
        _ => "servers",
    };
    let other = if key == "mcpServers" {
        "servers"
    } else {
        "mcpServers"
    };
    // `_mcp_servers_payload`: the key's object, else the other key's.
    let none: &[Entry<'_>] = &[];
    let (source, entries) = match object(key, &mcp_servers, &servers) {
        Some(entries) => (Some(key), entries),
        None => match object(other, &mcp_servers, &servers) {
            Some(entries) => (Some(other), entries),
            None => (None, none),
        },
    };
    let mut refresh = Vec::new();
    for (index, (_, launch)) in entries.iter().enumerate() {
        let Some(launch) = *launch else {
            continue;
        };
        let (command, args) = command_parts(launch);
        if is_guard_proxy(command, &args) {
            refresh.push(json!([index, python_args(args)]));
        }
    }
    let names: BTreeSet<&str> = entries
        .iter()
        .filter(|entry| entry.1.is_some())
        .map(|entry| entry.0)
        .collect();
    let mut add = Vec::new();
    for (index, [server, scope, config_path]) in managed.iter().enumerate() {
        // `_managed_servers_for_target`, then `should_skip_workspace_override`.
        let for_target = *scope == "global" || *config_path == path;
        let shadowed = workspace && *scope != "project" && names.contains(server);
        if for_target && !shadowed {
            add.push(index);
        }
    }
    let fields = if cli_file {
        json!([["type", "local"], ["tools", ["*"]]])
    } else {
        json!([["type", "stdio"]])
    };
    Ok(json!({
        "key": key,
        "source": source,
        "refresh": refresh,
        "add": add,
        "fields": fields,
    }))
}

/// `_command_parts`: a string `command`, or a list's first string with the
/// rest of its strings ahead of `args`; `args` keeps only a list's strings.
fn command_parts(launch: &Map<String, Value>) -> (Option<&str>, Vec<String>) {
    let args: Vec<String> = match launch.get("args") {
        Some(Value::Array(items)) => items
            .iter()
            .filter_map(Value::as_str)
            .map(str::to_string)
            .collect(),
        _ => Vec::new(),
    };
    match launch.get("command") {
        Some(Value::String(command)) => (Some(command.as_str()), args),
        Some(Value::Array(items)) => {
            let mut parts = items.iter().filter_map(Value::as_str);
            match parts.next() {
                Some(first) => (Some(first), parts.map(str::to_string).chain(args).collect()),
                None => (None, args),
            }
        }
        _ => (None, args),
    }
}

/// `python_proxy_launch`: a native relay launch unwrapped to the Python proxy
/// argv it carries.
fn python_args(args: Vec<String>) -> Vec<String> {
    if args.len() > 1 && args[0] == RELAY_COMMAND && relays(&args[2..]) {
        return args[2..].to_vec();
    }
    args
}

fn relays(args: &[String]) -> bool {
    args.len() > 3
        && args[..3]
            .iter()
            .zip(PYTHON_PROXY_PREFIX)
            .all(|(arg, expected)| arg.as_str() == expected)
        && RELAY_PROXY_COMMANDS.contains(&args[3].as_str())
}

//! `runner_authority` kind `kimi_detect`: the config parsing and artifact
//! discovery of `KimiHarnessAdapter.detect`. For the Kimi home (which Python
//! resolves from `KIMI_CODE_HOME` and sends as `home`) and then the workspace
//! this lists the `.kimi-code/config.toml` hook entries and the
//! `.kimi-code/mcp.json` servers. Python keeps the home resolution, the
//! command lookup and the workspace AIBOM extension. Every refusal is a
//! stable code and never a partial inventory.

use std::fs;
use std::path::{Path, PathBuf};

use serde_json::{json, Map, Number, Value};

use super::adapter_inventory::{json_payload, Inventory, Request, ERR_VALUE};
use super::codex_sources::{is_empty, toml_payload};
use super::codex_value::HookVal;
use super::context_digest::python_strip;
use super::pyjson::PyVal;
use super::runner_authority_op::KindResult;
use super::zcode_artifacts::{Fields, Scope};

const HARNESS: &str = "kimi";
const KIMI_DIR: &str = ".kimi-code";

/// `isinstance(timeout, (int, float))` as the wire carries it: a non-finite
/// float has no JSON form and is refused.
fn timeout_value(value: &HookVal) -> Result<Option<Value>, &'static str> {
    Ok(match value {
        HookVal::Bool(flag) => Some(Value::Bool(*flag)),
        HookVal::Int(digits) => Some(json!(digits.parse::<i64>().map_err(|_| ERR_VALUE)?)),
        HookVal::Float(number) => Some(Value::Number(Number::from_f64(*number).ok_or(ERR_VALUE)?)),
        _ => None,
    })
}

/// `_append_hook_artifacts`: the `hooks` list of one `config.toml`.
fn hooks(
    inventory: &mut Inventory,
    scope: &Scope<'_>,
    path: &Path,
    payload: &HookVal,
) -> Result<(), &'static str> {
    let Some(entries) = payload.get("hooks").and_then(HookVal::as_list) else {
        return Ok(());
    };
    for (index, entry) in entries.iter().enumerate() {
        if entry.as_dict().is_none() {
            continue;
        }
        let Some(command) = entry.get("command").and_then(HookVal::as_str) else {
            continue;
        };
        if python_strip(command).is_empty() {
            continue;
        }
        let event = entry.get("event").and_then(HookVal::as_str).unwrap_or("");
        let matcher = entry.get("matcher").and_then(HookVal::as_str);
        let mut metadata = Map::new();
        metadata.insert("event".to_owned(), json!(event));
        metadata.insert("command".to_owned(), json!(command));
        if let Some(matcher) = matcher {
            metadata.insert("matcher".to_owned(), json!(matcher));
        }
        if let Some(timeout) = entry
            .get("timeout")
            .map(timeout_value)
            .transpose()?
            .flatten()
        {
            metadata.insert("timeout".to_owned(), timeout);
        }
        let lowered = event.to_lowercase();
        let id_event = if lowered.is_empty() {
            "unknown"
        } else {
            lowered.as_str()
        };
        let label = if event.is_empty() { "hook" } else { event };
        let name = match matcher {
            Some(matcher) if !matcher.is_empty() => format!("{label}:{matcher}"),
            _ => label.to_owned(),
        };
        inventory.artifacts.push(scope.wire(
            format!("{HARNESS}:{}:hook:{id_event}:{index}", scope.scope),
            &name,
            "hook",
            path,
            Fields {
                command: Some(command),
                ..Fields::default()
            },
            metadata,
        ));
    }
    Ok(())
}

/// `str(value)` for a JSON value; a list or object is refused rather than
/// re-rendered as its Python `repr`.
fn python_str(value: &PyVal) -> Result<String, &'static str> {
    match value {
        PyVal::Null => Ok("None".to_owned()),
        other => other.scalar_text().ok_or(ERR_VALUE),
    }
}

/// `_append_mcp_artifacts`: the `mcpServers` of one `mcp.json`.
fn mcp_servers(
    inventory: &mut Inventory,
    scope: &Scope<'_>,
    path: &Path,
    payload: &PyVal,
) -> Result<(), &'static str> {
    let Some(servers) = payload.get("mcpServers").and_then(PyVal::as_dict) else {
        return Ok(());
    };
    for (name, config) in servers {
        if config.as_dict().is_none() {
            continue;
        }
        let command = config.get("command").and_then(PyVal::as_str);
        let url = config.get("url").and_then(PyVal::as_str);
        if command.is_none() && url.is_none() {
            continue;
        }
        let args = match config.get("args").and_then(PyVal::as_list) {
            Some(items) => items.iter().map(python_str).collect::<Result<_, _>>()?,
            None => Vec::new(),
        };
        inventory.artifacts.push(scope.wire(
            format!("{HARNESS}:{}:mcp:{name}", scope.scope),
            name,
            "mcp_server",
            path,
            Fields {
                command,
                args,
                url,
                transport: Some(if url.is_some() { "http" } else { "stdio" }),
                publisher: None,
            },
            Map::new(),
        ));
    }
    Ok(())
}

pub(crate) fn detect(args: &Value) -> KindResult {
    let request = Request::parse(args, HARNESS)?;
    let mut inventory = Inventory::new(&request);
    let mut roots: Vec<(PathBuf, &str)> = vec![(request.home.join(KIMI_DIR), "global")];
    if let Some(workspace) = &request.workspace {
        roots.push((workspace.join(KIMI_DIR), "project"));
    }
    for (root, scope) in &roots {
        let path = root.join("config.toml");
        if !inventory.is_file(&path)? {
            continue;
        }
        inventory.push_found(&path);
        let bytes = fs::read(inventory.fs(&path)).ok();
        let payload = toml_payload(bytes.as_deref())?;
        if !is_empty(&payload) {
            let scope = Scope {
                harness: HARNESS,
                scope,
            };
            hooks(&mut inventory, &scope, &path, &payload)?;
        }
    }
    for (root, scope) in &roots {
        let path = root.join("mcp.json");
        if !inventory.is_file(&path)? {
            continue;
        }
        inventory.push_found(&path);
        let payload = json_payload(&inventory.fs(&path))?;
        if payload.truthy() {
            let scope = Scope {
                harness: HARNESS,
                scope,
            };
            mcp_servers(&mut inventory, &scope, &path, &payload)?;
        }
    }
    inventory.finish()
}

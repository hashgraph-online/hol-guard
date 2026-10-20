//! The OpenClaw detection kind (`openclaw_detect`): the gateway, channel and
//! MCP server artifacts of the config Python loads (JSON, JSON5 and
//! `$include` stay in `openclaw_config.py` and arrive as JSON text), plus
//! the skill roots the config names (walked in `openclaw_skills`).

use std::path::{Path, PathBuf};

use serde_json::{json, Map, Value};

use super::adapter_inventory::{Inventory, Request};
use super::aibom_paths::{py_join, py_path};
use super::context_digest::python_strip;
use super::openclaw_mcp;
use super::openclaw_skills;
use super::pyjson::{parse_marking_lone_surrogates, PyVal};
use super::runner_authority_detector::args_object;
use super::runner_authority_op::{KindResult, ERR_INVALID};
use super::zcode_artifacts::{Fields, Scope};

pub(crate) const SCOPE: Scope<'static> = Scope {
    harness: "openclaw",
    scope: "global",
};
const OPEN_CHANNEL_SIGNAL: &str =
    "network traffic from open chat channel can reach the agent without sender pairing";

/// `_string_list`: the `str()` of every string, number and boolean item.
pub(crate) fn string_list(value: Option<&PyVal>) -> Vec<String> {
    value
        .and_then(PyVal::as_list)
        .unwrap_or_default()
        .iter()
        .filter_map(PyVal::scalar_text)
        .collect()
}

/// `_dict_value`: an object, else the empty one.
fn dict(value: Option<&PyVal>) -> Option<&PyVal> {
    value.filter(|value| value.as_dict().is_some())
}

/// `_string_value(_dict_value(value).get(key))`.
fn string_at<'a>(value: Option<&'a PyVal>, key: &str) -> Option<&'a str> {
    dict(value)?.get(key)?.as_str()
}

fn defaults(payload: &PyVal) -> Option<&PyVal> {
    dict(dict(payload.get("agents"))?.get("defaults"))
}

/// `_expand_home`.
fn expand_home(home: &Path, value: &str) -> PathBuf {
    if value == "~" {
        return home.to_path_buf();
    }
    if let Some(rest) = value.strip_prefix("~/") {
        return py_join(home, rest);
    }
    let path = py_path(value);
    if path.is_absolute() {
        path
    } else {
        py_join(home, value)
    }
}

/// `_workspace_path`.
fn workspace_path(home: &Path, payload: &PyVal) -> PathBuf {
    match string_at(defaults(payload), "workspace") {
        Some(workspace) if !workspace.is_empty() => expand_home(home, workspace),
        _ => home.join(".openclaw").join("workspace"),
    }
}

/// `_channels`: the object-valued channel entries in config order.
fn channels(payload: &PyVal) -> Vec<(&str, &PyVal)> {
    dict(payload.get("channels"))
        .and_then(PyVal::as_dict)
        .unwrap_or_default()
        .iter()
        .filter(|(_, config)| config.as_dict().is_some())
        .map(|(name, config)| (name.as_str(), config))
        .collect()
}

fn gateway(
    home: &Path,
    path: &Path,
    payload: &PyVal,
    mcp: &openclaw_mcp::McpInventory<'_>,
) -> Value {
    let gateway = dict(payload.get("gateway"));
    let bind = string_at(gateway, "bind");
    let auth = string_at(gateway.and_then(|gateway| gateway.get("auth")), "mode");
    let sandbox = string_at(
        defaults(payload).and_then(|defaults| defaults.get("sandbox")),
        "mode",
    );
    let mut names: Vec<&str> = channels(payload)
        .into_iter()
        .map(|(name, _)| name)
        .collect();
    names.sort_unstable();
    let effective: Vec<_> = mcp
        .servers
        .iter()
        .map(|server| server.effective())
        .collect();
    let mut sources = Map::new();
    for definition in &effective {
        sources.insert(definition.name.clone(), json!(definition.source_scope));
    }
    let mut metadata = Map::new();
    metadata.insert(
        "workspace_path".to_owned(),
        json!(workspace_path(home, payload).to_string_lossy()),
    );
    metadata.insert("gateway_mode".to_owned(), json!(string_at(gateway, "mode")));
    metadata.insert("gateway_bind".to_owned(), json!(bind));
    metadata.insert("auth_mode".to_owned(), json!(auth));
    metadata.insert("sandbox_mode".to_owned(), json!(sandbox));
    metadata.insert(
        "hooks_enabled".to_owned(),
        json!(dict(payload.get("hooks")).is_some_and(PyVal::truthy)),
    );
    metadata.insert("channel_names".to_owned(), json!(names));
    metadata.insert(
        "mcp_server_names".to_owned(),
        json!(effective
            .iter()
            .map(|definition| definition.name.as_str())
            .collect::<Vec<_>>()),
    );
    metadata.insert("mcp_server_sources".to_owned(), Value::Object(sources));
    metadata.insert("mcp_inventory_warnings".to_owned(), json!(mcp.warnings));
    SCOPE.wire(
        "openclaw:config:global".to_owned(),
        "OpenClaw gateway config",
        "gateway_config",
        path,
        Fields {
            args: vec![
                format!("gateway bind {}", or_default(bind, "loopback")),
                format!("auth mode {}", or_default(auth, "token")),
                format!("sandbox {}", or_default(sandbox, "unset")),
            ],
            ..Fields::default()
        },
        metadata,
    )
}

/// `value or default` for an optional string.
fn or_default<'a>(value: Option<&'a str>, default: &'a str) -> &'a str {
    value.filter(|value| !value.is_empty()).unwrap_or(default)
}

/// `_channel_artifacts`.
fn channel_artifacts(path: &Path, payload: &PyVal) -> Vec<Value> {
    channels(payload)
        .into_iter()
        .map(|(name, config)| {
            let dm = dict(config.get("dm"));
            let dm_policy = config
                .get("dmPolicy")
                .and_then(PyVal::as_str)
                .filter(|policy| !policy.is_empty())
                .or_else(|| string_at(dm, "policy"));
            let mut allow_from = string_list(config.get("allowFrom"));
            if allow_from.is_empty() {
                allow_from = string_list(dm.and_then(|dm| dm.get("allowFrom")));
            }
            let enabled = !matches!(config.get("enabled"), Some(PyVal::Bool(false)));
            let open = enabled
                && dm_policy == Some("open")
                && allow_from.iter().any(|sender| sender == "*");
            let signals: Vec<&str> = if open {
                vec![OPEN_CHANNEL_SIGNAL]
            } else {
                Vec::new()
            };
            let policy_arg = dm_policy.filter(|policy| !policy.is_empty());
            let args = vec![
                format!("channel {name}"),
                format!("dmPolicy {}", policy_arg.unwrap_or("default")),
                format!("allowFrom {}", allow_from.join(",")),
            ];
            let mut metadata = Map::new();
            metadata.insert("channel".to_owned(), json!(name));
            metadata.insert("enabled".to_owned(), json!(enabled));
            metadata.insert("dm_policy".to_owned(), json!(dm_policy));
            metadata.insert("allow_from".to_owned(), json!(allow_from));
            metadata.insert("runtime_request_signals".to_owned(), json!(signals));
            SCOPE.wire(
                format!("openclaw:channel:{name}"),
                name,
                "channel",
                path,
                Fields {
                    args,
                    ..Fields::default()
                },
                metadata,
            )
        })
        .collect()
}

/// `_skill_roots`.
fn skill_roots(request: &Request, payload: &PyVal) -> Vec<PathBuf> {
    let home = &request.home;
    let workspace = workspace_path(home, payload);
    let mut roots = Vec::new();
    if let Some(dir) = &request.workspace {
        roots.push(dir.join("skills"));
        roots.push(dir.join(".agents").join("skills"));
    }
    roots.push(workspace.join("skills"));
    roots.push(workspace.join(".agents").join("skills"));
    roots.push(home.join(".agents").join("skills"));
    roots.push(home.join(".openclaw").join("skills"));
    let load = dict(payload.get("skills")).and_then(|skills| dict(skills.get("load")));
    for extra in string_list(load.and_then(|load| load.get("extraDirs"))) {
        let stripped = python_strip(&extra);
        if !stripped.is_empty() {
            roots.push(expand_home(home, stripped));
        }
    }
    roots
}

pub(crate) fn detect(args: &Value) -> KindResult {
    let request = Request::parse(args, "openclaw")?;
    let config_path = request.path(args, "config_path")?;
    let text = args_object(args)?
        .get("payload")
        .and_then(Value::as_str)
        .ok_or(ERR_INVALID)?;
    let payload = parse_marking_lone_surrogates(text).map_err(|_| ERR_INVALID)?;
    if payload.as_dict().is_none() {
        return Err(ERR_INVALID);
    }
    let mut inventory = Inventory::new(&request);
    if payload.truthy() {
        inventory.push_found(&config_path);
        let mcp = openclaw_mcp::inventory(&payload)?;
        let gateway = gateway(&request.home, &config_path, &payload, &mcp);
        inventory.artifacts.push(gateway);
        inventory
            .artifacts
            .extend(channel_artifacts(&config_path, &payload));
        inventory
            .artifacts
            .extend(openclaw_mcp::artifacts(&config_path, &mcp)?);
    }
    let roots = skill_roots(&request, &payload);
    openclaw_skills::skills(&mut inventory, roots)?;
    inventory.finish()
}

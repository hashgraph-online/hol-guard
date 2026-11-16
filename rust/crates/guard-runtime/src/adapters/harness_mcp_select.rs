//! The `harness_mcp_discovery` `select`, `server_id` and `launch_env` ops:
//! `managed_stdio_servers`, `observable_stdio_servers_with_proxy` and
//! `stable_mcp_server_identifier`, which `guard/adapters/mcp_servers.py`
//! computed per server before they moved here, and the env choice of
//! `extra_env_for_mcp_launch` in `guard/adapters/harness_mcp_discovery.py`.
//!
//! One `select` request carries every artifact a detection found and answers,
//! in order, the local stdio server Guard can run behind its proxy, or null.
//! A server recovered from a Guard proxy's argv is inventory only; it never
//! carries tool schemas or execution permission.

use std::collections::BTreeMap;

use guard_command::mcp_decision::build_mcp_server_identity;
use guard_contracts::python_strip;
use serde_json::{json, Map, Value};

use super::upstream::{read, Connection};
use super::{bounded_list, exact_keys, optional_text, text};
use crate::codex_detect::PROXY_COMMANDS;
use crate::opencode_proxy_entry::is_guard_command;
use crate::opencode_server_id::server_identifier;
use crate::runner_authority_op::{KindResult, ERR_INVALID};

const SELECT_KEYS: [&str; 3] = ["op", "include_proxy", "artifacts"];
const ARTIFACT_KEYS: [&str; 12] = [
    "harness",
    "name",
    "source_scope",
    "config_path",
    "command",
    "args",
    "transport",
    "env",
    "guard_managed_proxy",
    "enabled",
    "saved_origin",
    "saved_guard_home",
];
const SERVER_ID_KEYS: [&str; 2] = ["op", "servers"];
const LAUNCH_ENV_KEYS: [&str; 3] = ["op", "configured", "present"];
const SERVER_KEYS: [&str; 6] = [
    "harness",
    "name",
    "source_scope",
    "command",
    "args",
    "transport",
];
/// `GUARD_MCP_COMPANION_PREFIX`.
const COMPANION_PREFIX: &str = "hol-guard::";
/// `MAX_PROXY_UNWRAP_LAYERS`.
const MAX_UNWRAP_LAYERS: usize = 4;
const LOCAL_TRANSPORTS: [&str; 2] = ["stdio", "local"];

/// An `mcp_server` artifact, after Python applied its private `mcp_args`.
struct Artifact<'a> {
    harness: &'a str,
    name: &'a str,
    source_scope: String,
    config_path: String,
    command: Option<String>,
    args: Vec<String>,
    transport: Option<&'a str>,
    /// The string pairs of the configured env, or None when it is not a mapping.
    env: Option<Vec<(String, String)>>,
    guard_managed_proxy: bool,
    enabled: bool,
    saved_origin: &'a Value,
    saved_guard_home: Option<&'a str>,
}

/// The ops this module answers.
pub(super) fn dispatch(op: &str, map: &Map<String, Value>) -> KindResult {
    match op {
        "select" => select(map),
        "server_id" => server_ids(map),
        "launch_env" => launch_env(map),
        _ => Err(ERR_INVALID),
    }
}

fn select(map: &Map<String, Value>) -> KindResult {
    exact_keys(map, &SELECT_KEYS)?;
    let include_proxy = flag(map, "include_proxy")?;
    let artifacts = bounded_list(map.get("artifacts").ok_or(ERR_INVALID)?)?
        .iter()
        .map(artifact)
        .collect::<Result<Vec<Artifact<'_>>, &'static str>>()?;
    let servers: Vec<Value> = artifacts
        .into_iter()
        .map(|artifact| managed(artifact, include_proxy).unwrap_or(Value::Null))
        .collect();
    Ok(json!({ "servers": servers }))
}

fn server_ids(map: &Map<String, Value>) -> KindResult {
    exact_keys(map, &SERVER_ID_KEYS)?;
    let ids = bounded_list(map.get("servers").ok_or(ERR_INVALID)?)?
        .iter()
        .map(|server| {
            let server = server.as_object().ok_or(ERR_INVALID)?;
            exact_keys(server, &SERVER_KEYS)?;
            let args = string_list(server, "args")?;
            Ok(Value::String(server_identifier(
                text(server, "harness")?,
                text(server, "name")?,
                text(server, "source_scope")?,
                text(server, "command")?,
                &borrowed(&args),
                text(server, "transport")?,
                false,
            )))
        })
        .collect::<Result<Vec<Value>, &'static str>>()?;
    Ok(json!({ "ids": ids }))
}

/// Which of a matched server's env keys a listing probe takes from Guard's own
/// environment. `configured` is the env the harness config gives the server and
/// `present` the server's env keys that Guard's environment sets, in order; a
/// key is taken when the config leaves it unset or as an unexpanded `${NAME}`
/// placeholder. Python keeps the process values, so none crosses the wire.
fn launch_env(map: &Map<String, Value>) -> KindResult {
    exact_keys(map, &LAUNCH_ENV_KEYS)?;
    let configured: BTreeMap<String, String> = env_pairs(&map["configured"])?
        .ok_or(ERR_INVALID)?
        .into_iter()
        .collect();
    let from_process: Vec<String> = string_list(map, "present")?
        .into_iter()
        .filter(|key| {
            configured
                .get(key)
                .is_none_or(|value| looks_unresolved(value))
        })
        .collect();
    Ok(json!({ "from_process": from_process }))
}

/// `_looks_unresolved`: a `${NAME}` placeholder the harness never expanded.
fn looks_unresolved(value: &str) -> bool {
    let stripped = python_strip(value);
    stripped.chars().count() >= 4 && stripped.starts_with("${") && stripped.ends_with('}')
}

/// `_managed_stdio_server`.
fn managed(mut artifact: Artifact<'_>, include_proxy: bool) -> Option<Value> {
    if artifact.name.starts_with(COMPANION_PREFIX) && is_proxy(&artifact) {
        return None;
    }
    if !include_proxy && artifact.guard_managed_proxy {
        return None;
    }
    if artifact.command.is_none() || python_strip(artifact.name).is_empty() {
        return None;
    }
    for _ in 0..MAX_UNWRAP_LAYERS {
        if !is_proxy(&artifact) {
            break;
        }
        if !include_proxy {
            return None;
        }
        unwrap(&mut artifact)?;
    }
    if is_proxy(&artifact) {
        return None;
    }
    let command = artifact.command?;
    let transport = launch_transport(artifact.transport);
    if !LOCAL_TRANSPORTS.contains(&transport) {
        return None;
    }
    let env = artifact.env.unwrap_or_default();
    let mut identity_env = Map::new();
    for (key, value) in &env {
        let key = python_strip(key);
        if !key.is_empty() {
            identity_env.insert(key.to_owned(), Value::String(value.clone()));
        }
    }
    let identity = build_mcp_server_identity(
        &artifact.config_path,
        &command,
        &artifact.args,
        transport,
        Some(&identity_env),
        &[],
    );
    Some(json!({
        "command": command,
        "args": artifact.args,
        "source_scope": artifact.source_scope,
        "config_path": artifact.config_path,
        "transport": transport,
        "env": env,
        "enabled": artifact.enabled,
        "identity": {
            "config_path": identity.config_path,
            "command": identity.command,
            "args_hash": identity.args_hash,
            "package_name": identity.package_name,
            "package_version": identity.package_version,
            "package_source": identity.package_source,
            "transport": identity.transport,
            "env_keys": identity.env_keys,
            "env_values_hash": identity.env_values_hash,
            "identity_hash": identity.identity_hash,
        },
    }))
}

/// One unwrap layer: the upstream launch a Guard proxy's argv names, kept only
/// when its claimed server ID matches the recovered launch.
fn unwrap(artifact: &mut Artifact<'_>) -> Option<()> {
    // `read_managed_mcp_upstream` keys the env by stripped name; a later
    // duplicate wins, as in a dict comprehension.
    let mut configured: BTreeMap<&str, &str> = BTreeMap::new();
    for (key, value) in artifact.env.as_ref()? {
        let key = python_strip(key);
        if !key.is_empty() {
            configured.insert(key, value);
        }
    }
    let names: Vec<&str> = configured.keys().copied().collect();
    let transport = launch_transport(artifact.transport);
    let connection = Connection {
        harness: artifact.harness,
        name: artifact.name,
        transport,
        source_scope: &artifact.source_scope,
        config_path: &artifact.config_path,
        saved_origin: artifact.saved_origin,
        saved_guard_home: artifact.saved_guard_home,
    };
    let found = read(
        &connection,
        &borrowed(&artifact.args),
        &PROXY_COMMANDS,
        &names,
    );
    let found = found.as_object()?;
    let field = |key: &str| found.get(key).and_then(Value::as_str);
    let command = field("command")?.to_owned();
    let args: Vec<String> = found
        .get("args")?
        .as_array()?
        .iter()
        .map(|value| value.as_str().map(str::to_owned))
        .collect::<Option<Vec<String>>>()?;
    let env: Vec<(String, String)> = found
        .get("env_names")?
        .as_array()?
        .iter()
        .map(|value| {
            let name = value.as_str()?;
            Some((name.to_owned(), (*configured.get(name)?).to_owned()))
        })
        .collect::<Option<Vec<(String, String)>>>()?;
    let source_scope = field("source_scope")?.to_owned();
    let config_path = field("config_path")?.to_owned();
    let described = server_identifier(
        artifact.harness,
        artifact.name,
        &source_scope,
        &command,
        &borrowed(&args),
        transport,
        false,
    );
    if Some(described.as_str()) != field("server_id") {
        return None;
    }
    artifact.command = Some(command);
    artifact.args = args;
    artifact.source_scope = source_scope;
    artifact.config_path = config_path;
    artifact.env = Some(env);
    Some(())
}

/// `is_guard_proxy_command` over the artifact's launch.
fn is_proxy(artifact: &Artifact<'_>) -> bool {
    is_guard_command(artifact.command.as_deref(), &borrowed(&artifact.args))
}

/// `artifact.transport or "stdio"`.
fn launch_transport(transport: Option<&str>) -> &str {
    transport
        .filter(|value| !value.is_empty())
        .unwrap_or("stdio")
}

fn artifact(value: &Value) -> Result<Artifact<'_>, &'static str> {
    let map = value.as_object().ok_or(ERR_INVALID)?;
    exact_keys(map, &ARTIFACT_KEYS)?;
    let saved_origin = map.get("saved_origin").ok_or(ERR_INVALID)?;
    if !saved_origin.is_null() && !saved_origin.is_array() {
        return Err(ERR_INVALID);
    }
    Ok(Artifact {
        harness: text(map, "harness")?,
        name: text(map, "name")?,
        source_scope: text(map, "source_scope")?.to_owned(),
        config_path: text(map, "config_path")?.to_owned(),
        command: optional_text(map, "command")?.map(str::to_owned),
        args: string_list(map, "args")?,
        transport: optional_text(map, "transport")?,
        env: env_pairs(map.get("env").ok_or(ERR_INVALID)?)?,
        guard_managed_proxy: flag(map, "guard_managed_proxy")?,
        enabled: flag(map, "enabled")?,
        saved_origin,
        saved_guard_home: optional_text(map, "saved_guard_home")?,
    })
}

fn env_pairs(value: &Value) -> Result<Option<Vec<(String, String)>>, &'static str> {
    if value.is_null() {
        return Ok(None);
    }
    value
        .as_array()
        .ok_or(ERR_INVALID)?
        .iter()
        .map(|pair| match pair.as_array().map(Vec::as_slice) {
            Some([Value::String(key), Value::String(item)]) => Ok((key.clone(), item.clone())),
            _ => Err(ERR_INVALID),
        })
        .collect::<Result<Vec<(String, String)>, &'static str>>()
        .map(Some)
}

fn flag(map: &Map<String, Value>, key: &str) -> Result<bool, &'static str> {
    map.get(key).and_then(Value::as_bool).ok_or(ERR_INVALID)
}

fn string_list(map: &Map<String, Value>, key: &str) -> Result<Vec<String>, &'static str> {
    map.get(key)
        .and_then(Value::as_array)
        .ok_or(ERR_INVALID)?
        .iter()
        .map(|item| item.as_str().map(str::to_owned).ok_or(ERR_INVALID))
        .collect()
}

fn borrowed(values: &[String]) -> Vec<&str> {
    values.iter().map(String::as_str).collect()
}

#[cfg(test)]
#[path = "harness_mcp_select_tests.rs"]
mod tests;

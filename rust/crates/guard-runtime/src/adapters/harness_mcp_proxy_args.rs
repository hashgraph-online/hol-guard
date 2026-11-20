//! The `harness_mcp_discovery` `proxy_args` and `proxy_env` ops:
//! `proxy_cli_args` and `proxy_process_env` in
//! `guard/adapters/mcp_servers.py` before they moved. Python only wraps the
//! answer in Guard's launcher and adds the launcher's own env.

use serde_json::{json, Map, Value};

use super::super::upstream::LAUNCHER_ENV_KEYS;
use super::{borrowed, env_pairs, exact_keys, optional_text, string_list, text};
use crate::opencode_server_id::server_identifier;
use crate::runner_authority_op::{KindResult, ERR_INVALID};
use guard_contracts::python_strip;

const PROXY_ARGS_KEYS: [&str; 6] = [
    "op",
    "proxy_command",
    "guard_home",
    "home",
    "workspace",
    "server",
];
const PROXY_ENV_KEYS: [&str; 2] = ["op", "env"];
const SERVER_KEYS: [&str; 8] = [
    "harness",
    "name",
    "source_scope",
    "config_path",
    "command",
    "args",
    "transport",
    "env",
];
const MODULE_PREFIX: [&str; 3] = ["-m", "codex_plugin_scanner.cli", "guard"];

/// The argv after the launcher for one Guard MCP proxy: the server's identity
/// and launch, its stable Cloud id, and the names of the env keys it may take.
pub(super) fn proxy_args(map: &Map<String, Value>) -> KindResult {
    exact_keys(map, &PROXY_ARGS_KEYS)?;
    let server = map
        .get("server")
        .and_then(Value::as_object)
        .ok_or(ERR_INVALID)?;
    exact_keys(server, &SERVER_KEYS)?;
    let server_args = string_list(server, "args")?;
    let (name, scope, command, transport) = (
        text(server, "name")?,
        text(server, "source_scope")?,
        text(server, "command")?,
        text(server, "transport")?,
    );
    let server_id = server_identifier(
        text(server, "harness")?,
        name,
        scope,
        command,
        &borrowed(&server_args),
        transport,
        false,
    );
    let mut args: Vec<String> = MODULE_PREFIX
        .iter()
        .map(|part| (*part).to_owned())
        .collect();
    args.push(text(map, "proxy_command")?.to_owned());
    for (flag, value) in [
        ("--guard-home", Some(text(map, "guard_home")?)),
        ("--server-name", Some(name)),
        ("--server-id", Some(server_id.as_str())),
        ("--source-scope", Some(scope)),
        ("--config-path", Some(text(server, "config_path")?)),
        ("--transport", Some(transport)),
        ("--command", Some(command)),
        ("--home", optional_text(map, "home")?),
        ("--workspace", optional_text(map, "workspace")?),
    ] {
        if let Some(value) = value {
            args.extend([flag.to_owned(), value.to_owned()]);
        }
    }
    args.extend(server_args.iter().map(|value| format!("--arg={value}")));
    let mut keys: Vec<String> = kept_env(server)?.into_iter().map(|(key, _)| key).collect();
    keys.sort();
    args.extend(keys.iter().map(|key| format!("--server-env-key={key}")));
    Ok(json!({ "args": args }))
}

/// The server's configured env pairs that are safe to hand the proxy.
pub(super) fn proxy_env(map: &Map<String, Value>) -> KindResult {
    exact_keys(map, &PROXY_ENV_KEYS)?;
    let pairs: Vec<Value> = kept_env(map)?
        .into_iter()
        .map(|(key, value)| json!([key, value]))
        .collect();
    Ok(json!({ "env": pairs }))
}

/// `proxy_process_env`: each key stripped, empty keys and the launcher's own
/// keys dropped. A key repeated after stripping keeps its first place and its
/// last value, as a Python dict does.
fn kept_env(map: &Map<String, Value>) -> Result<Vec<(String, String)>, &'static str> {
    let mut kept: Vec<(String, String)> = Vec::new();
    for (key, value) in env_pairs(map.get("env").ok_or(ERR_INVALID)?)?.ok_or(ERR_INVALID)? {
        let key = python_strip(&key);
        if key.is_empty() || LAUNCHER_ENV_KEYS.contains(&key.to_uppercase().as_str()) {
            continue;
        }
        match kept.iter_mut().find(|(seen, _)| seen == key) {
            Some(slot) => slot.1 = value,
            None => kept.push((key.to_owned(), value)),
        }
    }
    Ok(kept)
}

#[cfg(test)]
#[path = "harness_mcp_proxy_args_tests.rs"]
mod tests;

//! The managed MCP servers of an OpenCode install: which detected servers
//! Guard can run behind its proxy, the servers it cannot, and the proxy argv
//! and environment of each managed one.
//!
//! This is `managed_stdio_servers`, `skipped_stdio_server_names`,
//! `proxy_cli_args`, `proxy_process_env`, `_guard_proxy_command` and
//! `merge_guard_launcher_env` as the OpenCode install used them. The
//! selection, the proxy argv and the proxy environment are the
//! `harness_mcp_discovery` ops; the Guard process only supplies the facts that
//! live in it (see [`Launch`]).

use serde_json::{json, Value};

use super::files::{text, Doc};
use super::opencode::PROXY;
use super::{caller, path_text, proxy_launch, Ctx, Failure, Step};
use crate::pyjson::PyVal;
use guard_contracts::python_strip;

/// The proxy argv every Guard MCP proxy launch starts with.
pub(super) const MODULE_PREFIX: [&str; 3] = ["-m", "codex_plugin_scanner.cli", "guard"];
const RELAY_COMMAND: &str = "mcp-relay";
/// The variable the launcher's import path travels in.
const PYTHONPATH: &str = "PYTHONPATH";

fn unavailable(error: &str) -> Failure {
    Failure::Refusal(format!("native_mcp_server_identity_unavailable:{error}"))
}

fn malformed() -> Failure {
    Failure::Refusal("native_mcp_server_select_malformed".into())
}

/// One local stdio server Guard can wrap, as the `select` op answered it.
pub(super) struct Server {
    pub(super) name: String,
    pub(super) source_scope: String,
    pub(super) config_path: String,
    pub(super) command: String,
    pub(super) args: Vec<String>,
    pub(super) env: Vec<(String, String)>,
    pub(super) enabled: bool,
    transport: String,
}

/// What the detected artifacts say about the install's servers.
pub(super) struct Selection {
    /// Every managed server, in detection order.
    pub(super) servers: Vec<Server>,
    /// The named servers Guard cannot manage through its proxy.
    pub(super) skipped: Vec<String>,
    /// Every detected server artifact's name.
    pub(super) artifacts: Vec<String>,
}

/// The facts of the Guard process a proxy launch is built from.
pub(super) struct Launch {
    /// The attested interpreter, or the frozen Guard launcher.
    executable: String,
    frozen: bool,
    /// The native runtime that relays the proxy, when one is selected.
    relay: Option<String>,
    /// `merge_guard_launcher_env()` of this process, in order.
    env: Vec<(String, String)>,
}

impl Launch {
    /// `_launch_facts`: the caller's hook interpreter, whether it is frozen,
    /// the relay its Guard home selects and its launcher environment.
    pub(super) fn of(ctx: &Ctx) -> Step<Self> {
        Ok(Self {
            executable: caller::hook_python(ctx)?.to_owned(),
            frozen: caller::frozen(ctx)?,
            relay: proxy_launch::bridge(
                ctx,
                proxy_launch::RELAY_FEATURE,
                Some(ctx.guard_home.as_path()),
            )?,
            env: proxy_launch::launcher_env(ctx, &[]),
        })
    }
}

/// A server's proxy launches and the environment its proxy runs with.
pub(super) struct Launched {
    pub(super) proxy_environment: PyVal,
    /// `[companion, override]`: the argv without and with the workspace.
    pub(super) launches: [PyVal; 2],
}

fn pair(value: &Value) -> Option<(String, String)> {
    match value.as_array().map(Vec::as_slice) {
        Some([Value::String(key), Value::String(item)]) => Some((key.clone(), item.clone())),
        _ => None,
    }
}

fn pairs(value: &Value) -> Option<Vec<(String, String)>> {
    value.as_array()?.iter().map(pair).collect()
}

/// The string pairs of a mapping, as `_env_pairs` reads one.
fn mapping_pairs(value: Option<&Value>) -> Value {
    match value.and_then(Value::as_object) {
        Some(entries) => Value::Array(
            entries
                .iter()
                .filter_map(|(key, item)| Some(json!([key, item.as_str()?])))
                .collect(),
        ),
        None => Value::Null,
    }
}

/// Insert as a dict assignment does: a repeated key keeps its place.
fn assign(entries: &mut Vec<(String, String)>, key: String, value: String) {
    match entries.iter_mut().find(|(known, _)| *known == key) {
        Some(entry) => entry.1 = value,
        None => entries.push((key, value)),
    }
}

fn strings(value: Option<&Value>) -> Option<Vec<String>> {
    value?
        .as_array()?
        .iter()
        .map(|item| item.as_str().map(str::to_owned))
        .collect()
}

/// `_select_request`: the artifact as the `select` op reads it. A detected
/// OpenCode artifact carries no private metadata, so the arguments and the
/// environment are the ones it shows.
fn select_request(artifact: &Value) -> Option<Value> {
    let metadata = artifact.get("metadata");
    let args = match artifact.get("args") {
        None | Some(Value::Null) => Vec::new(),
        found => strings(found)?,
    };
    let text_of = |key: &str| artifact.get(key).and_then(Value::as_str);
    Some(json!({
        "harness": text_of("harness")?,
        "name": text_of("name")?,
        "source_scope": text_of("source_scope")?,
        "config_path": text_of("config_path")?,
        "command": artifact.get("command").cloned().unwrap_or(Value::Null),
        "args": args,
        "transport": artifact.get("transport").cloned().unwrap_or(Value::Null),
        "env": mapping_pairs(metadata.and_then(|metadata| metadata.get("env"))),
        "guard_managed_proxy": metadata
            .and_then(|metadata| metadata.get("guard_managed_proxy"))
            == Some(&Value::Bool(true)),
        "enabled": metadata.and_then(|metadata| metadata.get("enabled"))
            != Some(&Value::Bool(false)),
        "saved_origin": Value::Null,
        "saved_guard_home": Value::Null,
    }))
}

/// `_selected_server`: one `select` answer entry as a server.
fn selected(name: &str, found: &Value) -> Step<Server> {
    let field = |key: &str| {
        found
            .get(key)
            .and_then(Value::as_str)
            .map(str::to_owned)
            .ok_or_else(malformed)
    };
    let mut env: Vec<(String, String)> = Vec::new();
    for (key, value) in found.get("env").and_then(pairs).ok_or_else(malformed)? {
        assign(&mut env, key, value);
    }
    Ok(Server {
        name: name.to_owned(),
        source_scope: field("source_scope")?,
        config_path: field("config_path")?,
        command: field("command")?,
        args: strings(found.get("args")).ok_or_else(malformed)?,
        env,
        enabled: found.get("enabled") == Some(&Value::Bool(true)),
        transport: field("transport")?,
    })
}

/// One `harness_mcp_discovery` call, as `_native` made it.
fn discovery(request: &Value) -> Step<Value> {
    crate::harness_mcp_discovery::dispatch(request).map_err(unavailable)
}

/// `managed_stdio_servers` and `skipped_stdio_server_names` over the
/// detected artifacts: one `select` request carries every server artifact.
pub(super) fn select(artifacts: &[Value]) -> Step<Selection> {
    let detected: Vec<&Value> = artifacts
        .iter()
        .filter(|artifact| {
            artifact.get("artifact_type").and_then(Value::as_str) == Some("mcp_server")
        })
        .collect();
    let named = |artifact: &Value| {
        artifact
            .get("name")
            .and_then(Value::as_str)
            .map(str::to_owned)
            .ok_or(Failure::Invalid)
    };
    let names = detected
        .iter()
        .map(|artifact| named(artifact))
        .collect::<Step<Vec<_>>>()?;
    let mut positions = Vec::new();
    let mut requests = Vec::new();
    for (index, artifact) in detected.iter().enumerate() {
        if let Some(request) = select_request(artifact) {
            positions.push(index);
            requests.push(request);
        }
    }
    let mut found: Vec<Option<Value>> = vec![None; detected.len()];
    if !requests.is_empty() {
        let answer = discovery(&json!({
            "op": "select",
            "include_proxy": false,
            "artifacts": requests,
        }))?;
        let list = answer
            .get("servers")
            .and_then(Value::as_array)
            .filter(|list| list.len() == positions.len())
            .ok_or_else(malformed)?;
        for (index, item) in positions.iter().zip(list) {
            if !item.is_null() {
                found[*index] = Some(item.clone());
            }
        }
    }
    let mut servers = Vec::new();
    let mut skipped = Vec::new();
    for (name, item) in names.iter().zip(&found) {
        match item {
            Some(item) => servers.push(selected(name, item)?),
            None if !python_strip(name).is_empty() => skipped.push(name.clone()),
            None => {}
        }
    }
    Ok(Selection {
        servers,
        skipped,
        artifacts: names,
    })
}

/// `_guard_proxy_command(context, proxy_cli_args(...))`: the launch argv of
/// one proxy, through the native relay when the Guard process selected one.
fn proxy_command(
    ctx: &Ctx,
    launch: &Launch,
    server: &Server,
    workspace: Option<&str>,
) -> Step<PyVal> {
    let home = (!ctx.default_home()).then(|| path_text(&ctx.home));
    let env: Vec<Value> = server
        .env
        .iter()
        .map(|(key, item)| json!([key, item]))
        .collect();
    let answer = discovery(&json!({
        "op": "proxy_args",
        "proxy_command": PROXY,
        "guard_home": path_text(&ctx.guard_home),
        "home": home,
        "workspace": workspace,
        "server": {
            "harness": "opencode",
            "name": server.name,
            "source_scope": server.source_scope,
            "config_path": server.config_path,
            "command": server.command,
            "args": server.args,
            "transport": server.transport,
            "env": env,
        },
    }))?;
    let args = strings(answer.get("args")).ok_or_else(malformed)?;
    let mut argv = vec![];
    if let Some(relay) = &launch.relay {
        argv.extend([relay.as_str(), RELAY_COMMAND, launch.executable.as_str()]);
        argv.extend(args.iter().map(String::as_str));
    } else if launch.frozen {
        if args.iter().take(3).map(String::as_str).ne(MODULE_PREFIX) {
            return Err(Failure::Runtime(
                "Frozen Guard CLI arguments do not match the managed launch contract.".into(),
            ));
        }
        argv.push(launch.executable.as_str());
        argv.extend(args.iter().skip(3).map(String::as_str));
    } else {
        argv.push(launch.executable.as_str());
        argv.extend(args.iter().map(String::as_str));
    }
    Ok(PyVal::List(argv.into_iter().map(text).collect()))
}

/// `merge_guard_launcher_env(proxy_process_env(server.env))`: the import path
/// first, the server's own variables the proxy may take, then the native
/// bindings. A server cannot set any of those, so nothing is overridden.
fn proxy_environment(launch: &Launch, server: &Server) -> Step<PyVal> {
    let env: Vec<Value> = server
        .env
        .iter()
        .map(|(key, item)| json!([key, item]))
        .collect();
    let answer = discovery(&json!({ "op": "proxy_env", "env": env }))?;
    let kept = answer.get("env").and_then(pairs).ok_or_else(malformed)?;
    let mut merged = Doc::default();
    for (key, value) in launch.env.iter().filter(|(key, _)| key == PYTHONPATH) {
        merged.set(key, text(value.as_str()));
    }
    for (key, value) in &kept {
        merged.set(key, text(value.as_str()));
    }
    for (key, value) in launch.env.iter().filter(|(key, _)| key != PYTHONPATH) {
        merged.set(key, text(value.as_str()));
    }
    Ok(merged.value())
}

/// The proxy launches and environment of one managed server.
pub(super) fn launched(ctx: &Ctx, launch: &Launch, server: &Server) -> Step<Launched> {
    let workspace = ctx.workspace.as_deref().map(path_text);
    Ok(Launched {
        launches: [
            proxy_command(ctx, launch, server, None)?,
            proxy_command(ctx, launch, server, workspace.as_deref())?,
        ],
        proxy_environment: proxy_environment(launch, server)?,
    })
}

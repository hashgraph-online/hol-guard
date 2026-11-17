//! How Guard launches its MCP proxies and native hook bridges:
//! `native_hook_bridge.py`, `mcp_relay_native.py`, the unpinned
//! `merge_guard_launcher_env` and `proxy_launcher_entry` before they moved.
//!
//! The native runtime replaces the Python MCP proxy through its `mcp-relay`
//! subcommand when the validated runtime advertises `mcp-stdio-relay-v1`. It
//! receives the exact Python proxy argv after the subcommand, so one argv
//! serves both launchers and upstream recovery reads it unchanged. A frozen
//! Guard launches the verified copy under the proxy's `--guard-home`, as its
//! hooks do, because its bundled runtime can live in a per-launch extraction
//! directory.
//!
//! The runtime the Guard process validated travels in the caller stamp as
//! `native_runtime`: `{path, size, sha256, features}`, or null when the
//! process found none it could use.

use std::path::{Path, PathBuf};

use serde_json::{json, Map, Value};

use super::durable_runtime::{self, Identity};
use super::files::{text, Doc};
use super::{caller, path_text, Ctx, Failure, Step};
use crate::pyjson::PyVal;

/// The feature a runtime advertises when it can relay an MCP proxy.
pub(super) const RELAY_FEATURE: &str = "mcp-stdio-relay-v1";
const RELAY_COMMAND: &str = "mcp-relay";
/// The proxy argv every module-form Guard MCP proxy launch starts with.
const MODULE_PREFIX: [&str; 3] = ["-m", "codex_plugin_scanner.cli", "guard"];
/// The proxies the native relay parses; other Guard proxies stay on Python.
const RELAY_PROXIES: [&str; 6] = [
    "cline-mcp-proxy",
    "codex-mcp-proxy",
    "copilot-mcp-proxy",
    "cursor-mcp-proxy",
    "hermes-mcp-proxy",
    "opencode-mcp-proxy",
];
const PYTHONPATH: &str = "PYTHONPATH";

fn unavailable(error: &str) -> Failure {
    Failure::Refusal(format!("native_mcp_server_identity_unavailable:{error}"))
}

fn malformed() -> Failure {
    Failure::Refusal("native_mcp_server_select_malformed".into())
}

/// `native_hook_bridge_executable(feature, guard_home=guard_home)`: the
/// validated runtime when it advertises `feature`, a frozen caller's durable
/// copy of it under `guard_home`, or `None`.
pub(super) fn bridge(ctx: &Ctx, feature: &str, guard_home: Option<&Path>) -> Step<Option<String>> {
    let frozen = caller::frozen(ctx)?;
    if frozen && guard_home.is_none() {
        return Ok(None);
    }
    let runtime = match ctx.caller.get("native_runtime") {
        None | Some(Value::Null) => return Ok(None),
        Some(Value::Object(runtime)) => runtime,
        Some(_) => return Err(Failure::Invalid),
    };
    let text = |key: &str| {
        runtime
            .get(key)
            .and_then(Value::as_str)
            .ok_or(Failure::Invalid)
    };
    let path = text("path")?;
    let advertised = runtime
        .get("features")
        .and_then(Value::as_array)
        .ok_or(Failure::Invalid)?
        .iter()
        .any(|item| item.as_str() == Some(feature));
    if !advertised {
        return Ok(None);
    }
    let Some(guard_home) = guard_home.filter(|_| frozen) else {
        return Ok(Some(path.to_owned()));
    };
    let identity = Identity {
        path: Path::new(path),
        size: runtime
            .get("size")
            .and_then(Value::as_u64)
            .ok_or(Failure::Invalid)?,
        sha256: text("sha256")?,
    };
    Ok(durable_runtime::hook_runtime(&identity, guard_home).map(|copy| path_text(&copy)))
}

/// `_relay_argv`: the module-form proxy argv the relay parses, or `None` when
/// it does not relay. A frozen caller's argv names the proxy directly; the
/// relay gets it back in module form, which the frozen launcher also runs.
fn relay_argv(ctx: &Ctx, args: &[String]) -> Step<Option<Vec<String>>> {
    let module_form = args.len() > 3
        && args.iter().take(3).map(String::as_str).eq(MODULE_PREFIX)
        && RELAY_PROXIES.contains(&args[3].as_str());
    if module_form {
        return Ok(Some(args.to_vec()));
    }
    if caller::frozen(ctx)?
        && args
            .first()
            .is_some_and(|first| RELAY_PROXIES.contains(&first.as_str()))
    {
        let mut relayed: Vec<String> = MODULE_PREFIX
            .iter()
            .map(|part| (*part).to_owned())
            .collect();
        relayed.extend(args.iter().cloned());
        return Ok(Some(relayed));
    }
    Ok(None)
}

/// `_guard_home`: the proxy argv's `--guard-home`, read as the relay parses
/// it. Tokens after the proxy command are `--flag value` or `--flag=value`
/// pairs, and a repeated flag keeps its last value.
fn proxy_guard_home(args: &[String]) -> Option<PathBuf> {
    let mut guard_home = None;
    let mut rest = args.iter().skip(MODULE_PREFIX.len() + 1);
    while let Some(token) = rest.next() {
        let (flag, value) = match token.split_once('=') {
            Some((flag, inline)) => (flag, Some(inline.to_owned())),
            None => (token.as_str(), rest.next().cloned()),
        };
        if flag == "--guard-home" {
            if let Some(value) = value.filter(|value| !value.is_empty()) {
                guard_home = Some(value);
            }
        }
    }
    guard_home.map(PathBuf::from)
}

/// `mcp_proxy_launch(python, args)`: `(command, args)` launching a Python
/// proxy argv, through the native relay when the runtime can relay it.
pub(super) fn relay_launch(
    ctx: &Ctx,
    python: &str,
    args: &[String],
) -> Step<(String, Vec<String>)> {
    let Some(relayed) = relay_argv(ctx, args)? else {
        return Ok((python.to_owned(), args.to_vec()));
    };
    let guard_home = proxy_guard_home(&relayed);
    let Some(relay) = bridge(ctx, RELAY_FEATURE, guard_home.as_deref())? else {
        return Ok((python.to_owned(), args.to_vec()));
    };
    let mut launch = vec![RELAY_COMMAND.to_owned(), python.to_owned()];
    launch.extend(relayed);
    Ok((relay, launch))
}

/// `python_proxy_launch`: unwrap a native relay launch to the Python proxy
/// `(command, args)` it carries.
pub(super) fn python_launch(
    command: Option<&str>,
    args: &[String],
) -> (Option<String>, Vec<String>) {
    let relays = args.len() > 5
        && args[0] == RELAY_COMMAND
        && args
            .iter()
            .skip(2)
            .take(3)
            .map(String::as_str)
            .eq(MODULE_PREFIX)
        && RELAY_PROXIES.contains(&args[5].as_str());
    if relays {
        return (Some(args[1].clone()), args[2..].to_vec());
    }
    (command.map(str::to_owned), args.to_vec())
}

fn separator(ctx: &Ctx) -> char {
    if ctx.windows {
        ';'
    } else {
        ':'
    }
}

/// `str(Path(entry))` of an absolute or relative entry: separators collapsed,
/// `.` components and a trailing separator dropped.
fn pure_path(ctx: &Ctx, entry: &str) -> String {
    let text = path_text(&Path::new(entry).components().collect::<PathBuf>());
    if ctx.windows {
        text.replace('/', "\\")
    } else {
        text
    }
}

/// `Path(entry).expanduser()` against the caller's home.
fn expand_user(ctx: &Ctx, entry: &str) -> String {
    match entry.strip_prefix('~') {
        Some("") => path_text(&ctx.user_home),
        Some(rest) if rest.starts_with('/') || (ctx.windows && rest.starts_with('\\')) => {
            format!("{}{rest}", path_text(&ctx.user_home))
        }
        _ => entry.to_owned(),
    }
}

/// `_normalize_path_entry`: an absolute entry as its pure path, a relative
/// one resolved against `base` when there is one, else kept as written.
fn normalize_entry(ctx: &Ctx, entry: &str, base: Option<&Path>) -> Option<String> {
    let trimmed = entry.trim();
    if trimmed.is_empty() {
        return None;
    }
    let expanded = expand_user(ctx, trimmed);
    if Path::new(&expanded).is_absolute() {
        return Some(pure_path(ctx, &expanded));
    }
    match base {
        Some(base) => Some(path_text(
            &crate::harness_coverage::artifacts::resolve_lenient(&base.join(&expanded)),
        )),
        None => Some(trimmed.to_owned()),
    }
}

/// `_merge_path_entries`: the entries of both lists in order, normalized,
/// each once.
fn merge_entries(ctx: &Ctx, left: &str, right: &str, base: Option<&Path>) -> String {
    let mut values: Vec<String> = Vec::new();
    for entry in left
        .split(separator(ctx))
        .chain(right.split(separator(ctx)))
    {
        if let Some(value) = normalize_entry(ctx, entry, base) {
            if !values.contains(&value) {
                values.push(value);
            }
        }
    }
    values.join(&separator(ctx).to_string())
}

/// `_normalize_launcher_pythonpath(os.environ.get("PYTHONPATH"))`: relative
/// entries resolved against the caller's directory, or dropped without one.
fn caller_pythonpath(ctx: &Ctx) -> String {
    let value = ctx.env(PYTHONPATH).unwrap_or("");
    match &ctx.cwd {
        Some(cwd) => merge_entries(ctx, "", value, Some(cwd)),
        None => {
            let mut values: Vec<String> = Vec::new();
            for entry in value.split(separator(ctx)) {
                let expanded = expand_user(ctx, entry.trim());
                if Path::new(&expanded).is_absolute() {
                    let normalized = pure_path(ctx, &expanded);
                    if !values.contains(&normalized) {
                        values.push(normalized);
                    }
                }
            }
            values.join(&separator(ctx).to_string())
        }
    }
}

/// Insert as a dict assignment does: a repeated key keeps its place.
fn assign(entries: &mut Vec<(String, String)>, key: &str, value: String) {
    match entries.iter_mut().find(|(known, _)| known == key) {
        Some(entry) => entry.1 = value,
        None => entries.push((key.to_owned(), value)),
    }
}

/// `merge_guard_launcher_env(env)`: the caller's import path, `env` merged
/// over it, then each native binding variable the caller set, which `env`
/// cannot override.
pub(super) fn launcher_env(ctx: &Ctx, env: &[(String, String)]) -> Vec<(String, String)> {
    let mut merged: Vec<(String, String)> = Vec::new();
    let pythonpath = caller_pythonpath(ctx);
    if !pythonpath.is_empty() {
        merged.push((PYTHONPATH.to_owned(), pythonpath));
    }
    for (key, value) in env {
        if key == PYTHONPATH {
            if value.trim().is_empty() {
                assign(&mut merged, PYTHONPATH, String::new());
                continue;
            }
            let left = merged
                .iter()
                .find(|(known, _)| known == PYTHONPATH)
                .map_or(String::new(), |(_, value)| value.clone());
            let joined = merge_entries(ctx, &left, value, None);
            if joined.is_empty() {
                merged.retain(|(known, _)| known != PYTHONPATH);
            } else {
                assign(&mut merged, PYTHONPATH, joined);
            }
            continue;
        }
        if caller::LAUNCHER_BINDING_ENV.contains(&key.as_str()) {
            continue;
        }
        assign(&mut merged, key, value.clone());
    }
    for name in caller::LAUNCHER_BINDING_ENV {
        if let Some(value) = ctx.env(name).filter(|value| !value.is_empty()) {
            assign(&mut merged, name, value.to_owned());
        }
    }
    merged
}

fn discovery(request: &Value) -> Step<Value> {
    crate::harness_mcp_discovery::dispatch(request).map_err(unavailable)
}

fn pairs(value: Option<&Value>) -> Option<Vec<(String, String)>> {
    value?
        .as_array()?
        .iter()
        .map(|pair| match pair.as_array().map(Vec::as_slice) {
            Some([Value::String(key), Value::String(item)]) => Some((key.clone(), item.clone())),
            _ => None,
        })
        .collect()
}

/// `proxy_launcher_entry`: the `{command, args, env?}` dict, in order, launching one managed
/// server behind `proxy_command`. `server` holds the `proxy_args` op's server
/// fields: harness, name, source_scope, config_path, command, args,
/// transport and env pairs.
pub(super) fn entry(
    ctx: &Ctx,
    proxy_command: &str,
    server: &Map<String, Value>,
) -> Step<Vec<(String, PyVal)>> {
    let home = (!ctx.default_home()).then(|| path_text(&ctx.home));
    let workspace = ctx.workspace.as_deref().map(path_text);
    let answer = discovery(&json!({
        "op": "proxy_args",
        "proxy_command": proxy_command,
        "guard_home": path_text(&ctx.guard_home),
        "home": home,
        "workspace": workspace,
        "server": server,
    }))?;
    let args = answer
        .get("args")
        .and_then(Value::as_array)
        .ok_or_else(malformed)?
        .iter()
        .map(|arg| arg.as_str().map(str::to_owned))
        .collect::<Option<Vec<_>>>()
        .ok_or_else(malformed)?;
    let (command, launch_args) = relay_launch(ctx, caller::launcher(ctx)?, &args)?;
    let server_env = server
        .get("env")
        .filter(|env| !env.is_null())
        .cloned()
        .unwrap_or(Value::Array(Vec::new()));
    let kept = pairs(discovery(&json!({ "op": "proxy_env", "env": server_env }))?.get("env"))
        .ok_or_else(malformed)?;
    let env = launcher_env(ctx, &kept);
    let mut launch = Doc::default();
    launch.set("command", text(command)).set(
        "args",
        PyVal::List(launch_args.into_iter().map(text).collect()),
    );
    if !env.is_empty() {
        let env = env.into_iter().map(|(key, value)| (key, text(value)));
        launch.set("env", PyVal::Dict(env.collect()));
    }
    Ok(launch.0)
}

#[cfg(test)]
#[path = "tests_proxy_launch.rs"]
mod tests;

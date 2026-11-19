//! Codex: the MCP server and hook-feature rewrites of a config payload.
//!
//! `alternate_cleanup` strips Guard's entries from a config another install
//! wrote, and `managed_mcp` refreshes each Guard proxy's launch and writes the
//! managed servers. `managed_mcp` replies `relaunch` with each proxy's argv;
//! the Guard process answers the launch it would write for it today.

use serde_json::{json, Map, Value};

use super::codex::{compact, registered, strings};
use super::codex_merge::{get, payload, pop, py_eq, render, set, Entries};
use super::codex_migration::{owners_op, without_legacy};
use super::{Ctx, Failure, Step};
use crate::cursor_editor_plan::is_guard_proxy;
use crate::pyjson::{self, PyVal};

/// The named entries whose `args` is a list (absent reads as `[]`), with
/// their command and string args, as `guard_proxy_server_names` reads them.
fn launches(servers: &[(String, PyVal)], names: Option<&[String]>) -> Vec<(String, bool)> {
    let mut found = Vec::new();
    for (name, server) in servers {
        if names.is_some_and(|names| !names.contains(name)) {
            continue;
        }
        let Some(server) = server.as_dict() else {
            continue;
        };
        let args = match get(server, "args") {
            Some(PyVal::List(args)) => args.as_slice(),
            None if names.is_some() => &[],
            _ => continue,
        };
        let args: Vec<String> = args
            .iter()
            .filter_map(|arg| arg.as_str().map(str::to_owned))
            .collect();
        let command = get(server, "command").and_then(PyVal::as_str);
        found.push((name.clone(), is_guard_proxy(command, &args)));
    }
    found
}

/// The hooks left once this install's exact legacy bridge entries are gone,
/// or `None` when none was there: `_current_install_legacy_bindings`, then
/// `remove_manifest_bound_hook_events`, over the legacy owner fields.
fn legacy_cleaned(fields: &Map<String, Value>, payload: &[(String, PyVal)]) -> Step<Option<PyVal>> {
    let Some(hooks @ PyVal::Dict(_)) = get(payload, "hooks") else {
        return Ok(None);
    };
    let mut base = Map::new();
    for key in [
        "expected",
        "argv",
        "legacy_argv",
        "statuses",
        "windows",
        "long_paths",
    ] {
        base.insert(
            key.into(),
            fields.get(key).cloned().ok_or(Failure::Invalid)?,
        );
    }
    let hooks = compact(hooks, false);
    let mut extra = Map::new();
    extra.insert("hooks".into(), json!(hooks));
    let legacy = owners_op(&base, "legacy", extra)?;
    let bindings = legacy
        .get("bindings")
        .and_then(Value::as_str)
        .ok_or(Failure::Invalid)?;
    let mut extra = Map::new();
    extra.insert("hooks".into(), json!(hooks));
    extra.insert("bindings".into(), json!(bindings));
    let removed = owners_op(&without_legacy(&base), "remove", extra)?;
    if removed.get("changed").and_then(Value::as_bool) != Some(true) {
        return Ok(None);
    }
    let cleaned = removed
        .get("hooks")
        .and_then(Value::as_str)
        .ok_or(Failure::Invalid)?;
    pyjson::parse(cleaned)
        .map(Some)
        .map_err(|_| Failure::Invalid)
}

/// `render_codex_alternate_cleanup`; with `remove_hooks`, this install's
/// legacy Guard hooks go first.
pub(super) fn alternate_cleanup(fields: &Map<String, Value>) -> Step<Value> {
    let original = payload(fields, "payload")?;
    let mut rendered = original.clone();
    let remove_hooks = fields.get("remove_hooks").and_then(Value::as_bool) == Some(true);
    if remove_hooks {
        if let Some(cleaned) = legacy_cleaned(fields, &original)? {
            if cleaned.as_dict().is_some_and(|hooks| !hooks.is_empty()) {
                set(&mut rendered, "hooks", cleaned);
            } else {
                pop(&mut rendered, "hooks");
            }
        }
        if !registered(get(&rendered, "hooks")) {
            if let Some(PyVal::Dict(features)) = rendered
                .iter_mut()
                .find_map(|(name, value)| (name == "features").then_some(value))
            {
                pop(features, "codex_hooks");
                pop(features, "hooks");
                if features.is_empty() {
                    pop(&mut rendered, "features");
                }
            }
        }
    }
    let names = strings(fields.get("managed_server_names"))?;
    if let Some(PyVal::Dict(servers)) = rendered
        .iter_mut()
        .find_map(|(name, value)| (name == "mcp_servers").then_some(value))
    {
        let mut removed = false;
        for (name, proxy) in launches(servers, Some(&names)) {
            if !proxy {
                pop(servers, &name);
                removed = true;
            }
        }
        if removed && servers.is_empty() {
            pop(&mut rendered, "mcp_servers");
        }
    }
    let changed = !py_eq(
        &PyVal::Dict(rendered.clone()),
        &PyVal::Dict(original.clone()),
    );
    let hooks_changed = remove_hooks
        && ["hooks", "features"].iter().any(|key| {
            match (get(&rendered, key), get(&original, key)) {
                (None, None) => false,
                (Some(after), Some(before)) => !py_eq(after, before),
                _ => true,
            }
        });
    Ok(json!({
        "rendered": render(rendered),
        "changed": changed,
        "hooks_changed": hooks_changed,
    }))
}

/// `render_codex_managed_mcp`: refresh each Guard proxy's launch the way the
/// caller would write it, then write or drop the managed servers Python
/// rendered (`null` drops one).
///
/// With a workspace (`workspace_payload` present), a workspace entry of the
/// same name shadows a managed server that was not itself read from the project, so
/// that server is dropped rather than written over it.
pub(super) fn managed_mcp(ctx: &Ctx, fields: &Map<String, Value>) -> Step<Value> {
    let mut rendered = payload(fields, "payload")?;
    let mut servers: Entries = get(&rendered, "mcp_servers")
        .and_then(PyVal::as_dict)
        .map(<[_]>::to_vec)
        .unwrap_or_default();
    let proxies: Vec<String> = launches(&servers, None)
        .into_iter()
        .filter_map(|(name, proxy)| proxy.then_some(name))
        .collect();
    let mut migrated = Vec::new();
    if !proxies.is_empty() {
        let python = super::caller::hook_python(ctx)?;
        for name in &proxies {
            let proxy_args: Vec<String> = get(&servers, name)
                .and_then(|server| server.get("args"))
                .and_then(PyVal::as_list)
                .unwrap_or_default()
                .iter()
                .filter_map(|arg| arg.as_str().map(str::to_owned))
                .collect();
            let (_, python_args) = super::proxy_launch::python_launch(None, &proxy_args);
            let (launcher, launch_args) =
                super::proxy_launch::relay_launch(ctx, python, &python_args)?;
            let launcher = &launcher;
            let Some(PyVal::Dict(server)) = servers
                .iter_mut()
                .find_map(|(key, value)| (key == name).then_some(value))
            else {
                continue;
            };
            let args: Vec<&str> = get(server, "args")
                .and_then(PyVal::as_list)
                .unwrap_or_default()
                .iter()
                .filter_map(PyVal::as_str)
                .collect();
            let same_command = get(server, "command").and_then(PyVal::as_str) == Some(launcher);
            if same_command && args == launch_args {
                continue;
            }
            set(server, "command", PyVal::Str(launcher.clone()));
            set(
                server,
                "args",
                PyVal::List(launch_args.into_iter().map(PyVal::Str).collect()),
            );
            migrated.push(name.clone());
        }
    }
    migrated.sort();
    let workspace_names: Option<Vec<String>> = match fields.get("workspace_payload") {
        None | Some(Value::Null) => None,
        Some(_) => Some(
            get(&payload(fields, "workspace_payload")?, "mcp_servers")
                .and_then(PyVal::as_dict)
                .unwrap_or_default()
                .iter()
                .filter(|(_, server)| server.as_dict().is_some())
                .map(|(name, _)| name.clone())
                .collect(),
        ),
    };
    for server in fields
        .get("servers")
        .and_then(Value::as_array)
        .ok_or(Failure::Invalid)?
    {
        let name = server
            .get("name")
            .and_then(Value::as_str)
            .ok_or(Failure::Invalid)?;
        let shadowed = workspace_names.as_ref().is_some_and(|names| {
            server.get("source_scope").and_then(Value::as_str) != Some("project")
                && names.iter().any(|shadow| shadow == name)
        });
        match server.get("entry").and_then(Value::as_str) {
            Some(raw) if !shadowed => {
                let entry = pyjson::parse(raw).map_err(|_| Failure::Invalid)?;
                set(&mut servers, name, entry);
            }
            _ => {
                pop(&mut servers, name);
            }
        }
    }
    set(&mut rendered, "mcp_servers", PyVal::Dict(servers));
    Ok(json!({ "rendered": render(rendered), "migrated": migrated }))
}

//! Cline install and uninstall: the surface and transport choice, one
//! transport's install and its confirmation, the manifest and the removal.
//!
//! Python runs the shim and the MCP proxy entries. An install answers its
//! probe (the `node --check` verdict or the hook canary's run), and
//! `confirm_transport` takes it back with the manifest.

use std::fs;

use serde_json::{json, Map, Value};

use super::cline::{
    adapter_state, adapter_state_path, canary_run, hosts, runtime, write_file, Hosts,
};
use super::cline_hooks::{self, judged};
use super::{cline_mcp, cline_plugin, Ctx, Failure, Step};
use crate::context_digest::python_strip;

const SURFACES: [&str; 5] = ["auto", "hooks", "plugin", "cli", "all"];
const SCHEMA: u64 = 1;
const FILE_MODE: u32 = 0o644;

/// `_surface`: an absent or empty surface is the default; `editor` means
/// native hooks.
fn surface(fields: &Map<String, Value>, default: &str) -> Step<String> {
    let raw = fields.get("surface").and_then(Value::as_str);
    let value = raw.filter(|value| !value.is_empty()).unwrap_or(default);
    let normalized = python_strip(value).to_lowercase();
    let normalized = if normalized == "editor" {
        "hooks".to_owned()
    } else {
        normalized
    };
    if SURFACES.contains(&normalized.as_str()) {
        Ok(normalized)
    } else {
        let shown = raw.unwrap_or("None");
        Err(Failure::Refusal(format!(
            "Unsupported Cline surface: {shown}"
        )))
    }
}

fn plan(request: Value) -> Step<Map<String, Value>> {
    match crate::cline_install_plan::dispatch(&request)? {
        Value::Object(answer) => Ok(answer),
        _ => Err(Failure::Invalid),
    }
}

fn flag(fields: &Map<String, Value>, key: &str) -> Step<bool> {
    fields
        .get(key)
        .and_then(Value::as_bool)
        .ok_or(Failure::Invalid)
}

fn text<'a>(fields: &'a Map<String, Value>, key: &str) -> Step<&'a str> {
    fields
        .get(key)
        .and_then(Value::as_str)
        .ok_or(Failure::Invalid)
}

fn install_plan(ctx: &Ctx, fields: &Map<String, Value>) -> Step<Value> {
    let surface = surface(fields, "auto")?;
    let hosts = hosts(ctx, fields)?;
    let answer = plan(json!({
        "op": "transport",
        "surface": surface,
        "frozen": flag(fields, "frozen")?,
        "cli": hosts.cli.is_some(),
        "vscode": !hosts.vscode.is_empty(),
        "jetbrains": !hosts.jetbrains.is_empty(),
    }))?;
    Ok(json!({
        "surface": surface,
        "transport": answer.get("transport").cloned().unwrap_or(Value::Null),
        "fallback": answer.get("fallback") == Some(&json!(true)),
        "shim": matches!(surface.as_str(), "auto" | "cli" | "all"),
        "mcp": matches!(surface.as_str(), "auto" | "all"),
    }))
}

fn install_transport(ctx: &Ctx, fields: &Map<String, Value>) -> Step<Value> {
    let facts = match fields.get("facts") {
        Some(Value::Object(facts)) => facts,
        _ => return Err(Failure::Invalid),
    };
    match text(fields, "transport")? {
        "plugin" => Ok(cline_plugin::install(ctx, facts)?),
        "hooks" if flag(fields, "frozen")? => Err(runtime(
            "Cline native-hook repair requires the managed plugin in HOL Guard Desktop.",
        )),
        "hooks" => cline_hooks::install(ctx, facts),
        other => Err(Failure::Refusal(format!(
            "Unsupported Cline enforcement transport: {other}"
        ))),
    }
}

fn hook_state(ctx: &Ctx, fields: &Map<String, Value>) -> Step<Value> {
    cline_hooks::state(ctx, true, canary_run(fields))
}

fn truthy(state: &Value, key: &str) -> bool {
    match state.get(key) {
        None | Some(Value::Null | Value::Bool(false)) => false,
        Some(Value::String(text)) => !text.is_empty(),
        Some(Value::Array(items)) => !items.is_empty(),
        Some(Value::Object(items)) => !items.is_empty(),
        Some(Value::Number(number)) => number.as_f64() != Some(0.0),
        Some(Value::Bool(true)) => true,
    }
}

fn uninstall_transport(ctx: &Ctx, transport: &str) -> Step<Value> {
    if transport == "plugin" {
        cline_plugin::uninstall(ctx)
    } else {
        cline_hooks::uninstall(ctx)
    }
}

/// `_install_transport`'s probe check and `_reconcile_transport`.
fn confirm_transport(ctx: &Ctx, fields: &Map<String, Value>) -> Step<Value> {
    let transport = text(fields, "transport")?;
    if !matches!(transport, "plugin" | "hooks") {
        return Err(Failure::Invalid);
    }
    let mut manifest = match serde_json::from_str::<Value>(text(fields, "manifest")?) {
        Ok(Value::Object(manifest)) => manifest,
        _ => return Err(Failure::Invalid),
    };
    let verdict = match fields.get("verdict") {
        Some(Value::Object(verdict)) => Value::Object(verdict.clone()),
        _ => judged(canary_run(fields).ok_or(Failure::Invalid)?)?,
    };
    if verdict.get("ok") != Some(&json!(true)) {
        uninstall_transport(ctx, transport)?;
        return Err(runtime(if transport == "plugin" {
            "Guard-generated Cline plugin did not pass its syntax probe"
        } else {
            "Guard-generated Cline native hooks did not pass their bounded canary"
        }));
    }
    let key = if transport == "plugin" {
        "syntax_probe"
    } else {
        "synthetic_canary"
    };
    manifest.insert(key.into(), verdict);
    // The hook state may ask for its canary; nothing has changed yet. Hooks
    // reuse the run that judged the install: the same launcher and input.
    let hooks = hook_state(ctx, fields)?;
    let plugin = cline_plugin::state(ctx);
    let (target, other) = if transport == "plugin" {
        (plugin, hooks)
    } else {
        (hooks, plugin)
    };
    let answer = plan(json!({
        "op": "reconcile",
        "target_ready": truthy(&target, "ready"),
        "other_installed": truthy(&other, "installed"),
        "other_ready": truthy(&other, "ready"),
    }))?;
    let cleanup = if answer.get("remove_other") == Some(&json!(true)) {
        let other = if transport == "plugin" {
            "hooks"
        } else {
            "plugin"
        };
        uninstall_transport(ctx, other)?
    } else {
        Value::Null
    };
    let previous = match adapter_state(ctx).remove("active_transport") {
        Some(Value::String(previous)) => Value::String(previous),
        _ => Value::Null,
    };
    manifest.insert("active_transport".into(), json!(transport));
    manifest.insert("previous_transport".into(), previous);
    manifest.insert(
        "transition_pending_live_proof".into(),
        json!(answer.get("transition_pending") == Some(&json!(true))),
    );
    manifest.insert("inactive_transport_cleanup".into(), cleanup);
    Ok(Value::Object(manifest))
}

/// A field Python sent as `json.dumps` text, or `null`.
fn embedded(fields: &Map<String, Value>, key: &str) -> Step<Value> {
    match fields.get(key) {
        None | Some(Value::Null) => Ok(Value::Null),
        Some(Value::String(text)) => serde_json::from_str(text).map_err(|_| Failure::Invalid),
        Some(_) => Err(Failure::Invalid),
    }
}

fn write_adapter_state(ctx: &Ctx, transport: &str, surface: &str) -> Step<()> {
    let record = json!({
        "schema_version": SCHEMA,
        "active_transport": transport,
        "surface": surface,
    });
    let text = serde_json::to_string_pretty(&record).map_err(|_| Failure::Invalid)? + "\n";
    write_file(&adapter_state_path(ctx), text.as_bytes(), FILE_MODE)
}

fn finish_install(ctx: &Ctx, fields: &Map<String, Value>) -> Step<Value> {
    let surface = surface(fields, "auto")?;
    let transport = text(fields, "transport")?;
    let transport_manifest = embedded(fields, "transport_manifest")?;
    let shim = embedded(fields, "shim")?;
    let mcp_install = embedded(fields, "mcp_install")?;
    let hosts: Hosts = hosts(ctx, fields)?;
    let hooks = hook_state(ctx, fields)?;
    let plugin = cline_plugin::state(ctx);
    let posture = plan(json!({
        "op": "posture",
        "transport": transport,
        "hook_ready": hooks.get("ready") == Some(&json!(true)),
        "plugin_ready": plugin.get("ready") == Some(&json!(true)),
        "jetbrains": !hosts.jetbrains.is_empty(),
    }))?;
    let mut manifest = json!({
        "schema_version": SCHEMA,
        "harness": "cline",
        "active": true,
        "surface": surface,
        "surfaces": [surface],
        "active_transport": transport,
        "transport": transport_manifest,
        "hosts": hosts.wire(),
        "native_hooks": hooks,
        "plugin": plugin,
        "mcp": cline_mcp::state(ctx),
        "shim": shim,
        "mcp_install": mcp_install,
    });
    let object = manifest.as_object_mut().ok_or(Failure::Invalid)?;
    object.extend(posture);
    if let Value::Object(shim) = &shim {
        if !shim.is_empty() {
            for key in ["shim_path", "shim_command"] {
                let value = shim.get(key).cloned().unwrap_or(Value::Null);
                object.insert(key.into(), value);
            }
        }
    }
    write_adapter_state(ctx, transport, &surface)?;
    Ok(manifest)
}

fn complete(result: &Value) -> bool {
    result.is_null()
        || result
            .get("complete")
            .is_none_or(|done| done == &json!(true))
}

fn uninstall(ctx: &Ctx, fields: &Map<String, Value>) -> Step<Value> {
    let surface = surface(fields, "all")?;
    let full = matches!(surface.as_str(), "auto" | "all");
    let hooks = if full || surface == "hooks" {
        cline_hooks::uninstall(ctx)?
    } else {
        Value::Null
    };
    let plugin = if full || surface == "plugin" {
        cline_plugin::uninstall(ctx)?
    } else {
        Value::Null
    };
    let mcp = if full {
        cline_mcp::restore(ctx)?
    } else {
        Value::Null
    };
    let done = [&hooks, &plugin, &mcp].into_iter().all(complete);
    let state = adapter_state_path(ctx);
    if done && full && state.is_file() {
        fs::remove_file(&state).map_err(|error| Failure::Os(error.to_string()))?;
    }
    Ok(json!({
        "manifest": {
            "harness": "cline",
            "active": !(full && done),
            "surface": surface,
            "native_hooks": hooks,
            "plugin": plugin,
            "shim": null,
            "mcp": mcp,
            "complete": done,
        },
        "remove_shim": full || surface == "cli",
    }))
}

pub(super) fn dispatch(op: &str, ctx: &Ctx, fields: &Map<String, Value>) -> Step<Value> {
    match op {
        "install_plan" => install_plan(ctx, fields),
        "install_transport" => install_transport(ctx, fields),
        "confirm_transport" => confirm_transport(ctx, fields),
        "finish_install" => finish_install(ctx, fields),
        "uninstall" => uninstall(ctx, fields),
        _ => Err(Failure::Invalid),
    }
}

//! Cursor's surfaces: which are detected on this machine, which Guard protects,
//! and the local action payload that reports both.
//!
//! - `install_surface` is the surface an install or uninstall acts on:
//!   `all` when none is named, else `editor` or `cli`.
//! - `protected_surfaces` reads the surfaces a list of managed installs name.
//! - `protected_surfaces_from_store` is that for the one managed install the
//!   store at `store_home` holds, which the runtime reads itself: nothing when Cursor is not installed, both surfaces when no
//!   install is recorded.
//! - `local_action` is the payload `cursor_action` carries.

use std::path::{Path, PathBuf};

use serde_json::{json, Map, Value};

use super::cursor::{cli_available, get, read_object, shim_installed, Ask};
use super::{managed_store, Ctx, Failure, Step};
use crate::pyjson::PyVal;

const SURFACES: [&str; 2] = ["editor", "cli"];

fn unsupported(surface: &str) -> Failure {
    Failure::Refusal(format!("Unsupported Cursor surface: {surface}"))
}

/// `_cursor_surface`: the surface a local action names, `editor` by default.
fn named_surface(value: Option<&Value>) -> Step<&str> {
    match value {
        None | Some(Value::Null) => Ok("editor"),
        Some(Value::String(surface)) if SURFACES.contains(&surface.as_str()) => {
            Ok(surface.as_str())
        }
        Some(Value::String(surface)) => Err(unsupported(surface)),
        Some(_) => Err(Failure::Invalid),
    }
}

fn add(surfaces: &mut Vec<String>, surface: &str) -> bool {
    let known = SURFACES.contains(&surface) && !surfaces.iter().any(|seen| seen == surface);
    if known {
        surfaces.push(surface.to_owned());
    }
    known
}

/// The surfaces a list of managed installs protect, in the order they first
/// name them: a row's own surface, else its manifest's `surfaces` and `surface`.
pub(super) fn protected_surfaces(installs: &[Value]) -> Vec<String> {
    let mut surfaces = Vec::new();
    for install in installs {
        if let Some(surface) = install.get("surface").and_then(Value::as_str) {
            if add(&mut surfaces, surface) {
                continue;
            }
        }
        let Some(manifest) = install
            .get("manifest")
            .filter(|manifest| manifest.is_object())
        else {
            continue;
        };
        if let Some(listed) = manifest.get("surfaces").and_then(Value::as_array) {
            for surface in listed.iter().filter_map(Value::as_str) {
                add(&mut surfaces, surface);
            }
        }
        match manifest.get("surface").and_then(Value::as_str) {
            Some("all") => {
                for surface in SURFACES {
                    add(&mut surfaces, surface);
                }
            }
            Some(surface) => {
                add(&mut surfaces, surface);
            }
            None => {}
        }
    }
    surfaces
}

fn status(detected: bool, protected: bool) -> &'static str {
    match (detected, protected) {
        (true, true) => "protected",
        (true, false) => "detected_unprotected",
        (false, _) => "not_detected",
    }
}

/// The editor configs a context reads, the workspace's first.
fn editor_configs(ctx: &Ctx) -> Vec<PathBuf> {
    let mut paths = Vec::new();
    if let Some(workspace) = &ctx.workspace {
        paths.push(workspace.join(".cursor").join("mcp.json"));
    }
    paths.push(ctx.home.join(".cursor").join("mcp.json"));
    paths
}

/// Whether a config routes at least one MCP server through a Guard proxy.
fn proxies_a_server(ctx: &Ctx, config: &Path) -> bool {
    let Some(payload) = read_object(ctx, config) else {
        return false;
    };
    let Some(PyVal::Dict(servers)) = get(&payload, "mcpServers") else {
        return false;
    };
    let table: Map<String, Value> = servers
        .iter()
        .map(|(name, server)| (name.clone(), server.to_json().unwrap_or(Value::Null)))
        .collect();
    !crate::codex_install_plan::proxy_names(&table).is_empty()
}

fn redacted_path(ctx: &Ctx, surface: &str) -> &'static str {
    if surface == "cli" {
        return "PATH:guard-cursor-agent|guard-cursor";
    }
    let workspace = ctx
        .workspace
        .as_ref()
        .map(|workspace| workspace.join(".cursor").join("mcp.json"));
    match workspace {
        Some(path) if ctx.absolute(&path).exists() => "$WORKSPACE/.cursor/mcp.json",
        _ => "$HOME/.cursor/mcp.json",
    }
}

fn surface_statuses(ask: &Ask, protected: &[String]) -> Step<Vec<Value>> {
    let ctx = ask.ctx;
    let configs = editor_configs(ctx);
    let editor_detected = configs.iter().any(|path| ctx.absolute(path).exists());
    let cli_detected = cli_available(ask)? || shim_installed(ctx);
    let flagged = |surface: &str| protected.iter().any(|seen| seen == surface);
    let editor_protected =
        flagged("editor") || configs.iter().any(|path| proxies_a_server(ctx, path));
    let cli_protected = flagged("cli") || shim_installed(ctx);
    Ok(vec![
        json!({"surface": "editor", "status": status(editor_detected, editor_protected)}),
        json!({"surface": "cli", "status": status(cli_detected, cli_protected)}),
    ])
}

fn text_list(fields: &Map<String, Value>, key: &str) -> Step<Vec<String>> {
    match fields.get(key) {
        None | Some(Value::Null) => Ok(Vec::new()),
        Some(Value::Array(items)) => items
            .iter()
            .map(|item| item.as_str().map(str::to_owned).ok_or(Failure::Invalid))
            .collect(),
        Some(_) => Err(Failure::Invalid),
    }
}

fn local_action(ask: &Ask) -> Step<Value> {
    let fields = ask.fields;
    let action = fields
        .get("action")
        .and_then(Value::as_str)
        .ok_or(Failure::Invalid)?;
    let surface = named_surface(fields.get("surface"))?;
    let protected = match fields.get("protected") {
        None | Some(Value::Null) => false,
        Some(Value::Bool(protected)) => *protected,
        Some(_) => return Err(Failure::Invalid),
    };
    let protected_surfaces = if protected {
        SURFACES.map(str::to_owned).to_vec()
    } else {
        text_list(fields, "protected_surfaces")?
    };
    let statuses = surface_statuses(ask, &protected_surfaces)?;
    let selected = statuses
        .iter()
        .find(|row| row["surface"] == surface)
        .map(|row| row["status"].clone())
        .ok_or(Failure::Invalid)?;
    let scope = format!("cursor:{surface}:{action}");
    Ok(json!({
        "app_id": "cursor",
        "action": action,
        "surface": surface,
        "status": selected,
        "surface_statuses": statuses,
        "sync": {
            "surface": surface,
            "status": selected,
            "lastSeenAt": null,
            "lastReceiptSyncedAt": null,
            "daemonReachability": "local",
            "protectedLocationId": null,
        },
        "evidence": {
            "receiptId": null,
            "artifactId": scope,
            "actionScope": scope,
            "surface": surface,
            "redactedPath": redacted_path(ask.ctx, surface),
            "policyDecision": "monitor",
        },
    }))
}

pub(super) fn dispatch(op: &str, ask: &Ask) -> Step<Value> {
    let fields = ask.fields;
    match op {
        "install_surface" => match fields.get("surface") {
            None | Some(Value::Null) => Ok(json!({ "surface": "all" })),
            surface => Ok(json!({ "surface": named_surface(surface)? })),
        },
        "protected_surfaces" => {
            let installs = fields
                .get("managed_installs")
                .and_then(Value::as_array)
                .ok_or(Failure::Invalid)?;
            Ok(json!({ "surfaces": protected_surfaces(installs) }))
        }
        "protected_surfaces_from_store" => {
            let installed = fields
                .get("installed")
                .and_then(Value::as_bool)
                .ok_or(Failure::Invalid)?;
            // The caller names the Guard home of the store it holds and the
            // runtime reads Cursor's record itself; a caller that already has
            // the record sends it as `managed`.
            let managed = match fields.get("store_home") {
                Some(Value::String(home)) if installed => {
                    managed_store::managed_install(Path::new(home), "cursor")?
                }
                Some(Value::String(_)) => None,
                None | Some(Value::Null) => fields.get("managed").cloned(),
                Some(_) => return Err(Failure::Invalid),
            };
            let surfaces = match managed {
                _ if !installed => Vec::new(),
                Some(managed) if managed.is_object() => {
                    protected_surfaces(std::slice::from_ref(&managed))
                }
                _ => SURFACES.map(str::to_owned).to_vec(),
            };
            Ok(json!({ "surfaces": surfaces }))
        }
        "local_action" => local_action(ask),
        _ => Err(Failure::Invalid),
    }
}

//! The OpenCode install: every applicable config read and normalized, the
//! native plan for Guard's `permission`, `mcp` and runtime overlay, and the
//! transition files and manifest of the install.
//!
//! Install runs in two steps because Python still owns the proxy argv of
//! each managed server: `install_detection` reads the configs and answers
//! the detection Python derives the servers from, with a digest of the
//! bytes it read; `prepare_install` reads them again, refuses when the
//! digest moved, and plans the files.

use std::path::{Path, PathBuf};

use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};

use super::files::{self, path_value, text, Change, Doc};
use super::opencode::{
    self, config_paths, digest_path, global_plugin, managed_config_path, managed_plugin,
    overlay_path, scope_for, wire_payload,
};
use super::opencode_build::{self, Builder};
use super::{detection, path_text, Ctx, Failure, Spec, Step};
use crate::pyjson::{self, PyVal};

const SCHEMA: &str = "https://opencode.ai/config.json";
const INSTALL_NOTES: [&str; 4] = [
    "Guard installed an OpenCode pretool plugin that reviews bash and shell commands through \
     hol-guard hook before execution.",
    "Guard updated the global OpenCode root config at ~/.config/opencode/opencode.json with \
     baseline bash permission rules and hol-guard:: MCP companion servers, and installed the \
     pretool plugin under ~/.config/opencode/plugins/.",
    "Guard added an OpenCode runtime overlay that keeps managed MCP tools on native ask and \
     routes managed local MCP servers through Guard runtime interception when you launch \
     through Guard.",
    "Use hol-guard:: MCP servers in OpenCode for Guard-proxied tools, or launch through \
     guard-opencode or hol-guard run opencode for pre-launch artifact checks and the runtime \
     skill overlay.",
];

/// One applicable config, normalized with Guard's wrappers taken off.
struct Config {
    path: PathBuf,
    scope: &'static str,
    /// The normalized config as `json.dumps` text.
    text: String,
    value: Vec<(String, PyVal)>,
}

struct Snapshot {
    contents: Vec<(PathBuf, Option<Vec<u8>>)>,
    configs: Vec<Config>,
    digest: String,
}

fn invalid(path: &Path) -> Failure {
    Failure::Refusal(format!(
        "Refusing to install with an invalid OpenCode config at {}. Fix its syntax and retry.",
        path_text(path)
    ))
}

fn unreadable(path: &Path) -> Failure {
    Failure::Refusal(format!(
        "Could not read the OpenCode config at {}.",
        path_text(path)
    ))
}

/// `_normalized_config_payload` through `opencode_config_normalize`.
pub(super) fn normalize(ctx: &Ctx, path: &Path, payload: String, op: Option<&str>) -> Step<Value> {
    let mut request = json!({
        "config": payload,
        "scope": scope_for(ctx, path),
        "config_path": path_text(path),
        "guard_home": path_text(&ctx.guard_home),
        "cwd": ctx.cwd.as_deref().map(path_text).unwrap_or_default(),
    });
    if let Some(op) = op {
        request["op"] = json!(op);
    }
    crate::opencode_config_normalize::dispatch(&request).map_err(|_| unreadable(path))
}

/// `load_opencode_install_snapshot` over the bytes read now.
fn snapshot(ctx: &Ctx) -> Step<Snapshot> {
    let mut contents = Vec::new();
    let mut configs = Vec::new();
    let mut hasher = Sha256::new();
    for path in config_paths(ctx) {
        let raw = files::snapshot(ctx, &path)?;
        hasher.update(path_text(&path).as_bytes());
        hasher.update([0]);
        match &raw {
            Some(bytes) => {
                hasher.update((bytes.len() as u64).to_le_bytes());
                hasher.update(bytes);
            }
            None => hasher.update([0xff]),
        }
        if let Some(bytes) = &raw {
            let source = std::str::from_utf8(bytes).map_err(|_| {
                Failure::Refusal(format!(
                    "Invalid OpenCode config encoding at {}.",
                    path_text(&path)
                ))
            })?;
            let parsed = opencode::load_text(&path, source).ok_or_else(|| invalid(&path))?;
            let answer = normalize(ctx, &path, wire_payload(&parsed), None)?;
            let normalized = match answer.as_object() {
                Some(fields) if fields.len() == 1 => fields.get("config").and_then(Value::as_str),
                _ => None,
            }
            .ok_or_else(|| unreadable(&path))?;
            // A lone surrogate Python would keep cannot be written back here.
            let value = match pyjson::parse_mapping_lone_surrogates(normalized) {
                Ok(parsed) if parsed.mapped => return Err(invalid(&path)),
                Ok(parsed) => match parsed.value {
                    PyVal::Dict(entries) => entries,
                    _ => return Err(unreadable(&path)),
                },
                Err(_) => return Err(unreadable(&path)),
            };
            configs.push(Config {
                scope: scope_for(ctx, &path),
                path: path.clone(),
                text: normalized.to_owned(),
                value,
            });
        }
        contents.push((path, raw));
    }
    Ok(Snapshot {
        contents,
        configs,
        digest: hex::encode(hasher.finalize()),
    })
}

/// `install_detection`: the detection of the normalized configs, verified
/// Guard companions included, and the digest `prepare_install` checks.
pub(super) fn install_detection(spec: &Spec, ctx: &Ctx) -> Step<Value> {
    let snapshot = snapshot(ctx)?;
    let configs: Vec<(PathBuf, &str, String)> = snapshot
        .configs
        .iter()
        .map(|config| (config.path.clone(), config.scope, config.text.clone()))
        .collect();
    let request = opencode::detect_request(ctx, &configs, false);
    let found = crate::opencode_detect::detect(&request);
    let mut answer = detection(spec, found, opencode::command_available(spec, ctx))?;
    answer["firewall"] = json!(true);
    answer["digest"] = json!(snapshot.digest);
    Ok(answer)
}

fn json_field(fields: &Map<String, Value>, key: &str) -> Step<PyVal> {
    let raw = fields
        .get(key)
        .and_then(Value::as_str)
        .ok_or(Failure::Invalid)?;
    pyjson::parse(raw).map_err(|_| Failure::Invalid)
}

/// `_source_entry`: the server's own entry in its source config, as read now.
fn source_entry(ctx: &Ctx, path: &str, name: &str) -> PyVal {
    opencode::read_config(ctx, Path::new(path))
        .filter(|parsed| !parsed.mapped)
        .and_then(|parsed| parsed.value.get("mcp")?.get(name).cloned())
        .filter(|entry| matches!(entry, PyVal::Dict(_)))
        .unwrap_or(PyVal::Null)
}

/// The plan request, in the order Python built it, and each server's launches.
fn plan_request(
    ctx: &Ctx,
    fields: &Map<String, Value>,
    snapshot: &Snapshot,
    target: &[(String, PyVal)],
) -> Step<(PyVal, Vec<[PyVal; 2]>, Vec<String>)> {
    let PyVal::List(servers) = json_field(fields, "servers")? else {
        return Err(Failure::Invalid);
    };
    let mut wire = Vec::new();
    let mut launches = Vec::new();
    let mut names = Vec::new();
    for server in &servers {
        let field = |key: &str| server.get(key).cloned().ok_or(Failure::Invalid);
        let name = server
            .get("name")
            .and_then(PyVal::as_str)
            .ok_or(Failure::Invalid)?;
        let scope = server
            .get("source_scope")
            .and_then(PyVal::as_str)
            .ok_or(Failure::Invalid)?;
        let config_path = server
            .get("config_path")
            .and_then(PyVal::as_str)
            .ok_or(Failure::Invalid)?;
        let source = if scope == "project" {
            PyVal::Null
        } else {
            source_entry(ctx, config_path, name)
        };
        let mut entry = Doc::default();
        entry
            .set("name", text(name))
            .set("source_scope", text(scope))
            .set("command", field("command")?)
            .set("args", field("args")?)
            .set("env", field("env")?)
            .set("enabled", field("enabled")?)
            .set("proxy_environment", field("proxy_environment")?)
            .set("source", source);
        wire.push(entry.value());
        let pair = server
            .get("launches")
            .and_then(PyVal::as_list)
            .ok_or(Failure::Invalid)?;
        let [companion, over] = pair else {
            return Err(Failure::Invalid);
        };
        launches.push([companion.clone(), over.clone()]);
        names.push(name.to_owned());
    }
    let mut workspace_servers: Vec<String> = snapshot
        .configs
        .iter()
        .filter(|config| config.scope == "project")
        .filter_map(|config| config.value.iter().find(|(key, _)| key == "mcp"))
        .filter_map(|(_, mcp)| mcp.as_dict())
        .flat_map(|mcp| {
            mcp.iter()
                .filter(|(_, entry)| matches!(entry, PyVal::Dict(_)))
                .map(|(name, _)| name.clone())
        })
        .collect();
    workspace_servers.sort();
    workspace_servers.dedup();
    let current = |key: &str| {
        target
            .iter()
            .find(|(name, _)| name == key)
            .map_or(PyVal::Null, |(_, value)| value.clone())
    };
    let mcp = current("mcp");
    let mcp_keys = mcp
        .as_dict()
        .map(|entries| entries.iter().map(|(key, _)| text(key.as_str())).collect())
        .unwrap_or_default();
    let mut request = Doc::default();
    request
        .set("op", text("plan"))
        .set("workspace", PyVal::Bool(ctx.workspace.is_some()))
        .set("servers", PyVal::List(wire))
        .set("skipped", json_field(fields, "skipped")?)
        .set("artifacts", json_field(fields, "artifacts")?)
        .set(
            "workspace_servers",
            PyVal::List(workspace_servers.into_iter().map(text).collect()),
        )
        .set("permission", current("permission"))
        .set("mcp", mcp)
        .set("mcp_keys", PyVal::List(mcp_keys));
    Ok((request.value(), launches, names))
}

/// `json.dumps(payload, indent=2) + "\n"`.
fn json_bytes(value: &PyVal) -> Step<Vec<u8>> {
    Ok(format!("{}\n", files::render(value)?).into_bytes())
}

/// Insert as a dict assignment does: a repeated path keeps its place.
fn assign(after: &mut Vec<(PathBuf, Option<Vec<u8>>)>, path: PathBuf, bytes: Option<Vec<u8>>) {
    match after.iter_mut().find(|(known, _)| *known == path) {
        Some(entry) => entry.1 = bytes,
        None => after.push((path, bytes)),
    }
}

/// `prepare_install`: the transition files and manifest of the install.
pub(super) fn prepare_install(ctx: &Ctx, fields: &Map<String, Value>) -> Step<Value> {
    let snapshot = snapshot(ctx)?;
    if fields.get("digest").and_then(Value::as_str) != Some(snapshot.digest.as_str()) {
        return Err(Failure::Integrity("target_changed"));
    }
    let shim = files::shim_manifest(fields)?;
    let target = managed_config_path(ctx);
    let mut payload = snapshot
        .configs
        .iter()
        .find(|config| config.path == target)
        .map(|config| config.value.clone())
        .unwrap_or_default();
    let (request, launches, names) = plan_request(ctx, fields, &snapshot, &payload)?;
    let answer = request.to_json().ok_or(Failure::Invalid).and_then(|wire| {
        crate::opencode_install_plan::dispatch(&wire).map_err(|_| Failure::Invalid)
    })?;
    let answer = answer.as_object().ok_or(Failure::Invalid)?;
    let keys = ["managed", "skipped", "permission", "mcp", "overlay"];
    if answer.len() != keys.len() || !keys.iter().all(|key| answer.contains_key(*key)) {
        return Err(Failure::Refusal(
            "the native OpenCode install plan was malformed: the answer keys are wrong".into(),
        ));
    }
    let builder = Builder {
        request: &request,
        launches: &launches,
    };
    let managed = opencode_build::managed(&answer["managed"], names.len())?;
    let skipped = opencode_build::strings(&answer["skipped"], "skipped")?;
    let permission = builder.object(&answer["permission"])?;
    let mcp = builder.object(&answer["mcp"])?;
    let overlay = PyVal::Dict(builder.object(&answer["overlay"])?);

    let mut doc = Doc(std::mem::take(&mut payload));
    if doc.0.iter().all(|(key, _)| key != "$schema") {
        doc.set("$schema", text(SCHEMA));
    }
    doc.set("permission", PyVal::Dict(permission))
        .set("mcp", PyVal::Dict(mcp));
    let target_payload = doc.value();

    let content = |path: &Path| {
        snapshot
            .contents
            .iter()
            .find(|(known, _)| known == path)
            .map(|(_, bytes)| bytes.clone())
    };
    let original = content(&target).flatten();
    let backup = digest_path(ctx, &target, "backup");
    let state_path = digest_path(ctx, &target, "state");
    let mut state = Doc::default();
    state
        .set("managed_config_path", path_value(&target))
        .set("backup_path", path_value(&backup))
        .set(
            "scope",
            text(if ctx.workspace.is_some() {
                "workspace"
            } else {
                "global"
            }),
        )
        .set(
            "workspace_dir",
            ctx.workspace.as_deref().map_or(PyVal::Null, |workspace| {
                path_value(&ctx.resolved(workspace))
            }),
        );
    let plugin = fields.get("plugin").ok_or(Failure::Invalid)?;
    let source = crate::opencode_plugin_render::render(plugin)
        .map_err(|error| {
            Failure::Refusal(format!(
                "Guard could not render the OpenCode plugin: {error}"
            ))
        })?
        .get("source")
        .and_then(Value::as_str)
        .map(|source| source.as_bytes().to_vec())
        .ok_or_else(|| Failure::Refusal("Guard could not render the OpenCode plugin.".into()))?;

    let backup_before = files::snapshot(ctx, &backup)?;
    let backup_after = match &backup_before {
        Some(bytes) => bytes.clone(),
        None => {
            let original_text = original
                .as_deref()
                .map(|bytes| String::from_utf8_lossy(bytes).into_owned());
            let mut envelope = Doc::default();
            envelope
                .set("existed", PyVal::Bool(original_text.is_some()))
                .set("content", original_text.map_or(PyVal::Null, text));
            json_bytes(&envelope.value())?
        }
    };
    let managed_plugin = managed_plugin(ctx);
    let global_plugin = global_plugin(ctx);
    let mut after: Vec<(PathBuf, Option<Vec<u8>>)> = Vec::new();
    assign(
        &mut after,
        state_path.clone(),
        Some(json_bytes(&state.value())?),
    );
    assign(
        &mut after,
        target.clone(),
        Some(json_bytes(&target_payload)?),
    );
    assign(&mut after, overlay_path(ctx), Some(json_bytes(&overlay)?));
    assign(&mut after, backup.clone(), Some(backup_after));
    assign(&mut after, managed_plugin.clone(), Some(source.clone()));
    assign(&mut after, global_plugin.clone(), Some(source));
    for (path, bytes) in &snapshot.contents {
        if after.iter().all(|(known, _)| known != path) {
            after.push((path.clone(), bytes.clone()));
        }
    }
    let mut changes = Vec::with_capacity(after.len());
    for (path, bytes) in after {
        let config = content(&path);
        let before = match (&config, path == backup) {
            (Some(before), _) => before.clone(),
            (None, true) => backup_before.clone(),
            (None, false) => files::snapshot(ctx, &path)?,
        };
        let before_mode = match before {
            Some(_) => files::mode(ctx, &path).ok_or(Failure::Integrity("target_changed"))?,
            None => 0o600,
        };
        let mut after_mode = if config.is_some() && path != target {
            before_mode
        } else {
            0o600
        };
        if path == managed_plugin || path == global_plugin {
            after_mode = if before.is_some() { before_mode } else { 0o644 };
        }
        if path == backup && backup_before.is_some() {
            after_mode = before_mode;
        }
        let mut change = Change::at(ctx, &path, before, bytes, before_mode);
        change.after_mode = after_mode;
        changes.push(change.wire());
    }

    let mut notes = files::shim_notes(&shim);
    notes.extend(INSTALL_NOTES.iter().map(|note| text(*note)));
    let listed = |key: &str| json_field(fields, key);
    let mut manifest = Doc::default();
    manifest
        .set("harness", text("opencode"))
        .set("active", PyVal::Bool(true))
        .set("config_path", path_value(&target))
        .spread(&shim)
        .set("managed_plugin_path", path_value(&managed_plugin))
        .set("global_plugin_path", path_value(&global_plugin))
        .set("managed_config_path", path_value(&target))
        .set("backup_path", path_value(&backup))
        .set("state_path", path_value(&state_path))
        .set("runtime_config_path", path_value(&overlay_path(ctx)))
        .set("runtime_env_var", text(opencode::RUNTIME_ENV_VAR))
        .set(
            "managed_servers",
            PyVal::List(
                managed
                    .iter()
                    .map(|index| text(names[*index].as_str()))
                    .collect(),
            ),
        )
        .set(
            "skipped_servers",
            PyVal::List(skipped.into_iter().map(text).collect()),
        )
        .set("source_config_paths", listed("source_config_paths")?)
        .set("notes", PyVal::List(notes));
    Ok(json!({ "files": changes, "manifest": files::render(&manifest.value())? }))
}

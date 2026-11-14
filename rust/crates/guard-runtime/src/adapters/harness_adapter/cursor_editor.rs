//! The Cursor editor surface: Guard's MCP proxies in the global `mcp.json`
//! with a restorable backup and the origins state, Guard's hooks beside them,
//! the combined manifests and the stale-hook rebind.
//!
//! Every op here plans without writing until each reply Python owes has been
//! answered, so a reply never repeats a write. Python publishes the planned
//! files; the direct install creates the attestation key first and verifies
//! the published hooks after.

use std::path::{Path, PathBuf};

use serde_json::{json, Map, Value};

use super::copilot_install::rendered;
use super::cursor::{self, get, runtime, wire, Ask, Captured, Facts, HARNESS};
use super::cursor_files::{ensure_secret, restore, unlink_file};
use super::cursor_hooks_plan::{self as plan, backup_document, no_follow, Prepared};
use super::cursor_hooks_uninstall;
use super::files::{self, within_root, Change, Doc};
use super::{path_text, Failure, Spec, Step};
use crate::pyjson::{self, PyVal};

const UNINSTALL_NOTES: [&str; 2] = [
    "Removed Guard Cursor editor MCP proxies and restored the prior Cursor config.",
    "Removed Guard native Cursor hooks when a managed hooks backup was available.",
];

/// A managed server: name, source scope, config path and Guard's proxy entry.
type Managed = (String, String, String, PyVal);

/// The servers Python derived from a detection.
struct Servers {
    managed: Vec<Managed>,
    skipped: PyVal,
    observed: Vec<[String; 3]>,
}

fn servers(ask: &Ask, detected: &Value) -> Step<Servers> {
    ask.servers(detected)?;
    let raw = ask
        .fields
        .get("servers")
        .and_then(Value::as_str)
        .ok_or(Failure::Invalid)?;
    let parsed = cursor::parse_object(raw).ok_or(Failure::Invalid)?;
    let list = |key: &str| {
        get(&parsed, key)
            .and_then(PyVal::as_list)
            .ok_or(Failure::Invalid)
    };
    let managed = list("managed")?
        .iter()
        .map(|row| match row.as_list() {
            Some(
                [PyVal::Str(name), PyVal::Str(scope), PyVal::Str(path), entry @ PyVal::Dict(_)],
            ) => Ok((name.clone(), scope.clone(), path.clone(), entry.clone())),
            _ => Err(Failure::Invalid),
        })
        .collect::<Step<_>>()?;
    let observed = list("observed")?
        .iter()
        .map(|row| match row.as_list() {
            Some([PyVal::Str(name), PyVal::Str(scope), PyVal::Str(path)]) => {
                Ok([name.clone(), scope.clone(), path.clone()])
            }
            _ => Err(Failure::Invalid),
        })
        .collect::<Step<_>>()?;
    Ok(Servers {
        managed,
        skipped: PyVal::List(list("skipped")?.to_vec()),
        observed,
    })
}

/// The `cursor_editor_plan` answer: the state origins, the proxies to
/// refresh and the install notes.
struct Plan {
    origins: Vec<(String, PyVal)>,
    refresh: Vec<usize>,
    notes: Vec<PyVal>,
}

fn launch_fields(config: &PyVal) -> Step<Value> {
    let PyVal::Dict(entries) = config else {
        return Ok(Value::Null);
    };
    let mut kept = Map::new();
    for key in ["command", "args"] {
        if let Some(value) = get(entries, key) {
            kept.insert(key.into(), wire(value)?);
        }
    }
    Ok(Value::Object(kept))
}

fn editor_plan(
    ask: &Ask,
    found: &Servers,
    state: &Path,
    payload: &[(String, PyVal)],
) -> Step<Plan> {
    let previous = cursor::read_object(ask.ctx, state).unwrap_or_default();
    let previous = match get(&previous, "managed_origins") {
        Some(PyVal::Dict(origins)) => origins
            .iter()
            .map(|(name, value)| Ok(json!([name, wire(value)?])))
            .collect::<Step<Vec<_>>>()
            .map(Value::Array)?,
        _ => Value::Null,
    };
    let configs = match get(payload, "mcpServers") {
        Some(PyVal::Dict(servers)) => servers
            .iter()
            .map(|(_, config)| launch_fields(config))
            .collect::<Step<Vec<_>>>()
            .map(Value::Array)?,
        _ => Value::Null,
    };
    let managed: Vec<Value> = found
        .managed
        .iter()
        .map(|(name, scope, path, _)| json!([name, scope, path]))
        .collect();
    let answer = crate::cursor_editor_plan::plan(&json!({
        "previous_origins": previous,
        "observed": found.observed,
        "managed": managed,
        "servers": configs,
        "workspace": ask.ctx.workspace.is_some(),
    }))
    .map_err(|_| Failure::Refusal("Cursor editor plan answer is malformed".into()))?;
    let origins = answer["origins"]
        .as_array()
        .ok_or(Failure::Invalid)?
        .iter()
        .map(|row| {
            let name = row[0].as_str().ok_or(Failure::Invalid)?.to_owned();
            let value = pyjson::parse(&row[1].to_string()).map_err(|_| Failure::Invalid)?;
            Ok((name, value))
        })
        .collect::<Step<_>>()?;
    let refresh = answer["refresh"]
        .as_array()
        .ok_or(Failure::Invalid)?
        .iter()
        .map(|index| {
            index
                .as_u64()
                .map(|index| index as usize)
                .ok_or(Failure::Invalid)
        })
        .collect::<Step<_>>()?;
    let notes = answer["notes"]
        .as_array()
        .ok_or(Failure::Invalid)?
        .iter()
        .map(|note| note.as_str().map(files::text).ok_or(Failure::Invalid))
        .collect::<Step<_>>()?;
    Ok(Plan {
        origins,
        refresh,
        notes,
    })
}

/// `_apply_editor_servers`: refresh Guard's existing proxies, then point each
/// managed server at Guard's proxy.
fn apply_servers(ask: &Ask, payload: &mut Doc, refresh: &[usize], managed: &[Managed]) -> Step<()> {
    let mut normalized = match get(&payload.0, "mcpServers") {
        Some(PyVal::Dict(servers)) => Doc(servers.clone()),
        _ => Doc::default(),
    };
    let args_of = |index: usize| -> Vec<String> {
        match normalized.0.get(index).map(|(_, config)| config) {
            Some(PyVal::Dict(config)) => match get(config, "args") {
                Some(PyVal::List(args)) => args
                    .iter()
                    .filter_map(|arg| arg.as_str().map(str::to_owned))
                    .collect(),
                _ => Vec::new(),
            },
            _ => Vec::new(),
        }
    };
    let sets: Vec<Vec<String>> = refresh.iter().map(|index| args_of(*index)).collect();
    let launches = ask.relaunch(&sets)?;
    for (index, (command, args)) in refresh.iter().zip(launches) {
        let (name, PyVal::Dict(config)) =
            normalized.0.get(*index).cloned().ok_or(Failure::Invalid)?
        else {
            return Err(Failure::Invalid);
        };
        let mut refreshed = Doc(config);
        refreshed.set("command", files::text(command)).set(
            "args",
            PyVal::List(args.into_iter().map(files::text).collect()),
        );
        normalized.set(&name, refreshed.value());
    }
    for (name, _, _, entry) in managed {
        normalized.set(name, entry.clone());
    }
    payload.set("mcpServers", normalized.value());
    Ok(())
}

fn editor_paths(ask: &Ask) -> Step<(PathBuf, PathBuf, PathBuf)> {
    let ctx = ask.ctx;
    let target = cursor::editor_target(ctx);
    let backup = cursor::digest_path(ctx, &target, "", "backup");
    let state = cursor::digest_path(ctx, &target, "", "state");
    Ok((target, backup, state))
}

fn editor_state(ask: &Ask, target: &Path, backup: &Path, origins: Vec<(String, PyVal)>) -> Doc {
    let ctx = ask.ctx;
    let workspace = ctx.workspace.as_deref().map_or(PyVal::Null, |workspace| {
        files::path_value(&ctx.resolved(workspace))
    });
    let mut state = Doc::default();
    state
        .set("managed_config_path", files::path_value(target))
        .set("backup_path", files::path_value(backup))
        .set("surface", files::text("editor"))
        .set("workspace_dir", workspace)
        .set("managed_origins", PyVal::Dict(origins));
    state
}

fn hook_field(hooks: &Doc, key: &str) -> PyVal {
    get(&hooks.0, key).cloned().unwrap_or(PyVal::Null)
}

/// `_prepare_editor`: the editor config, its state and backup, and the hooks.
fn prepare_editor(spec: &Spec, ask: &Ask, facts: &Facts) -> Step<Result<Prepared, &'static str>> {
    let ctx = ask.ctx;
    let (target, backup, state) = editor_paths(ask)?;
    within_root(ctx, &ctx.home, &target, "Cursor editor")?;
    within_root(ctx, &ctx.guard_home, &backup, "Cursor lifecycle")?;
    within_root(ctx, &ctx.guard_home, &state, "Cursor lifecycle")?;
    let mut paths = cursor::editor_configs(ctx);
    paths.extend([cursor::hooks_path(ctx), backup.clone(), state.clone()]);
    let contents: Vec<(PathBuf, Option<Vec<u8>>)> = paths
        .into_iter()
        .map(|path| files::snapshot(ctx, &path).map(|data| (path, data)))
        .collect::<Step<_>>()?;
    let captured = |path: &Path| {
        contents
            .iter()
            .find(|(known, _)| known == path)
            .and_then(|(_, data)| data.clone())
    };
    let original = captured(&target);
    let mut payload = match &original {
        None => Doc::default(),
        Some(bytes) => {
            let unreadable = || {
                Failure::Refusal(format!(
                    "Guard refused to overwrite unreadable Cursor editor config at {}",
                    path_text(&target)
                ))
            };
            let text = std::str::from_utf8(bytes).map_err(|_| unreadable())?;
            match pyjson::parse(text).map_err(|_| unreadable())? {
                PyVal::Dict(entries) => Doc(entries),
                _ => {
                    return Err(runtime(format!(
                        "Guard refused to overwrite non-object Cursor editor config at {}",
                        path_text(&target)
                    )))
                }
            }
        }
    };
    let detected = cursor::detect(spec, ask, Some(contents.as_slice() as &Captured))?;
    let found = servers(ask, &detected)?;
    let planned = editor_plan(ask, &found, &state, &payload.0)?;
    apply_servers(ask, &mut payload, &planned.refresh, &found.managed)?;
    let hooks = match plan::prepare(ask, facts)? {
        Ok(hooks) => hooks,
        Err(reason) => return Ok(Err(reason)),
    };
    let mut changes = hooks.files;
    let state_doc = editor_state(ask, &target, &backup, planned.origins);
    let backup_after = match captured(&backup) {
        Some(existing) => existing,
        None => {
            let text = original
                .as_ref()
                .map(|bytes| String::from_utf8_lossy(bytes).into_owned());
            backup_document(text.as_deref())?
        }
    };
    let mut after: Vec<(PathBuf, Option<Vec<u8>>)> = vec![
        (target.clone(), Some(rendered(&payload.value())?)),
        (state.clone(), Some(rendered(&state_doc.value())?)),
        (backup.clone(), Some(backup_after)),
    ];
    for path in cursor::editor_configs(ctx) {
        if !after.iter().any(|(known, _)| *known == path) {
            let data = captured(&path);
            after.push((path, data));
        }
    }
    for (path, data) in after {
        let before = captured(&path);
        let mode = if before.is_some() {
            files::mode(ctx, &path).unwrap_or(0o600)
        } else {
            0o600
        };
        changes.push(no_follow(ctx, &path, before, data, (mode, mode)));
    }
    let mut manifest = Doc::default();
    manifest
        .set("harness", files::text(HARNESS))
        .set("active", PyVal::Bool(true))
        .set("surface", files::text("editor"))
        .set("managed_config_path", files::path_value(&target))
        .set("backup_path", files::path_value(&backup))
        .set("state_path", files::path_value(&state))
        .set(
            "managed_servers",
            PyVal::List(
                found
                    .managed
                    .iter()
                    .map(|server| files::text(server.0.clone()))
                    .collect(),
            ),
        )
        .set("skipped_servers", found.skipped)
        .set(
            "managed_hooks_path",
            hook_field(&hooks.manifest, "managed_hooks_path"),
        )
        .set(
            "managed_hook_script_path",
            hook_field(&hooks.manifest, "managed_hook_script_path"),
        )
        .set(
            "guard_cli_identity",
            hook_field(&hooks.manifest, "guard_cli_identity"),
        )
        .set(
            "hook_script_sha256",
            hook_field(&hooks.manifest, "hook_script_sha256"),
        )
        .set("notes", PyVal::List(planned.notes));
    Ok(Ok(Prepared {
        secret: hooks.secret,
        files: changes,
        manifest,
    }))
}

fn prepared_answer(prepared: Result<Prepared, &'static str>) -> Step<Value> {
    match prepared {
        Err(reason) => Ok(json!({ "transition_error": reason })),
        Ok(prepared) => Ok(json!({
            "files": prepared.files.iter().map(Change::wire).collect::<Vec<_>>(),
            "manifest": files::render(&prepared.manifest.value())?,
            "identity": [path_text(&prepared.secret)],
        })),
    }
}

/// A direct install keeps or makes the attestation key before it plans.
fn ensure_authority(ask: &Ask, facts: &Facts) -> Step<()> {
    facts.require_bridge()?;
    facts.attestation()?;
    ensure_secret(ask.ctx, &cursor::secret_path(ask.ctx))
}

/// `_uninstall_editor`: Guard's hooks first, since they may still ask Python
/// for a reply, then the editor config's restore.
fn uninstall(ask: &Ask) -> Step<Value> {
    let ctx = ask.ctx;
    let (target, backup, state) = editor_paths(ask)?;
    within_root(ctx, &ctx.home, &target, "Cursor editor")?;
    within_root(ctx, &ctx.guard_home, &backup, "Cursor backup")?;
    within_root(ctx, &ctx.guard_home, &state, "Cursor state")?;
    let hooks = cursor_hooks_uninstall::uninstall(ask)?;
    let restored = restore(ctx, &backup, &target, "The Cursor editor backup")?;
    if restored {
        unlink_file(ctx, &backup)?;
        unlink_file(ctx, &state)?;
    }
    let mut doc = Doc::default();
    doc.set("harness", files::text(HARNESS))
        .set("active", PyVal::Bool(false))
        .set("surface", files::text("editor"))
        .set("managed_config_path", files::path_value(&target))
        .set("backup_path", files::path_value(&backup))
        .set("state_path", files::path_value(&state))
        .set("restored", PyVal::Bool(restored))
        .set(
            "managed_hooks_path",
            hook_field(&hooks, "managed_hooks_path"),
        )
        .set(
            "notes",
            PyVal::List(
                UNINSTALL_NOTES
                    .iter()
                    .map(|note| files::text(*note))
                    .collect(),
            ),
        );
    files::manifest_answer(doc)
}

pub(super) fn dispatch(spec: &Spec, op: &str, ask: &Ask) -> Step<Value> {
    match op {
        "prepare_install" => prepared_answer(prepare_editor(spec, ask, &ask.facts()?)?),
        "install" => {
            let facts = ask.facts()?;
            ensure_authority(ask, &facts)?;
            prepared_answer(prepare_editor(spec, ask, &facts)?)
        }
        "hooks_install" => {
            let facts = ask.facts()?;
            ensure_authority(ask, &facts)?;
            prepared_answer(plan::prepare(ask, &facts)?)
        }
        "verify" => plan::verify(ask).map(|()| json!({})),
        "uninstall" => uninstall(ask),
        _ => Err(Failure::Invalid),
    }
}

/// The combined `all` surface manifest over the editor and CLI manifests.
pub(super) fn all_manifest(fields: &Map<String, Value>) -> Step<Value> {
    let parsed = |key: &str| {
        let raw = fields
            .get(key)
            .and_then(Value::as_str)
            .ok_or(Failure::Invalid)?;
        cursor::parse_object(raw).ok_or(Failure::Invalid)
    };
    let active = fields
        .get("active")
        .and_then(Value::as_bool)
        .ok_or(Failure::Invalid)?;
    let (editor, cli) = (parsed("editor")?, parsed("cli")?);
    let field = |manifest: &[(String, PyVal)], key: &str| {
        get(manifest, key).cloned().unwrap_or(PyVal::Null)
    };
    let mut doc = Doc::default();
    doc.set("harness", files::text(HARNESS))
        .set("active", PyVal::Bool(active))
        .set("surface", files::text("all"))
        .set(
            "surfaces",
            PyVal::List(vec![files::text("editor"), files::text("cli")]),
        )
        .set("editor", PyVal::Dict(editor.clone()))
        .set("cli", PyVal::Dict(cli.clone()));
    for key in ["managed_config_path", "backup_path", "state_path"] {
        doc.set(key, field(&editor, key));
    }
    if active {
        doc.set("guard_cli_identity", field(&editor, "guard_cli_identity"))
            .set("hook_script_sha256", field(&editor, "hook_script_sha256"))
            .set("shim_path", field(&cli, "shim_path"))
            .set("shim_command", field(&cli, "shim_command"));
    } else {
        doc.set("shim_path", field(&cli, "shim_path"))
            .set("removed", field(&cli, "removed"))
            .set("restored", field(&editor, "restored"));
    }
    files::manifest_answer(doc)
}

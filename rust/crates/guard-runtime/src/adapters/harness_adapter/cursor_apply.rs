//! Cursor's `install` and `uninstall` over every surface, in one native call
//! each, as `CursorHarnessAdapter.install` and `.uninstall` ran them from
//! Python: the editor hooks published with their removals and verified, the
//! two CLI launchers with the shell profile's PATH block, and the combined
//! manifest when both surfaces change.
//!
//! `prepare_surfaces` plans the same surfaces without a write: the editor's
//! plan and attestation key, both launchers and the PATH block, and the
//! manifest the install would record.
//!
//! An install answers `manifest`, the last `publish` answer and each earlier
//! one under `published`, in order; the caller journals and checks each. A
//! failure after a publish succeeded comes back under `failure`, so the
//! caller still journals what was written before it raises.

use serde_json::{json, Map, Value};

use super::files::render;
use super::{answer, guard_shim, route, shim_profile, shim_remove, shims_apply};
use super::{Ctx, Failure, Spec, Step};
use crate::pyjson::PyVal;

/// The `cursor-agent` launcher and the `cursor agent` one.
const SHIMS: [(&str, &str); 2] = [
    ("cursor-agent", "Cursor CLI (cursor-agent)"),
    ("cursor", "Cursor CLI (cursor agent)"),
];
/// The launcher an uninstall removes, with the older name it also removes.
const CLI_LAUNCHER: &str = "cursor-agent";
const CLI_LABEL: &str = "Cursor CLI";
const LEGACY_LAUNCHERS: [&str; 1] = ["cursor"];

fn selected(spec: &Spec, ctx: &Ctx, fields: &Map<String, Value>) -> Step<String> {
    let mut asked = Map::new();
    asked.insert(
        "surface".into(),
        fields
            .get("surface")
            .cloned()
            .unwrap_or_else(|| json!("editor")),
    );
    route(spec, "surface", ctx, &asked)?
        .get("surface")
        .and_then(Value::as_str)
        .map(str::to_owned)
        .ok_or(Failure::Invalid)
}

fn ok(publish: &Value) -> bool {
    publish.get("ok") == Some(&Value::Bool(true))
}

fn text(answer: &Value, key: &str) -> Step<String> {
    answer
        .get(key)
        .and_then(Value::as_str)
        .map(str::to_owned)
        .ok_or(Failure::Invalid)
}

/// The failure an op stopped with, as the one-key answer Python raises.
fn failure(step: Failure) -> Step<Value> {
    answer(Err(step)).map_err(|_| Failure::Invalid)
}

fn stopped(published: Vec<Value>, publish: Value, failed: Value) -> Value {
    json!({
        "manifest": null,
        "publish": publish,
        "published": published,
        "failure": failed,
    })
}

/// `install(context, surface=...)`.
pub(super) fn install(spec: &Spec, ctx: &Ctx, fields: &Map<String, Value>) -> Step<Value> {
    let surface = selected(spec, ctx, fields)?;
    let mut published: Vec<Value> = Vec::new();
    let mut editor = None;
    if surface != "cli" {
        let mut plan = Map::new();
        plan.insert("plan_op".into(), json!("install"));
        plan.insert("removals".into(), json!(true));
        plan.insert(
            "transition".into(),
            fields.get("transition").cloned().unwrap_or(Value::Null),
        );
        let applied = shims_apply::apply_plan(spec, ctx, &plan)?;
        let publish = applied.get("publish").cloned().ok_or(Failure::Invalid)?;
        if !ok(&publish) {
            return Ok(stopped(published, publish, Value::Null));
        }
        if let Err(step) = route(spec, "verify", ctx, &Map::new()) {
            return Ok(stopped(published, publish, failure(step)?));
        }
        editor = Some(text(&applied, "manifest")?);
        if surface == "editor" {
            return Ok(json!({
                "manifest": editor,
                "publish": publish,
                "published": published,
                "failure": null,
            }));
        }
        published.push(publish);
    }
    let shims: Vec<Value> = SHIMS
        .iter()
        .map(|(launcher, label)| {
            json!({"harness": spec.harness, "launcher_name": launcher, "display_name": label})
        })
        .collect();
    let mut asked = Map::new();
    asked.insert("shims".into(), Value::Array(shims));
    for key in ["interpreter", "transition"] {
        asked.insert(key.into(), fields.get(key).cloned().unwrap_or(Value::Null));
    }
    asked.insert(
        "profile".into(),
        fields.get("shell_profile").cloned().unwrap_or(Value::Null),
    );
    let applied = shims_apply::apply_guard_shims(ctx, &asked)?;
    let publish = applied.get("publish").cloned().ok_or(Failure::Invalid)?;
    if !ok(&publish) {
        return Ok(stopped(published, publish, Value::Null));
    }
    let manifests = applied
        .get("shims")
        .and_then(Value::as_array)
        .filter(|manifests| manifests.len() == SHIMS.len())
        .ok_or(Failure::Invalid)?;
    let profile = match applied.get("profile") {
        Some(Value::String(profile)) => profile.clone(),
        Some(profile @ Value::Object(_)) => {
            serde_json::to_string(profile).map_err(|_| Failure::Invalid)?
        }
        _ => return Err(Failure::Invalid),
    };
    let mut cli_fields = Map::new();
    cli_fields.insert("agent_shim".into(), manifests[0].clone());
    cli_fields.insert("cursor_shim".into(), manifests[1].clone());
    cli_fields.insert("profile".into(), json!(profile));
    let cli = text(&route(spec, "cli_manifest", ctx, &cli_fields)?, "manifest")?;
    let manifest = match editor {
        None => cli,
        Some(editor) => combined(spec, ctx, &editor, &cli, true)?,
    };
    Ok(json!({
        "manifest": manifest,
        "publish": publish,
        "published": published,
        "failure": null,
    }))
}

fn combined(spec: &Spec, ctx: &Ctx, editor: &str, cli: &str, active: bool) -> Step<String> {
    let mut asked = Map::new();
    asked.insert("editor".into(), json!(editor));
    asked.insert("cli".into(), json!(cli));
    asked.insert("active".into(), json!(active));
    text(&route(spec, "all_manifest", ctx, &asked)?, "manifest")
}

/// `uninstall(context, surface=...)`: the CLI launchers first, then the
/// editor hooks, which the runtime removes as it plans them.
pub(super) fn uninstall(spec: &Spec, ctx: &Ctx, fields: &Map<String, Value>) -> Step<Value> {
    let surface = selected(spec, ctx, fields)?;
    let editor = |ctx: &Ctx| -> Step<String> {
        text(&route(spec, "uninstall", ctx, &Map::new())?, "manifest")
    };
    if surface == "editor" {
        return Ok(json!({ "manifest": editor(ctx)? }));
    }
    let (shim, _) = shim_remove::remove_named(ctx, CLI_LAUNCHER, CLI_LABEL, &LEGACY_LAUNCHERS)?;
    let mut asked = Map::new();
    asked.insert("shim".into(), json!(render(&PyVal::Dict(shim))?));
    let cli = text(&route(spec, "cli_uninstalled", ctx, &asked)?, "manifest")?;
    if surface == "cli" {
        return Ok(json!({ "manifest": cli }));
    }
    let editor = editor(ctx)?;
    Ok(json!({ "manifest": combined(spec, ctx, &editor, &cli, false)? }))
}

fn files(answer: &Value) -> Step<Vec<Value>> {
    answer
        .get("files")
        .and_then(Value::as_array)
        .cloned()
        .ok_or(Failure::Invalid)
}

/// A manifest as the JSON text the manifest ops read.
fn manifest_text(answer: &Value) -> Step<String> {
    match answer.get("manifest") {
        Some(Value::String(text)) => Ok(text.clone()),
        Some(manifest @ Value::Object(_)) => {
            serde_json::to_string(manifest).map_err(|_| Failure::Invalid)
        }
        _ => Err(Failure::Invalid),
    }
}

/// `_prepare_cli`: both launchers and the PATH block, planned.
fn prepare_cli(spec: &Spec, ctx: &Ctx, fields: &Map<String, Value>) -> Step<Value> {
    let mut planned = Vec::new();
    let mut manifests = Vec::new();
    for (launcher, label) in SHIMS {
        let mut asked = Map::new();
        asked.insert("harness".into(), json!(spec.harness));
        asked.insert("launcher_name".into(), json!(launcher));
        asked.insert("display_name".into(), json!(label));
        asked.insert(
            "interpreter".into(),
            fields.get("interpreter").cloned().unwrap_or(Value::Null),
        );
        let shim = guard_shim::prepare(ctx, &asked)?;
        planned.extend(files(&shim)?);
        manifests.push(manifest_text(&shim)?);
    }
    let shell = fields
        .get("shell_profile")
        .and_then(Value::as_object)
        .cloned()
        .unwrap_or_default();
    let profile = shim_profile::prepare(ctx, &shell)?;
    planned.extend(files(&profile)?);
    let mut cli_fields = Map::new();
    cli_fields.insert("agent_shim".into(), json!(manifests[0]));
    cli_fields.insert("cursor_shim".into(), json!(manifests[1]));
    cli_fields.insert("profile".into(), json!(manifest_text(&profile)?));
    let manifest = text(&route(spec, "cli_manifest", ctx, &cli_fields)?, "manifest")?;
    Ok(json!({ "files": planned, "manifest": manifest, "identity": [] }))
}

/// `prepare_install(context, surface=...)`.
pub(super) fn prepare(spec: &Spec, ctx: &Ctx, fields: &Map<String, Value>) -> Step<Value> {
    let surface = selected(spec, ctx, fields)?;
    if surface == "cli" {
        return prepare_cli(spec, ctx, fields);
    }
    let editor = route(spec, "prepare_install", ctx, &Map::new())?;
    if surface == "editor" || editor.get("transition_error").is_some() {
        return Ok(editor);
    }
    let cli = prepare_cli(spec, ctx, fields)?;
    let mut planned = files(&editor)?;
    planned.extend(files(&cli)?);
    let manifest = combined(
        spec,
        ctx,
        &text(&editor, "manifest")?,
        &text(&cli, "manifest")?,
        true,
    )?;
    Ok(json!({
        "files": planned,
        "manifest": manifest,
        "identity": editor.get("identity").cloned().unwrap_or_else(|| json!([])),
    }))
}

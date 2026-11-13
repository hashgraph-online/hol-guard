//! Pi and Oh My Pi: a managed `hol-guard.ts` extension in the agent directory
//! (`~/.pi/agent` or `~/.omp/agent`) that `settings.json` lists under
//! `extensions`. This module picks the paths, detects, and plans the install
//! and uninstall; `pi_extension` renders the extension and reads it back.

use std::path::{Path, PathBuf};

use serde_json::{json, Map, Value};

use super::files::{self, adapter_result, render, text, Change};
use super::kimi::{expand_user, utf8};
use super::openclaw::truthy;
use super::pi_extension::{code_mode_warnings, pinned_core, render_source, Runtime};
use super::{detection, path_answer, path_text, which, Ctx, Failure, Spec, Step};
use crate::pyjson::{self, PyVal};

const SETTINGS_FILE: &str = "settings.json";
const EXTENSION_NAME: &str = "hol-guard.ts";
const REMOTE_PREFIXES: [&str; 5] = ["npm:", "git:", "http://", "https://", "ssh://"];
const LEGACY_OMP_NOTE: &str =
    "Guard also removed the verified legacy Oh My Pi extension from the combined Pi install.";

struct Family {
    config_dir: &'static str,
    display_name: &'static str,
}

fn family(spec: &Spec) -> Family {
    match spec.harness {
        "omp" => Family {
            config_dir: ".omp",
            display_name: "Oh My Pi",
        },
        _ => Family {
            config_dir: ".pi",
            display_name: "Pi",
        },
    }
}

fn agent_root(home: &Path, config_dir: &str) -> PathBuf {
    home.join(config_dir).join("agent")
}

fn global_root(spec: &Spec, ctx: &Ctx) -> PathBuf {
    agent_root(&ctx.home, family(spec).config_dir)
}

fn settings_path(spec: &Spec, ctx: &Ctx) -> PathBuf {
    global_root(spec, ctx).join(SETTINGS_FILE)
}

fn extension_path(spec: &Spec, ctx: &Ctx) -> PathBuf {
    global_root(spec, ctx)
        .join("extensions")
        .join(EXTENSION_NAME)
}

fn project_root(spec: &Spec, ctx: &Ctx) -> Option<PathBuf> {
    ctx.workspace
        .as_ref()
        .map(|workspace| workspace.join(family(spec).config_dir))
}

fn candidates(spec: &Spec, ctx: &Ctx) -> Vec<PathBuf> {
    vec![ctx.home.join(".local").join("bin").join(spec.executable)]
}

/// The `pi_detect` request: the global tree, then the workspace one.
pub(super) fn detect_request(spec: &Spec, ctx: &Ctx) -> Value {
    let mut roots = vec![(global_root(spec, ctx), "global")];
    if let Some(project) = project_root(spec, ctx) {
        roots.push((project, "project"));
    }
    let mut request = json!({
        "harness": spec.harness,
        "home": path_text(&ctx.user_home),
        "roots": roots
            .iter()
            .map(|(root, scope)| json!({
                "path": path_text(root),
                "scope": scope,
                "id_scope": format!("{}-{scope}", spec.harness),
            }))
            .collect::<Vec<_>>(),
    });
    if let Some(cwd) = ctx
        .cwd
        .as_ref()
        .filter(|_| roots.iter().any(|(root, _)| !root.is_absolute()))
    {
        request["cwd"] = json!(path_text(cwd));
    }
    request
}

fn detect(spec: &Spec, ctx: &Ctx) -> Step<Value> {
    let request = detect_request(spec, ctx);
    let available = which::resolve_command(ctx, spec.executable, &candidates(spec, ctx)).is_some()
        || which::user_directory_command(ctx, spec.executable, &ctx.home, &[]).is_some();
    detection(spec, crate::pi_detect::detect(&request), available)
}

/// The browser flow until a managed extension is active.
fn approval_flow(spec: &Spec, fields: &Map<String, Value>) -> Value {
    let active = fields
        .get("managed_install")
        .and_then(|install| install.get("active"))
        .is_some_and(truthy);
    if active {
        return spec.approval_flow();
    }
    let name = family(spec).display_name;
    json!({
        "tier": "approval-center",
        "summary": format!("Guard routes {name} approvals through the local approval center."),
        "fallback_hint": format!("Resolve pending {name} requests from the Guard approval center."),
        "prompt_channel": "browser",
        "auto_open_browser": true,
    })
}

/// `json_payload`: the settings object, `{}` when it is unreadable or not one.
fn settings_payload(ctx: &Ctx, path: &Path) -> Vec<(String, PyVal)> {
    let Ok(text) = std::fs::read_to_string(ctx.absolute(path)) else {
        return Vec::new();
    };
    match pyjson::parse(&text) {
        Ok(PyVal::Dict(entries)) => entries,
        _ => Vec::new(),
    }
}

fn extensions(payload: &[(String, PyVal)]) -> Option<&[PyVal]> {
    payload
        .iter()
        .find(|(key, _)| key == "extensions")
        .and_then(|(_, value)| value.as_list())
}

fn listed(payload: &[(String, PyVal)], extension: &str) -> bool {
    extensions(payload).is_some_and(|items| {
        items
            .iter()
            .any(|item| matches!(item, PyVal::Str(value) if value == extension))
    })
}

fn with_extensions(payload: Vec<(String, PyVal)>, items: Vec<String>) -> Step<Vec<u8>> {
    let mut doc = files::Doc(payload);
    doc.set(
        "extensions",
        PyVal::List(items.into_iter().map(PyVal::Str).collect()),
    );
    Ok(format!("{}\n", render(&doc.value())?).into_bytes())
}

/// Whether a local settings entry names a managed extension file.
fn managed_reference(ctx: &Ctx, value: &str, settings: &Path) -> bool {
    if REMOTE_PREFIXES
        .iter()
        .any(|prefix| value.starts_with(prefix))
    {
        return false;
    }
    let mut candidate = expand_user(ctx, value);
    if !candidate.is_absolute() {
        candidate = settings.parent().unwrap_or(Path::new("")).join(candidate);
    }
    candidate
        .file_name()
        .is_some_and(|name| name == EXTENSION_NAME)
}

/// The settings with the managed reference listed once and no other.
fn enabled_settings(
    ctx: &Ctx,
    payload: Vec<(String, PyVal)>,
    settings: &Path,
    extension: &str,
) -> Step<Vec<u8>> {
    let mut items: Vec<String> = extensions(&payload)
        .unwrap_or_default()
        .iter()
        .filter_map(|item| match item {
            PyVal::Str(value) => Some(value.clone()),
            _ => None,
        })
        .filter(|item| item == extension || !managed_reference(ctx, item, settings))
        .collect();
    if !items.iter().any(|item| item == extension) {
        items.push(extension.to_owned());
    }
    with_extensions(payload, items)
}

/// The settings write that drops the managed reference, when there is a list.
fn disabled_settings(ctx: &Ctx, settings: &Path, extension: &str) -> Step<Option<Value>> {
    if !ctx.absolute(settings).is_file() {
        return Ok(None);
    }
    let payload = settings_payload(ctx, settings);
    let Some(items) = extensions(&payload) else {
        return Ok(None);
    };
    let kept = items
        .iter()
        .filter_map(|item| match item {
            PyVal::Str(value) if value != extension => Some(value.clone()),
            _ => None,
        })
        .collect();
    let rendered =
        String::from_utf8(with_extensions(payload, kept)?).map_err(|_| Failure::Invalid)?;
    Ok(Some(json!({"path": path_text(settings), "text": rendered})))
}

fn read_text(ctx: &Ctx, path: &Path) -> Option<String> {
    std::fs::read_to_string(ctx.absolute(path)).ok()
}

/// A file mode as `st_mode & 0o777`, or `0o644` for a new file.
fn mode_or_default(ctx: &Ctx, path: &Path, present: bool) -> u32 {
    present
        .then(|| files::mode(ctx, path))
        .flatten()
        .unwrap_or(0o644)
}

fn prepare_install(spec: &Spec, ctx: &Ctx, fields: &Map<String, Value>) -> Step<Value> {
    let shim = files::shim_manifest(fields)?;
    let runtime = Runtime::parse(fields)?;
    let display_name = family(spec).display_name;
    let extension = extension_path(spec, ctx);
    let settings = settings_path(spec, ctx);
    let extension_before = files::snapshot(ctx, &extension)?;
    let settings_before = files::snapshot(ctx, &settings)?;
    let payload = match &settings_before {
        None => Vec::new(),
        Some(bytes) => {
            let text = utf8(bytes.clone(), &format!("{display_name} settings"))?;
            match pyjson::parse(&text) {
                Ok(PyVal::Dict(entries)) => entries,
                Ok(_) => {
                    return Err(Failure::Refusal(format!(
                        "{display_name} settings must be a JSON object."
                    )))
                }
                Err(_) => {
                    return Err(Failure::Refusal(format!(
                        "{display_name} settings are not valid JSON."
                    )))
                }
            }
        }
    };
    let source = render_source(
        ctx,
        &runtime,
        "active",
        spec.harness,
        display_name,
        &settings,
    )?;
    let settings_after = enabled_settings(ctx, payload, &settings, &path_text(&extension))?;
    let mut changes = Vec::new();
    for (path, before, after) in [
        (&extension, extension_before, source.into_bytes()),
        (&settings, settings_before, settings_after),
    ] {
        let mode = mode_or_default(ctx, path, before.is_some());
        changes.push(Change::at(ctx, path, before, Some(after), mode));
    }
    let note = format!(
        "Guard installed a managed {display_name} extension that reviews prompts and tool calls \
         before {display_name} executes them."
    );
    let manifest = adapter_result(spec.harness, true, &extension, &shim, vec![text(note)]);
    Ok(json!({
        "files": changes.iter().map(Change::wire).collect::<Vec<_>>(),
        "manifest": render(&manifest.value())?,
    }))
}

/// The Oh My Pi extension the former combined Pi install wrote, when it is
/// still byte-for-byte that install's: `(settings, extension)`.
fn legacy_omp(ctx: &Ctx, runtime: &Runtime) -> Step<Option<(PathBuf, PathBuf)>> {
    let settings = agent_root(&ctx.home, ".omp").join(SETTINGS_FILE);
    let extension = settings
        .parent()
        .unwrap_or(Path::new(""))
        .join("extensions")
        .join(EXTENSION_NAME);
    let Some(source) = read_text(ctx, &extension) else {
        return Ok(None);
    };
    for variant in ["active", "previous"] {
        if render_source(ctx, runtime, variant, "pi", "Pi", &settings)? == source {
            return Ok(Some((settings, extension)));
        }
    }
    Ok(None)
}

fn prepare_uninstall(spec: &Spec, ctx: &Ctx, fields: &Map<String, Value>) -> Step<Value> {
    let display_name = family(spec).display_name;
    let extension = extension_path(spec, ctx);
    let mut writes: Vec<Value> = Vec::new();
    let mut deletes = Vec::new();
    writes.extend(disabled_settings(
        ctx,
        &settings_path(spec, ctx),
        &path_text(&extension),
    )?);
    if ctx.absolute(&extension).exists() {
        deletes.push(path_text(&extension));
    }
    let mut tail = Vec::new();
    if spec.harness == "pi" {
        if let Some((settings, legacy)) = legacy_omp(ctx, &Runtime::parse(fields)?)? {
            writes.extend(disabled_settings(ctx, &settings, &path_text(&legacy))?);
            deletes.push(path_text(&legacy));
            tail.push(LEGACY_OMP_NOTE);
        }
    }
    let note = format!(
        "Guard removed the managed {display_name} extension and left your {display_name} \
         resources unchanged."
    );
    Ok(json!({
        "writes": writes,
        "deletes": deletes,
        "finish": {"notes": [note], "tail": tail},
    }))
}

/// The inactive manifest: the plan's notes, the shim's, then the legacy note.
fn finish_uninstall(spec: &Spec, ctx: &Ctx, fields: &Map<String, Value>) -> Step<Value> {
    let notes = |key: &str| -> Step<Vec<PyVal>> {
        fields
            .get("finish")
            .and_then(|finish| finish.get(key))
            .and_then(Value::as_array)
            .ok_or(Failure::Invalid)?
            .iter()
            .map(|note| note.as_str().map(text).ok_or(Failure::Invalid))
            .collect()
    };
    let shim = files::shim_manifest(fields)?;
    let mut manifest = adapter_result(
        spec.harness,
        false,
        &extension_path(spec, ctx),
        &shim,
        notes("notes")?,
    );
    let tail = notes("tail")?;
    if let Some((_, PyVal::List(all))) = manifest.0.iter_mut().find(|(key, _)| key == "notes") {
        all.extend(tail);
    }
    files::manifest_answer(manifest)
}

/// Whether the managed extension already matches what this Guard would write.
fn extension_current(spec: &Spec, ctx: &Ctx, fields: &Map<String, Value>) -> Step<Value> {
    let extension = extension_path(spec, ctx);
    let settings = settings_path(spec, ctx);
    let current = ctx.absolute(&extension).is_file()
        && match read_text(ctx, &extension) {
            None => false,
            Some(source) => {
                let runtime = Runtime::parse(fields)?;
                let expected = render_source(
                    ctx,
                    &runtime,
                    "active",
                    spec.harness,
                    family(spec).display_name,
                    &settings,
                )?;
                source == expected
                    && listed(&settings_payload(ctx, &settings), &path_text(&extension))
            }
        };
    Ok(json!({ "current": current }))
}

/// Whether the Oh My Pi extension is exactly the one the former combined Pi
/// install wrote, for the Pi install record `managed_install`.
fn legacy_omp_verified(ctx: &Ctx, fields: &Map<String, Value>) -> Step<Value> {
    let install = fields.get("managed_install").ok_or(Failure::Invalid)?;
    let pi_extension = agent_root(&ctx.home, ".pi")
        .join("extensions")
        .join(EXTENSION_NAME);
    let recorded = install.get("active").is_some_and(truthy)
        && install
            .get("manifest")
            .and_then(Value::as_object)
            .and_then(|manifest| manifest.get("config_path"))
            .and_then(Value::as_str)
            == Some(path_text(&pi_extension).as_str());
    if !recorded {
        return Ok(json!({ "verified": false }));
    }
    let settings = agent_root(&ctx.home, ".omp").join(SETTINGS_FILE);
    let extension = settings
        .parent()
        .unwrap_or(Path::new(""))
        .join("extensions")
        .join(EXTENSION_NAME);
    if !listed(&settings_payload(ctx, &settings), &path_text(&extension)) {
        return Ok(json!({ "verified": false }));
    }
    let verified = legacy_omp(ctx, &Runtime::parse(fields)?)?.is_some();
    Ok(json!({ "verified": verified }))
}

/// One extension source, for a caller that compares or tests it.
fn extension_source(spec: &Spec, ctx: &Ctx, fields: &Map<String, Value>) -> Step<Value> {
    let variant = match fields.get("variant").and_then(Value::as_str) {
        Some(variant @ ("active" | "previous")) => variant,
        _ => return Err(Failure::Invalid),
    };
    let settings = match fields.get("config_path") {
        None | Some(Value::Null) => settings_path(spec, ctx),
        Some(Value::String(path)) => PathBuf::from(path),
        Some(_) => return Err(Failure::Invalid),
    };
    let source = render_source(
        ctx,
        &Runtime::parse(fields)?,
        variant,
        spec.harness,
        family(spec).display_name,
        &settings,
    )?;
    Ok(json!({ "source": source }))
}

/// The report fields the pinned Core and code-mode checks change.
fn diagnostics(spec: &Spec, ctx: &Ctx, fields: &Map<String, Value>) -> Step<Value> {
    let mut status = fields.get("setup_status").cloned().unwrap_or(Value::Null);
    let mut warnings: Vec<Value> = fields
        .get("warnings")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let mut update = Map::new();
    if let Some(pinned) = pinned_core(ctx, &extension_path(spec, ctx)) {
        warnings.push(json!(format!(
            "The managed {} extension runs a pinned Desktop core ({pinned}) that Desktop has \
             replaced, so its Guard calls run against a newer Guard. Run `hol-guard repair` to \
             regenerate it.",
            family(spec).display_name
        )));
        if status == json!("active") {
            status = json!("broken");
        }
        update.insert("setup_status".into(), status);
        update.insert("warnings".into(), json!(warnings));
    }
    if spec.harness == "omp" {
        let extra = code_mode_warnings(ctx);
        if !extra.is_empty() {
            warnings.extend(extra.into_iter().map(Value::String));
            update.insert("warnings".into(), json!(warnings));
        }
    }
    let update = serde_json::to_string(&update).map_err(|_| Failure::Invalid)?;
    Ok(json!({ "update": update }))
}

pub(crate) fn dispatch(
    spec: &Spec,
    op: &str,
    ctx: &Ctx,
    fields: &Map<String, Value>,
) -> Step<Value> {
    match op {
        "policy_path" => {
            let root = project_root(spec, ctx).unwrap_or_else(|| global_root(spec, ctx));
            path_answer(&root.join(SETTINGS_FILE))
        }
        "resolved_executable" => super::resolved_executable(spec, ctx, &candidates(spec, ctx)),
        "detect" => detect(spec, ctx),
        "approval_flow" => Ok(approval_flow(spec, fields)),
        "diagnostics" => diagnostics(spec, ctx, fields),
        "prepare_install" => prepare_install(spec, ctx, fields),
        "prepare_uninstall" => prepare_uninstall(spec, ctx, fields),
        "finish_uninstall" => finish_uninstall(spec, ctx, fields),
        "extension_source" => extension_source(spec, ctx, fields),
        "extension_current" => extension_current(spec, ctx, fields),
        "legacy_omp_verified" => legacy_omp_verified(ctx, fields),
        _ => super::common(spec, op, ctx),
    }
}

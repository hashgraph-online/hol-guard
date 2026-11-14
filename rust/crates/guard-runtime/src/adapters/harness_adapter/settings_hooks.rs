//! Devin and Muse: Guard's hook groups in the user settings file, with a
//! backup and an install state under the Guard home. `harness_settings_file`
//! reads and renders the settings; this module picks the paths, snapshots the
//! files and builds the plan.

use std::path::{Path, PathBuf};

use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use serde_json::{json, Map, Value};

use super::files::{self, adapter_result, Change};
use super::kimi::{guard_hook_args, hook_command};
use super::{
    common, detection, path_answer, path_text, resolved_executable, which, Ctx, Failure, Spec, Step,
};

const HOOK_TIMEOUT_SECONDS: i64 = 25;
const MUSE_GRACE_SECONDS: i64 = 5;
const MAX_APPROVAL_WAIT_SECONDS: i64 = 600;

/// The per-harness names, as the two Python adapters spelled them.
struct Layout {
    config_file: &'static str,
    project_dir: &'static str,
    label: &'static str,
    unsafe_message: &'static str,
}

fn layout(spec: &Spec) -> Layout {
    if spec.harness == "muse" {
        Layout {
            config_file: "settings.json",
            project_dir: ".muse",
            label: "Muse",
            unsafe_message: "Muse settings could not be parsed safely; Guard will not rewrite it.",
        }
    } else {
        Layout {
            config_file: "config.json",
            project_dir: ".devin",
            label: "Devin",
            unsafe_message: "Devin config could not be parsed safely; Guard will not rewrite it.",
        }
    }
}

fn config_dir(spec: &Spec, ctx: &Ctx) -> PathBuf {
    let default = ctx.home.join(".config").join(spec.harness);
    if spec.harness == "muse" {
        // XDG_CONFIG_HOME only redirects the caller's own home.
        match ctx.env("XDG_CONFIG_HOME").map(str::trim) {
            Some(xdg) if !xdg.is_empty() && ctx.default_home() => PathBuf::from(xdg).join("muse"),
            _ => default,
        }
    } else {
        match ctx.env("APPDATA").map(str::trim) {
            Some(appdata) if ctx.windows && !appdata.is_empty() => {
                PathBuf::from(appdata).join("devin")
            }
            _ => default,
        }
    }
}

fn user_config(spec: &Spec, ctx: &Ctx) -> PathBuf {
    config_dir(spec, ctx).join(layout(spec).config_file)
}

fn config_root(spec: &Spec, ctx: &Ctx) -> PathBuf {
    let dir = config_dir(spec, ctx);
    dir.parent().map_or(dir.clone(), Path::to_path_buf)
}

/// `guard_home/managed/<harness>/{backup, install.state.json}`, each checked.
fn state_paths(spec: &Spec, ctx: &Ctx) -> Step<(PathBuf, PathBuf)> {
    let Layout {
        config_file, label, ..
    } = layout(spec);
    let state_dir = ctx.guard_home.join("managed").join(spec.harness);
    let backup = state_dir.join(format!("{config_file}.backup"));
    let state = state_dir.join("install.state.json");
    files::within_root(ctx, &ctx.guard_home, &state_dir, &format!("{label} state"))?;
    files::within_root(ctx, &state_dir, &backup, &format!("{label} backup"))?;
    files::within_root(ctx, &state_dir, &state, &format!("{label} state"))?;
    Ok((backup, state))
}

/// `load_guard_config(...).approval_wait_timeout_seconds`.
fn approval_wait(ctx: &Ctx) -> Step<i64> {
    crate::guard_config_load::approval_wait_timeout_seconds(
        &ctx.guard_home,
        ctx.workspace.as_deref(),
    )
    .map_err(Failure::Refusal)
}

/// Muse's bridge deadline, which every managed hook timeout outlasts.
fn muse_bridge_seconds(ctx: &Ctx) -> Step<i64> {
    let wait = approval_wait(ctx)?.clamp(0, MAX_APPROVAL_WAIT_SECONDS) + MUSE_GRACE_SECONDS;
    Ok(HOOK_TIMEOUT_SECONDS.max(wait + MUSE_GRACE_SECONDS))
}

fn hook_timeout(spec: &Spec, ctx: &Ctx) -> Step<i64> {
    if spec.harness == "muse" {
        muse_bridge_seconds(ctx)
    } else {
        Ok(HOOK_TIMEOUT_SECONDS)
    }
}

fn settings_file(request: Value) -> Step<Map<String, Value>> {
    match crate::harness_settings_file::dispatch(&request).map_err(|_| Failure::Invalid)? {
        Value::Object(answer) => Ok(answer),
        _ => Err(Failure::Invalid),
    }
}

fn notes(answer: &Map<String, Value>) -> Step<Vec<String>> {
    answer
        .get("notes")
        .and_then(Value::as_array)
        .ok_or(Failure::Invalid)?
        .iter()
        .map(|note| note.as_str().map(str::to_owned).ok_or(Failure::Invalid))
        .collect()
}

fn snapshot_mode(ctx: &Ctx, path: &Path, before: Option<&Vec<u8>>, default: u32) -> Step<u32> {
    match before {
        Some(_) => files::mode(ctx, path).ok_or(Failure::Invalid),
        None => Ok(default),
    }
}

fn prepare_install(spec: &Spec, ctx: &Ctx, fields: &Map<String, Value>) -> Step<Value> {
    let shim = files::shim_manifest(fields)?;
    let config = user_config(spec, ctx);
    let names = layout(spec);
    files::within_root(ctx, &config_root(spec, ctx), &config, names.label)?;
    let config_before = match files::snapshot(ctx, &config) {
        Err(Failure::Integrity(_)) => return Err(Failure::Refusal(names.unsafe_message.into())),
        other => other?,
    };
    let (timing_key, timing) = if spec.harness == "muse" {
        ("bridge_seconds", muse_bridge_seconds(ctx)?)
    } else {
        ("wait_seconds", approval_wait(ctx)?)
    };
    let command = hook_command(ctx, fields)?;
    let (backup, state) = state_paths(spec, ctx)?;
    let mut request = json!({
        "op": "install",
        "harness": spec.harness,
        "content": config_before.as_deref().map(|bytes| STANDARD.encode(bytes)),
        "config_path": path_text(&config),
        "command": command,
    });
    request[timing_key] = json!(timing);
    let answer = settings_file(request)?;
    if let Some(Value::String(refusal)) = answer.get("refusal") {
        return Err(Failure::Refusal(refusal.clone()));
    }
    let rendered = |key: &str| {
        answer
            .get(key)
            .and_then(Value::as_str)
            .map(|text| text.as_bytes().to_vec())
            .ok_or(Failure::Invalid)
    };
    let (after_config, after_state) = (rendered("text")?, rendered("state")?);
    let notes = notes(&answer)?;
    let backup_before = files::snapshot(ctx, &backup)?;
    let state_before = files::snapshot(ctx, &state)?;
    let config_mode = snapshot_mode(ctx, &config, config_before.as_ref(), 0o600)?;
    let backup_mode = snapshot_mode(ctx, &backup, backup_before.as_ref(), config_mode)?;
    let state_mode = snapshot_mode(ctx, &state, state_before.as_ref(), 0o600)?;
    let backup_after = backup_before.clone().or_else(|| config_before.clone());
    let changes = [
        Change::at(ctx, &backup, backup_before, backup_after, backup_mode),
        Change::at(ctx, &config, config_before, Some(after_config), config_mode),
        Change::at(ctx, &state, state_before, Some(after_state), state_mode),
    ];
    let notes = notes.into_iter().map(files::text).collect();
    let manifest = adapter_result(spec.harness, true, &config, &shim, notes);
    Ok(json!({
        "files": changes.iter().map(Change::wire).collect::<Vec<_>>(),
        "manifest": files::render(&manifest.value())?,
    }))
}

fn prepare_uninstall(spec: &Spec, ctx: &Ctx) -> Step<Value> {
    let config = user_config(spec, ctx);
    let absolute = ctx.absolute(&config);
    let present = absolute.is_file();
    if present {
        files::within_root(ctx, &config_root(spec, ctx), &config, layout(spec).label)?;
    }
    let content = present
        .then(|| std::fs::read(&absolute).ok())
        .flatten()
        .map(|bytes| STANDARD.encode(bytes));
    // The prune asks first, so a refusal leaves the launcher, the settings and
    // the install state as they were.
    let answer = settings_file(json!({
        "op": "uninstall",
        "harness": spec.harness,
        "content": content,
        "present": present,
    }))?;
    let notes = notes(&answer)?;
    let (_, state) = state_paths(spec, ctx)?;
    let mut writes = Vec::new();
    if let Some(Value::String(text)) = answer.get("text") {
        // The settings at the path, or at its link's target, keeping the mode.
        let target = if absolute.is_symlink() {
            ctx.resolved(&config)
        } else {
            config.clone()
        };
        let mode = files::mode(ctx, &target).unwrap_or(0o600);
        writes.push(json!({"path": path_text(&target), "text": text, "mode": mode}));
    }
    let deletes: Vec<String> = ctx
        .absolute(&state)
        .is_file()
        .then(|| path_text(&state))
        .into_iter()
        .collect();
    Ok(json!({"writes": writes, "deletes": deletes, "finish": {"notes": notes}}))
}

pub(crate) fn dispatch(
    spec: &Spec,
    op: &str,
    ctx: &Ctx,
    fields: &Map<String, Value>,
) -> Step<Value> {
    match op {
        "policy_path" => {
            let project = ctx
                .workspace
                .as_ref()
                .map(|workspace| {
                    workspace
                        .join(layout(spec).project_dir)
                        .join(layout(spec).config_file)
                })
                .filter(|project| ctx.absolute(project).is_file());
            path_answer(&project.unwrap_or_else(|| user_config(spec, ctx)))
        }
        "resolved_executable" if spec.harness == "muse" => resolved_executable(
            spec,
            ctx,
            &[ctx.home.join(".local").join("bin").join(spec.executable)],
        ),
        "detect" => {
            let mut request = ctx.detection_request(spec.harness);
            request.insert(
                "config_dir".into(),
                json!(path_text(&config_dir(spec, ctx))),
            );
            let request = Value::Object(request);
            let (found, home) = if spec.harness == "muse" {
                (crate::muse_detect::detect(&request), None)
            } else {
                (
                    crate::devin_detect::detect(&request),
                    Some(ctx.home.as_path()),
                )
            };
            let available = which::command_available(ctx, spec.executable, home, &[]);
            detection(spec, found, available)
        }
        "hook_spec" => Ok(json!({
            "cli_args": guard_hook_args(ctx, spec.harness),
            "timeout_seconds": hook_timeout(spec, ctx)?,
        })),
        "prepare_install" => prepare_install(spec, ctx, fields),
        "prepare_uninstall" => prepare_uninstall(spec, ctx),
        "finish_uninstall" => files::finished(spec.harness, &user_config(spec, ctx), fields),
        _ => common(spec, op, ctx),
    }
}

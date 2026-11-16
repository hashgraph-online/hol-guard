//! Codex: every file an uninstall restores or deletes, captured before any of
//! them changes. The main config returns to its backup, or loses only the
//! hooks the authenticated manifest binds; alternate configs lose this
//! install's bridge; the receipt and manifest go, and so do the legacy shell
//! guards and the launcher.

use std::path::{Path, PathBuf};

use serde_json::{json, Map, Value};

use super::codex::{backup_path, config_path, hooks_path};
use super::codex_alternate_plan::alternate_change;
use super::codex_files::existing;
use super::codex_uninstall_config::uninstall_config;
use super::files::Change;
use super::{codex_files, path_text, shim_remove, Ctx, Failure, Step};

const PRIVATE_MODE: u32 = 0o600;

/// `_located`: the parent resolved, the name kept.
fn located(ctx: &Ctx, path: &Path) -> PathBuf {
    match (path.parent(), path.file_name()) {
        (Some(parent), Some(name)) => ctx.resolved(parent).join(name),
        _ => ctx.absolute(path),
    }
}

fn change(
    path: PathBuf,
    before: Option<Vec<u8>>,
    after: Option<Vec<u8>>,
    modes: (u32, u32),
) -> Value {
    Change {
        path,
        before,
        after,
        before_mode: modes.0,
        after_mode: modes.1,
        no_follow: true,
    }
    .wire()
}

fn encoded(data: Option<&[u8]>) -> Value {
    use base64::Engine as _;
    data.map_or(Value::Null, |data| {
        json!(base64::engine::general_purpose::STANDARD.encode(data))
    })
}

/// The main config's `render_without_guard`: whether it goes, and its new
/// bytes (`None` keeps the current ones).
fn rendered(
    ctx: &Ctx,
    fields: &Map<String, Value>,
    target: &Path,
    current: &[u8],
    backup: Option<&[u8]>,
) -> Step<(bool, Option<Vec<u8>>)> {
    let mut request = fields.clone();
    request.insert("config".into(), json!(path_text(target)));
    request.insert("hooks_json".into(), json!(path_text(&hooks_path(ctx))));
    request.insert("current".into(), encoded(Some(current)));
    request.insert("original".into(), encoded(backup));
    let answer = uninstall_config(ctx, &request)?;
    let text = answer.get("text").and_then(Value::as_str);
    Ok((
        answer.get("delete") == Some(&Value::Bool(true)),
        text.map(|text| text.as_bytes().to_vec()),
    ))
}

/// The main config and its backup.
fn main_files(ctx: &Ctx, fields: &Map<String, Value>, target: &Path) -> Step<Vec<Value>> {
    let (current, mode) = existing(ctx, target)?;
    let backup_path = located(ctx, &backup_path(ctx));
    let (backup, backup_mode) = existing(ctx, &backup_path)?;
    let mut files = Vec::new();
    match (&backup, current) {
        (Some(saved), current) => {
            let mut after = (!saved.is_empty()).then(|| saved.clone());
            if let Some(current) = &current {
                let (delete, text) = rendered(ctx, fields, target, current, Some(saved))?;
                after = if delete {
                    None
                } else {
                    Some(text.unwrap_or_else(|| current.clone()))
                };
            }
            files.push(change(
                target.to_path_buf(),
                current,
                after,
                (mode, PRIVATE_MODE),
            ));
            files.push(change(
                backup_path,
                backup,
                None,
                (backup_mode, PRIVATE_MODE),
            ));
        }
        (None, Some(current)) => {
            let (_delete, text) = rendered(ctx, fields, target, &current, None)?;
            if let Some(text) = text {
                files.push(change(
                    target.to_path_buf(),
                    Some(current),
                    Some(text),
                    (mode, PRIVATE_MODE),
                ));
            }
        }
        (None, None) => {}
    }
    Ok(files)
}

fn files_of(answer: &Value) -> Step<Vec<Value>> {
    match answer.get("files") {
        Some(Value::Array(files)) => Ok(files.clone()),
        _ => Err(Failure::Invalid),
    }
}

/// `_prepare_uninstall`: the ordered files, the indices the caller compares
/// against disk before using them, and the launcher manifest.
/// Request fields: `owned` (JSON text of the manifest bindings),
/// `authority_files` (receipt and manifest paths) and the owner fields.
pub(super) fn uninstall_plan(ctx: &Ctx, fields: &Map<String, Value>) -> Step<Value> {
    let target = located(ctx, &config_path(ctx));
    let mut files = main_files(ctx, fields, &target)?;
    let mut compared = Vec::new();
    let mut alternates = vec![config_path(ctx)];
    if let Some(workspace) = &ctx.workspace {
        alternates.push(workspace.join(".codex").join("config.toml"));
    }
    for path in alternates {
        if located(ctx, &path) == target || !ctx.absolute(&path).is_file() {
            continue;
        }
        let mut request = fields.clone();
        request.insert("config".into(), json!(path_text(&path)));
        request.insert("remove_hooks".into(), json!(true));
        request.insert("managed_server_names".into(), json!([]));
        let answer = alternate_change(ctx, &request)?;
        compared.push(files.len());
        files.push(answer.get("file").cloned().ok_or(Failure::Invalid)?);
    }
    let Some(Value::Array(authority)) = fields.get("authority_files") else {
        return Err(Failure::Invalid);
    };
    for path in authority {
        let path = located(ctx, Path::new(path.as_str().ok_or(Failure::Invalid)?));
        let (data, mode) = existing(ctx, &path)?;
        if data.is_some() {
            files.push(change(path, data, None, (mode, mode)));
        }
    }
    for shell in files_of(&codex_files::shell_cleanup(ctx)?)? {
        compared.push(files.len());
        files.push(shell);
    }
    let mut shim = Map::new();
    shim.insert("harness".into(), json!("codex"));
    let removal = shim_remove::prepare(ctx, &shim)?;
    files.extend(files_of(&removal)?);
    Ok(json!({
        "files": files,
        "compared": compared,
        "manifest": removal.get("manifest").cloned().ok_or(Failure::Invalid)?,
    }))
}

#[cfg(test)]
#[path = "codex_uninstall_plan_tests.rs"]
mod tests;

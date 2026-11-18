//! `update_refresh`: what `hol-guard update` does for an active OpenCode
//! install. It refreshes the MCP companion launchers under the config lock,
//! then rewrites the pretool plugin when either installed copy is stale, and
//! answers the one note the update reports (`null` when there is nothing to
//! say).
//!
//! Failures a Python caller would have caught as `OSError`, `RuntimeError` or
//! `ValueError` become the note's wording; anything else is the runtime's
//! own failure.

use std::fs;
use std::path::Path;

use serde_json::{json, Map, Value};

use super::opencode_checks::{plugin_refresh, refresh_apply};
use super::update_support::os_failure;
use super::{install_apply, managed_store, Ctx, Failure, Spec, Step};
use crate::guard_paths::expanduser;
use crate::transition_files::resolve_lenient;

const COMPANION_PARTIAL: &str =
    "Could not refresh OpenCode MCP companion launchers in every config: ";
const COMPANION_FAILED: &str = "Could not refresh OpenCode MCP companion launchers during update: ";
const COMPANIONS_REFRESHED: &str =
    "Refreshed OpenCode MCP companion launchers. Restart OpenCode to load them.";
const INSPECT_FAILED: &str = "Could not inspect OpenCode pretool plugin during update: ";
const PLUGIN_FAILED: &str = "Could not refresh OpenCode pretool plugin during update: ";
const PLUGIN_REFRESHED: &str =
    "Refreshed the OpenCode pretool plugin during update. Restart OpenCode to load it.";

/// The message of a failure an update reports as a note.
fn caught(failure: Failure) -> Step<String> {
    match failure {
        Failure::Refusal(message)
        | Failure::Os(message)
        | Failure::NotFound(message)
        | Failure::Runtime(message) => Ok(message),
        other => Err(other),
    }
}

fn note(text: Option<String>) -> Step<Value> {
    Ok(json!({ "note": text }))
}

/// Refresh the companion launchers: whether any changed, and the warning to
/// report.
fn refresh_companions(spec: &Spec, ctx: &Ctx) -> Step<(bool, Option<String>)> {
    let applied = install_apply::opencode_lock(spec, ctx).and_then(|_config| refresh_apply(ctx));
    let answer = match applied {
        Ok(answer) => answer,
        Err(failure) => {
            return Ok((
                false,
                Some(format!("{COMPANION_FAILED}{}", caught(failure)?)),
            ));
        }
    };
    let refreshed = answer
        .get("refreshed")
        .and_then(Value::as_u64)
        .ok_or(Failure::Invalid)?
        > 0;
    let mut unique: Vec<&str> = Vec::new();
    for warning in answer
        .get("warnings")
        .and_then(Value::as_array)
        .ok_or(Failure::Invalid)?
    {
        let warning = warning.as_str().ok_or(Failure::Invalid)?;
        if !unique.contains(&warning) {
            unique.push(warning);
        }
    }
    let warning = (!unique.is_empty()).then(|| format!("{COMPANION_PARTIAL}{}", unique.join(" ")));
    Ok((refreshed, warning))
}

/// `path.parent.mkdir(parents=True, exist_ok=True)` then
/// `path.write_text(source, encoding="utf-8")`.
fn write_plugin(ctx: &Ctx, path: &Path, source: &str) -> Step<()> {
    if let Some(parent) = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        fs::create_dir_all(ctx.absolute(parent))
            .map_err(|error| os_failure(ctx, &error, parent))?;
    }
    // Text mode writes the platform's line ending.
    let body = if ctx.windows {
        source.replace('\n', "\r\n")
    } else {
        source.to_owned()
    };
    fs::write(ctx.absolute(path), body).map_err(|error| os_failure(ctx, &error, path))
}

const WORKSPACE_INVALID: &str = "managed install workspace path is invalid";

/// `managed_install_context`: the context with the install's recorded
/// workspace, resolved as `Path.resolve()` would, or none when it records
/// none.
pub(super) fn rebind(ctx: &Ctx, recorded: Option<&Value>) -> Result<Ctx, &'static str> {
    let mut rebound = ctx.clone();
    rebound.workspace = None;
    let Some(text) = recorded
        .and_then(Value::as_str)
        .filter(|text| !text.trim().is_empty())
    else {
        return Ok(rebound);
    };
    let home = ctx.user_home.to_str().ok_or(WORKSPACE_INVALID)?;
    let expanded = expanduser(text, home).map_err(|_| WORKSPACE_INVALID)?;
    let mut path = Path::new(&expanded).to_path_buf();
    if path.is_relative() {
        path = ctx.cwd.as_ref().ok_or(WORKSPACE_INVALID)?.join(path);
    }
    rebound.workspace = Some(resolve_lenient(&path));
    Ok(rebound)
}

/// `update_refresh`. With `store_home` the runtime also reads the OpenCode
/// install record itself: nothing to say when there is no active install or
/// the record cannot be read, and the install's own workspace is the one the
/// refresh works in.
pub(super) fn update_refresh(spec: &Spec, ctx: &Ctx, fields: &Map<String, Value>) -> Step<Value> {
    let Some(store_home) = fields.get("store_home") else {
        return refresh(spec, ctx, fields);
    };
    let home = Path::new(store_home.as_str().ok_or(Failure::Invalid)?);
    let install = match managed_store::managed_install(home, "opencode") {
        Ok(Some(install)) => install,
        Ok(None) | Err(Failure::Runtime(_)) => return note(None),
        Err(other) => return Err(other),
    };
    if install.get("active") != Some(&Value::Bool(true)) {
        return note(None);
    }
    match rebind(ctx, install.get("workspace")) {
        Ok(rebound) => refresh(spec, &rebound, fields),
        Err(message) => note(Some(format!("{INSPECT_FAILED}{message}"))),
    }
}

fn refresh(spec: &Spec, ctx: &Ctx, fields: &Map<String, Value>) -> Step<Value> {
    let (refreshed, companion_warning) = refresh_companions(spec, ctx)?;
    let refresh = match plugin_refresh(ctx, fields) {
        Ok(refresh) => refresh,
        Err(failure) => return note(Some(format!("{INSPECT_FAILED}{}", caught(failure)?))),
    };
    if refresh.get("current") == Some(&Value::Bool(true)) {
        let parts: Vec<&str> = companion_warning
            .iter()
            .map(String::as_str)
            .chain(refreshed.then_some(COMPANIONS_REFRESHED))
            .collect();
        return note((!parts.is_empty()).then(|| parts.join(" ")));
    }
    let source = refresh
        .get("source")
        .and_then(Value::as_str)
        .ok_or(Failure::Invalid)?;
    let paths = refresh
        .get("paths")
        .and_then(Value::as_array)
        .ok_or(Failure::Invalid)?;
    for value in paths {
        let path = Path::new(value.as_str().ok_or(Failure::Invalid)?);
        if let Err(failure) = write_plugin(ctx, path, source) {
            return note(Some(format!("{PLUGIN_FAILED}{}", caught(failure)?)));
        }
    }
    note(Some(match companion_warning {
        Some(warning) => format!("{warning} {PLUGIN_REFRESHED}"),
        None => PLUGIN_REFRESHED.to_owned(),
    }))
}

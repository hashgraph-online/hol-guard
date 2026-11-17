//! The launchers an uninstall deletes: `prepare_guard_shim_removal` plans
//! them, and `remove` deletes each without following a link. Both answer the
//! shim manifest Python's `remove_guard_shim` returned.

use std::path::{Path, PathBuf};

use serde_json::{json, Map, Value};

use super::describe::Spec;
use super::files::{mode, path_value, render, snapshot, text, Change, Doc};
use super::{path_text, Ctx, Failure, Step};
use crate::pyjson::PyVal;
use crate::transition_files::remove_no_follow;

/// The older launcher names an adapter still removes on uninstall.
fn legacy_launcher_names(harness: &str) -> &'static [&'static str] {
    match harness {
        "cursor" => &["cursor"],
        "claude-code" => &["claude-code"],
        _ => &[],
    }
}

/// `path.parent.resolve(strict=False) / path.name`.
fn removal_target(ctx: &Ctx, path: &Path) -> Step<PathBuf> {
    let (Some(parent), Some(name)) = (path.parent(), path.file_name()) else {
        return Err(Failure::Invalid);
    };
    Ok(ctx.resolved(parent).join(name))
}

struct Plan {
    changes: Vec<Change>,
    manifest: Doc,
    posix_path: PathBuf,
}

/// Snapshots each installed launcher under `shim_name` and `legacy`.
fn plan(ctx: &Ctx, shim_name: &str, label: &str, legacy: &[&str]) -> Step<Plan> {
    let shim_dir = ctx.guard_home.join("bin");
    let mut changes = Vec::new();
    let mut removed = Vec::new();
    for name in std::iter::once(shim_name).chain(legacy.iter().copied()) {
        for suffix in ["", ".cmd"] {
            let path = shim_dir.join(format!("guard-{name}{suffix}"));
            let Some(before) = snapshot(ctx, &path)? else {
                continue;
            };
            let file_mode = mode(ctx, &path).unwrap_or(0o644);
            changes.push(Change {
                path: removal_target(ctx, &path)?,
                before: Some(before),
                after: None,
                before_mode: file_mode,
                after_mode: file_mode,
                no_follow: true,
            });
            removed.push(path_value(&path));
        }
    }
    let posix_path = shim_dir.join(format!("guard-{shim_name}"));
    let mut manifest = Doc::default();
    manifest
        .set("shim_path", path_value(&posix_path))
        .set("shim_dir", text(path_text(&shim_dir)))
        .set("removed_paths", PyVal::List(removed))
        .set("shim_command", text(format!("guard-{shim_name}")))
        .set(
            "notes",
            PyVal::List(vec![text(format!(
                "Removed the Guard launcher shim for {label}."
            ))]),
        );
    Ok(Plan {
        changes,
        manifest,
        posix_path,
    })
}

/// Removes every installed launcher for `spec` and answers the shim manifest.
pub(super) fn remove(spec: &Spec, ctx: &Ctx) -> Step<(Vec<(String, PyVal)>, PathBuf)> {
    let shim_name = if spec.launcher_name.is_empty() {
        spec.harness
    } else {
        spec.launcher_name
    };
    let label = spec.display_name.unwrap_or(spec.harness);
    remove_named(ctx, shim_name, label, legacy_launcher_names(spec.harness))
}

/// Removes the `shim_name` launcher and each `legacy` one under `label`.
pub(super) fn remove_named(
    ctx: &Ctx,
    shim_name: &str,
    label: &str,
    legacy: &[&str],
) -> Step<(Vec<(String, PyVal)>, PathBuf)> {
    let plan = plan(ctx, shim_name, label, legacy)?;
    for change in &plan.changes {
        remove_no_follow(&change.path).map_err(|error| Failure::Os(error.to_string()))?;
    }
    Ok((plan.manifest.0, plan.posix_path))
}

fn field<'a>(fields: &'a Map<String, Value>, key: &str) -> Step<Option<&'a str>> {
    match fields.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(value)) if value.is_empty() => Ok(None),
        Some(Value::String(value)) => Ok(Some(value)),
        Some(_) => Err(Failure::Invalid),
    }
}

/// `prepare_guard_shim_removal`: the removal plan, without changing a file.
pub(super) fn prepare(ctx: &Ctx, fields: &Map<String, Value>) -> Step<Value> {
    let harness = field(fields, "harness")?.ok_or(Failure::Invalid)?;
    let shim_name = field(fields, "launcher_name")?.unwrap_or(harness);
    let label = field(fields, "display_name")?.unwrap_or(harness);
    let legacy = match fields.get("legacy_launcher_names") {
        None | Some(Value::Null) => Vec::new(),
        Some(Value::Array(names)) => names
            .iter()
            .map(|name| name.as_str().ok_or(Failure::Invalid))
            .collect::<Step<Vec<_>>>()?,
        Some(_) => return Err(Failure::Invalid),
    };
    let plan = plan(ctx, shim_name, label, &legacy)?;
    let files: Vec<Value> = plan.changes.iter().map(Change::wire).collect();
    Ok(json!({ "files": files, "manifest": render(&plan.manifest.value())? }))
}

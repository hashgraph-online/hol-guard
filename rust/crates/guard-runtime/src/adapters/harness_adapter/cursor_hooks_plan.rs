//! Installing Guard's Cursor hooks: the transition plan a prepare publishes,
//! the cleanup of the project-local hooks older Guards wrote, and the direct
//! install a rebind performs.

use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};

use super::copilot_install::rendered;
use super::cursor::{self, runtime, Ask, Attestation, Facts, EVENTS};
use super::cursor_files;
use super::cursor_state;
use super::cursor_hooks::{all_entries, merge, script_source, without_managed};
use super::files::{self, within_root, Change, Doc};
use super::{path_text, Ctx, Failure, Step};
use crate::pyjson::{self, PyVal};

/// A prepared hooks install: the identity dependency, the files and manifest.
pub(super) struct Prepared {
    pub(super) secret: PathBuf,
    pub(super) files: Vec<Change>,
    pub(super) manifest: Doc,
}

fn digest(source: &str) -> String {
    hex::encode(Sha256::digest(source.as_bytes()))
}

fn workspace_value(ctx: &Ctx) -> PyVal {
    ctx.workspace.as_deref().map_or(PyVal::Null, |workspace| {
        files::path_value(&ctx.resolved(workspace))
    })
}

fn events() -> PyVal {
    PyVal::List(EVENTS.iter().map(|event| files::text(*event)).collect())
}

/// The installed hook manifest; the state file holds it without the event
/// list and its own path, plus the workspace.
fn manifest(ctx: &Ctx, attestation: &Attestation, source: &str) -> (Doc, Doc) {
    let hooks = cursor::hooks_path(ctx);
    let backup = cursor::digest_path(ctx, &hooks, "hooks-", "backup");
    let state = cursor::digest_path(ctx, &hooks, "hooks-", "state");
    let mut manifest = Doc::default();
    manifest
        .set("managed_hooks_path", files::path_value(&hooks))
        .set(
            "managed_hook_script_path",
            files::path_value(&cursor::script_path(ctx)),
        )
        .set("managed_hook_events", events())
        .set("guard_cli_identity", attestation.identity.clone())
        .set("hook_script_sha256", files::text(digest(source)))
        .set("backup_path", files::path_value(&backup))
        .set("state_path", files::path_value(&state));
    let mut saved = Doc(manifest
        .0
        .iter()
        .filter(|(key, _)| key != "managed_hook_events" && key != "state_path")
        .cloned()
        .collect());
    saved.set("workspace_dir", workspace_value(ctx));
    (manifest, saved)
}

/// The `{existed, content}` envelope a hooks backup holds.
pub(super) fn backup_document(original: Option<&str>) -> Step<Vec<u8>> {
    let mut doc = Doc::default();
    doc.set("existed", PyVal::Bool(original.is_some()))
        .set("content", original.map_or(PyVal::Null, files::text));
    rendered(&doc.value())
}

pub(super) fn no_follow(
    ctx: &Ctx,
    path: &Path,
    before: Option<Vec<u8>>,
    after: Option<Vec<u8>>,
    modes: (u32, u32),
) -> Change {
    let mut change = Change::at(ctx, path, before, after, modes.0);
    change.after_mode = modes.1;
    change.no_follow = true;
    change
}

/// `prepare_cursor_hooks`: the complete native rebind against existing
/// authority, or the transition error that stops it.
pub(super) fn prepare(ask: &Ask, facts: &Facts) -> Step<Result<Prepared, &'static str>> {
    let ctx = ask.ctx;
    if facts.require_bridge().is_err() {
        return Ok(Err("adapter_preparation_native_cursor_bridge_missing"));
    }
    let secret = cursor::secret_path(ctx);
    match files::snapshot(ctx, &secret)? {
        None => return Ok(Err("adapter_preparation_authority_missing")),
        Some(bytes) if bytes.len() != 32 || !cursor_files::secret_private(ctx, &secret) => {
            return Ok(Err("adapter_preparation_authority_invalid"));
        }
        Some(_) => {}
    }
    let attestation = facts.attestation()?;
    let hooks = cursor::hooks_path(ctx);
    let script = cursor::script_path(ctx);
    let managed = cursor::managed_script_path(ctx);
    let backup = cursor::digest_path(ctx, &hooks, "hooks-", "backup");
    let state = cursor::digest_path(ctx, &hooks, "hooks-", "state");
    for path in [&hooks, &script] {
        within_root(ctx, &ctx.home, path, "Cursor hook")?;
    }
    for path in [&managed, &backup, &state] {
        within_root(ctx, &ctx.guard_home, path, "Cursor hook state")?;
    }
    let paths = [&hooks, &script, &managed, &backup, &state];
    let before = paths
        .iter()
        .map(|path| files::snapshot(ctx, path))
        .collect::<Step<Vec<_>>>()?;
    let original = before[0].as_deref();
    let payload = match original {
        None => Vec::new(),
        Some(bytes) => {
            let unreadable = || {
                Failure::Refusal(format!(
                    "Guard refused to overwrite unreadable Cursor hooks config at {}",
                    path_text(&hooks)
                ))
            };
            let text = std::str::from_utf8(bytes).map_err(|_| unreadable())?;
            match pyjson::parse(text).map_err(|_| unreadable())? {
                PyVal::Dict(entries) => entries,
                _ => {
                    return Err(runtime(format!(
                        "Guard refused to overwrite non-object Cursor hooks config at {}",
                        path_text(&hooks)
                    )))
                }
            }
        }
    };
    let entries = all_entries(ask, facts, attestation)?;
    let resolved_script = path_text(&ctx.resolved(&script));
    let merged = merge(ask, &payload, &entries, &resolved_script)?;
    let source = script_source(ask, facts, attestation)?;
    let (manifest, saved) = manifest(ctx, attestation, &source);
    let backup_after = match &before[3] {
        Some(existing) => existing.clone(),
        None => {
            let text = original.map(|bytes| String::from_utf8_lossy(bytes).into_owned());
            backup_document(text.as_deref())?
        }
    };
    let after = [
        rendered(&merged)?,
        source.clone().into_bytes(),
        source.into_bytes(),
        backup_after,
        rendered(&saved.value())?,
    ];
    let mut planned = Vec::new();
    for (index, (path, data)) in paths.iter().zip(after).enumerate() {
        let existing = before[index].is_some();
        let mode = if existing {
            files::mode(ctx, path).unwrap_or(0o600)
        } else {
            0o600
        };
        let mut after_mode = if index == 3 && existing { mode } else { 0o600 };
        if (index == 1 || index == 2) && !ctx.windows {
            after_mode |= 0o100;
        }
        planned.push(no_follow(
            ctx,
            path,
            before[index].clone(),
            Some(data),
            (mode, after_mode),
        ));
    }
    planned.extend(legacy_plan(ask)?);
    Ok(Ok(Prepared {
        secret,
        files: planned,
        manifest,
    }))
}

fn legacy_paths(ctx: &Ctx) -> Option<(PathBuf, PathBuf)> {
    let workspace = ctx.workspace.as_deref()?;
    let hooks = workspace.join(".cursor").join("hooks.json");
    if ctx.resolved(&hooks) == ctx.resolved(&cursor::hooks_path(ctx)) {
        return None;
    }
    Some((
        hooks,
        workspace
            .join(".cursor")
            .join("hooks")
            .join(cursor::SCRIPT_NAME),
    ))
}

/// `_prepare_legacy_project_cursor_cleanup`: remove the project-local hooks.
fn legacy_plan(ask: &Ask) -> Step<Vec<Change>> {
    let ctx = ask.ctx;
    let (Some(workspace), Some((hooks, script))) = (ctx.workspace.as_deref(), legacy_paths(ctx))
    else {
        return Ok(Vec::new());
    };
    within_root(ctx, workspace, &hooks, "Cursor legacy hooks")?;
    within_root(ctx, workspace, &script, "Cursor legacy script")?;
    let backup = cursor::digest_path(ctx, &hooks, "hooks-", "backup");
    let state = cursor::digest_path(ctx, &hooks, "hooks-", "state");
    for path in [&backup, &state] {
        within_root(ctx, &ctx.guard_home, path, "Cursor legacy state")?;
    }
    let paths = [&hooks, &script, &backup, &state];
    let before = paths
        .iter()
        .map(|path| files::snapshot(ctx, path))
        .collect::<Step<Vec<_>>>()?;
    let managed_script = match &before[1] {
        Some(bytes) => crate::cursor_hook_config::is_managed_script(&super::kimi::utf8(
            bytes.clone(),
            "The Cursor legacy hook script",
        )?),
        None => false,
    };
    let payload = before[0]
        .as_deref()
        .and_then(|bytes| std::str::from_utf8(bytes).ok())
        .and_then(|text| pyjson::parse(text).ok())
        .unwrap_or(PyVal::Dict(Vec::new()));
    let (cleaned, removed) = without_managed(ask, &payload, &path_text(&ctx.resolved(&script)))?;
    let mut after = before.clone();
    if managed_script || removed {
        let (plan, content) =
            files::backup_plan(ctx, &backup, &hooks, "The Cursor legacy hooks backup")?;
        match (plan["action"].as_str(), content) {
            (Some("write"), Some(content)) => after[0] = Some(content.into_bytes()),
            (Some("unlink"), _) => after[0] = None,
            _ => {}
        }
        if plan["restored"].as_bool() == Some(true) {
            after[2] = None;
            after[3] = None;
        } else if removed {
            after[0] = cleaned.as_ref().map(rendered).transpose()?;
            after[3] = None;
        }
        if managed_script {
            after[1] = None;
        }
    }
    Ok(paths
        .iter()
        .zip(before)
        .zip(after)
        .map(|((path, before), after)| {
            let mode = if before.is_some() {
                files::mode(ctx, path).unwrap_or(0o600)
            } else {
                0o600
            };
            no_follow(ctx, path, before, after, (mode, mode))
        })
        .collect())
}

/// After a published install: Guard's hooks must protect Cursor, and the
/// emptied legacy project directories go.
pub(super) fn verify(ask: &Ask) -> Step<()> {
    let (active, reason) = cursor_state::active(&cursor_state::hook_state(ask)?);
    if !active {
        return Err(runtime(format!(
            "guard_cursor_hook_install_verification_failed:{reason}"
        )));
    }
    if let (Some(workspace), Some(_)) = (ask.ctx.workspace.as_deref(), legacy_paths(ask.ctx)) {
        cursor_files::prune_project_dirs(ask.ctx, workspace);
    }
    Ok(())
}

//! Codex: the files an install plans besides the config, the migration and
//! main backups and the legacy shell guard removals, and the manifest the
//! install, prepared install and uninstall report.

use std::path::{Path, PathBuf};

use serde_json::{json, Map, Value};

use super::codex::{backup_path, digest, flag, str_list, strings, text, ENFORCEMENT_BOUNDARY};
use super::files::{self, Change, Doc};
use super::{path_text, Ctx, Failure, Spec, Step};
use crate::codex_install_plan::shell_block_ranges;
use crate::pyjson::PyVal;

const PRIVATE_MODE: u32 = 0o600;

fn existing(ctx: &Ctx, path: &Path) -> Step<(Option<Vec<u8>>, u32)> {
    let before = files::snapshot(ctx, path)?;
    let mode = match before {
        Some(_) => files::mode(ctx, path).unwrap_or(PRIVATE_MODE),
        None => PRIVATE_MODE,
    };
    Ok((before, mode))
}

fn private_change(
    path: PathBuf,
    before: Option<Vec<u8>>,
    after: Option<Vec<u8>>,
    mode: u32,
) -> Change {
    Change {
        path,
        before,
        after,
        before_mode: mode,
        after_mode: mode,
        no_follow: true,
    }
}

fn bytes_field(fields: &Map<String, Value>, key: &str) -> Step<Option<Vec<u8>>> {
    use base64::Engine as _;
    match fields.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(encoded)) => base64::engine::general_purpose::STANDARD
            .decode(encoded)
            .map(Some)
            .map_err(|_| Failure::Invalid),
        Some(_) => Err(Failure::Invalid),
    }
}

/// `_prepare_hook_migration_backup`: the original config, kept once.
pub(super) fn migration_backup(ctx: &Ctx, fields: &Map<String, Value>) -> Step<Value> {
    let config = PathBuf::from(text(fields, "config")?);
    let name = format!("{}.json", digest(ctx, &config, 16));
    let path = ctx
        .guard_home
        .join("managed")
        .join("codex")
        .join("migration-backups")
        .join(name);
    let (before, mode) = existing(ctx, &path)?;
    if before.is_some() {
        let after = before.clone();
        return Ok(json!({ "file": private_change(path, before, after, mode).wire() }));
    }
    let original = bytes_field(fields, "before")?;
    let content = match &original {
        Some(bytes) => String::from_utf8(bytes.clone())
            .map_err(|_| Failure::Refusal("Codex config file is not valid UTF-8.".into()))?,
        None => String::new(),
    };
    let mut payload = Doc::default();
    payload
        .set("config_path", files::path_value(&ctx.resolved(&config)))
        .set("content", files::text(content))
        .set("existed", PyVal::Bool(original.is_some()))
        .set("schema", files::text("codex-hook-migration-backup-v1"));
    let after = format!("{}\n", files::render(&payload.value())?).into_bytes();
    let mut change = private_change(path, None, Some(after), mode);
    change.after_mode = PRIVATE_MODE;
    Ok(json!({ "file": change.wire() }))
}

/// `prepare_codex_main_backup`: an existing backup is kept as it is.
pub(super) fn main_backup(ctx: &Ctx, fields: &Map<String, Value>) -> Step<Value> {
    let path = backup_path(ctx);
    let (before, mode) = existing(ctx, &path)?;
    let after = match &before {
        Some(bytes) => bytes.clone(),
        None => match fields.get("migrated").and_then(Value::as_str) {
            Some(migrated) => migrated.as_bytes().to_vec(),
            None => bytes_field(fields, "original")?.unwrap_or_default(),
        },
    };
    Ok(json!({ "file": private_change(path, before, Some(after), mode).wire() }))
}

fn cleanup_change(ctx: &Ctx, path: &Path, whole: bool) -> Step<Change> {
    let path = match (path.parent(), path.file_name()) {
        (Some(parent), Some(name)) => ctx.resolved(parent).join(name),
        _ => ctx.absolute(path),
    };
    let (before, mode) = existing(ctx, &path)?;
    let after = match &before {
        Some(_) if whole => None,
        Some(bytes) => {
            let ranges = shell_block_ranges(bytes);
            if ranges.is_empty() {
                before.clone()
            } else {
                let mut kept = Vec::with_capacity(bytes.len());
                let mut position = 0;
                for [start, end] in ranges {
                    kept.extend_from_slice(&bytes[position..start]);
                    position = end;
                }
                kept.extend_from_slice(&bytes[position..]);
                (!kept.is_empty()).then_some(kept)
            }
        }
        None => None,
    };
    Ok(private_change(path, before, after, mode))
}

/// `prepare_codex_shell_cleanup`: every legacy shell guard removal.
pub(super) fn shell_cleanup(ctx: &Ctx) -> Step<Value> {
    let root = ctx.guard_home.join("managed").join("codex");
    let mut changes = Vec::new();
    for name in [
        "codex-zshenv-guard.zsh",
        "codex-bashenv-guard.bash",
        "codex-fish-guard.fish",
    ] {
        changes.push(cleanup_change(ctx, &root.join(name), true)?.wire());
    }
    let fish = ctx.home.join(".config").join("fish").join("conf.d");
    for path in [
        ctx.home.join(".zshenv"),
        ctx.home.join(".bashrc"),
        ctx.home.join(".bash_profile"),
        ctx.home.join(".bash_login"),
        ctx.home.join(".profile"),
        fish.join("hol-guard-codex.fish"),
    ] {
        changes.push(cleanup_change(ctx, &path, false)?.wire());
    }
    Ok(json!({ "files": changes }))
}

fn names(fields: &Map<String, Value>, key: &str) -> Step<Vec<String>> {
    strings(fields.get(key))
}

/// The install, prepared install or uninstall manifest.
pub(super) fn manifest(spec: &Spec, ctx: &Ctx, fields: &Map<String, Value>) -> Step<Value> {
    let shim = files::shim_manifest(fields)?;
    let kind = text(fields, "kind")?;
    let config = text(fields, "config_path")?;
    let hooks = text(fields, "hooks_path")?;
    let backup = fields
        .get("backup_path")
        .and_then(Value::as_str)
        .map_or_else(|| path_text(&backup_path(ctx)), str::to_owned);
    let mut doc = Doc::default();
    doc.set("harness", files::text(spec.harness))
        .set("active", PyVal::Bool(kind != "uninstall"))
        .set("config_path", files::text(config))
        .spread(&shim)
        .set("mode", files::text("codex-mcp-proxy"))
        .set("managed_config_path", files::text(config))
        .set(
            "managed_hook_config_path",
            files::text(text(fields, "hook_config_path")?),
        );
    if kind == "uninstall" {
        doc.set("managed_hooks_path", files::text(hooks))
            .set("backup_path", files::text(backup));
        return files::manifest_answer(doc);
    }
    let migrated = names(fields, "migrated")?;
    let skipped: Vec<String> = names(fields, "skipped")?
        .into_iter()
        .filter(|name| !migrated.contains(name))
        .collect();
    doc.set(
        "managed_hook_manifest_path",
        files::text(text(fields, "manifest_path")?),
    )
    .set(
        "managed_hook_integrity",
        files::text(text(fields, "integrity")?),
    )
    .set(
        "hook_workspace_explicit",
        PyVal::Bool(flag(fields, "workspace_explicit")?),
    )
    .set("managed_hooks_path", files::text(hooks))
    .set("enforcement_boundary", files::text(ENFORCEMENT_BOUNDARY))
    .set("legacy_shell_guard_cleanup", files::text("complete"))
    .set("backup_path", files::text(backup))
    .set("managed_servers", str_list(&names(fields, "managed")?))
    .set("migrated_proxy_servers", str_list(&migrated))
    .set(
        "runtime_restart_required",
        PyVal::Bool(!migrated.is_empty()),
    )
    .set("skipped_servers", str_list(&skipped))
    .set(
        "source_config_paths",
        str_list(&names(fields, "source_config_paths")?),
    );
    files::manifest_answer(doc)
}

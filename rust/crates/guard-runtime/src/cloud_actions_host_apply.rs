//! Write, and put back, the one settings entry that adds Cloud actions to an AI tool.
//!
//! `apply` writes the file a preview rendered, and only if the file still
//! holds the bytes that preview read: AI tools such as Claude Code rewrite
//! their settings while they run, and a change made after the preview must not
//! be overwritten. Before writing it keeps a copy of the previous file in the
//! Guard home. The new file is written beside the old one and moved into place
//! in one step, then read back; if it does not read back as rendered, the
//! previous file is put back.
//!
//! `restore` undoes the most recent write for an AI tool. While the file still
//! holds exactly what Guard wrote, the earlier copy is put back as it was. AI
//! tools change their own settings files as they run, so when the file has
//! changed since, only Guard's entry is put back as it was (or removed) and
//! everything else edited since stays; if Guard's entry itself was changed,
//! nothing is touched.
//!
//! A settings file that is a link is refused: Guard would otherwise write
//! wherever the link points. The same module answers where each AI tool keeps
//! its settings file and reads that file for the preview.

use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};

use serde::Deserialize;
use serde_json::{json, Map, Value};

use super::cloud_actions_host_config::{plan_text, supports};
use crate::aibom_paths::py_path;
use crate::aibom_skill_rules::expanduser;

#[path = "cloud_actions_host_apply_files.rs"]
mod files;
#[path = "cloud_actions_host_apply_records.rs"]
mod records;
#[path = "cloud_actions_host_apply_restore.rs"]
mod restoring;

use self::files::{
    changed_since_preview, file_mode, read_bounded, refuse_link, remove_if_present, sha256_hex,
    strerror, sync_directory, Failure, Ops, Real, WriteError, NEW_FILE_MODE,
};
use self::records::{
    backups_dir, discard_backup, interrupted, prune_backups, record_left_behind, restore_mode,
    save_backup, Backup, Saved,
};
use self::restoring::restore;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SettingsPathRequest {
    #[allow(dead_code)]
    op: String,
    ai_tool: String,
    home: String,
    environ: Option<HashMap<String, String>>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PlanFileRequest {
    #[allow(dead_code)]
    op: String,
    ai_tool: String,
    path: String,
    entry: Value,
    url: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ApplyRequest {
    #[allow(dead_code)]
    op: String,
    ai_tool: String,
    path: String,
    guard_home: String,
    entry: Value,
    action: String,
    before_sha256: Option<String>,
    after: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RestoreRequest {
    #[allow(dead_code)]
    op: String,
    ai_tool: String,
    path: String,
    guard_home: String,
}

/// The answer to one of the settings-file ops; `None` when the request is not
/// one this module understands.
pub(crate) fn answer(op: &str, request: Value) -> Option<Value> {
    match op {
        "settings_path" => settings_path_answer(serde_json::from_value(request).ok()?),
        "plan_file" => plan_file_answer(serde_json::from_value(request).ok()?),
        "apply" => apply_answer(serde_json::from_value(request).ok()?),
        "restore" => restore_answer(serde_json::from_value(request).ok()?),
        _ => None,
    }
}

fn absolute_path(text: &str) -> Option<PathBuf> {
    Path::new(text).is_absolute().then(|| PathBuf::from(text))
}

fn error_answer(error: &WriteError) -> Value {
    json!({"error": {"reason": error.reason, "message": error.message}})
}

/// `str.strip()`: Python also trims the information separators.
fn python_strip(value: &str) -> &str {
    value.trim_matches(|character: char| {
        character.is_whitespace() || ('\u{1c}'..='\u{1f}').contains(&character)
    })
}

/// The user-level settings file the AI tool reads its MCP servers from.
///
/// `environ` is `None` when the caller named the home folder explicitly; the
/// AI tool's own home variables are then ignored.
fn settings_path_answer(request: SettingsPathRequest) -> Option<Value> {
    supports(&request.ai_tool).then_some(())?;
    let home = py_path(&request.home);
    let variable = |name: &str| {
        request
            .environ
            .as_ref()
            .and_then(|environ| environ.get(name))
            .map_or("", |value| python_strip(value))
    };
    let path = match request.ai_tool.as_str() {
        "claude-code" => match variable("CLAUDE_CONFIG_DIR") {
            "" => home.join(".claude.json"),
            base => expanduser(base, Some(request.home.as_str())).join(".claude.json"),
        },
        "codex" => match variable("CODEX_HOME") {
            "" => home.join(".codex").join("config.toml"),
            base => expanduser(base, Some(request.home.as_str())).join("config.toml"),
        },
        _ => home.join(".cursor").join("mcp.json"),
    };
    Some(json!({"path": path.to_string_lossy()}))
}

/// Read the settings file, bounded, and work out the change to it; never writes.
fn plan_file_answer(request: PlanFileRequest) -> Option<Value> {
    supports(&request.ai_tool).then_some(())?;
    let unreadable = |problem: &str| {
        json!({
            "action": "unreadable",
            "other_entries": 0,
            "previous_url": null,
            "configured_as": [],
            "problem": problem,
            "after": null,
            "before_sha256": null,
        })
    };
    let before = match read_bounded(&absolute_path(&request.path)?) {
        Ok(before) => before,
        Err(problem) => return Some(unreadable(&problem)),
    };
    let text = match before.as_deref().map(std::str::from_utf8) {
        Some(Err(_)) => return Some(unreadable("The settings file is not UTF-8 text.")),
        Some(Ok(text)) => Some(text),
        None => None,
    };
    let mut answer = plan_text(&request.ai_tool, text, &request.entry, &request.url)?;
    answer["before_sha256"] = json!(before.as_deref().map(sha256_hex));
    Some(answer)
}

/// What one `apply` is asked to write.
struct ApplyPlan<'a> {
    ai_tool: &'a str,
    path: &'a Path,
    guard_home: &'a Path,
    entry: &'a Map<String, Value>,
    replaced_entry: bool,
    before_sha256: Option<&'a str>,
    after: &'a [u8],
}

fn apply_answer(request: ApplyRequest) -> Option<Value> {
    supports(&request.ai_tool).then_some(())?;
    let replaced_entry = match request.action.as_str() {
        "update" => true,
        "create_file" | "add" => false,
        _ => return None,
    };
    let path = absolute_path(&request.path)?;
    let guard_home = absolute_path(&request.guard_home)?;
    let entry = request.entry.as_object()?;
    let plan = ApplyPlan {
        ai_tool: &request.ai_tool,
        path: &path,
        guard_home: &guard_home,
        entry,
        replaced_entry,
        before_sha256: request.before_sha256.as_deref(),
        after: request.after.as_bytes(),
    };
    Some(match apply(&Real, &plan) {
        Ok(()) => json!({"ok": true}),
        Err(error) => error_answer(&error),
    })
}

fn restore_answer(request: RestoreRequest) -> Option<Value> {
    supports(&request.ai_tool).then_some(())?;
    let path = absolute_path(&request.path)?;
    let guard_home = absolute_path(&request.guard_home)?;
    Some(match restore(&Real, &request.ai_tool, &path, &guard_home) {
        Ok(None) => json!({"restored": null}),
        Ok(Some(restored)) => json!({"restored": {
            "removed_file": restored.removed_file,
            "scope": restored.scope,
            "entry_removed": restored.entry_removed,
        }}),
        Err(error) => error_answer(&error),
    })
}

/// How a failed step reads to the person running the command.
pub(in crate::cloud_actions_host_apply) fn settle(path: &Path, failure: Failure) -> WriteError {
    match failure {
        Failure::Write(error) => error,
        Failure::Io(error) => WriteError::new(
            "write_failed",
            format!(
                "{} could not be written ({}).",
                path.display(),
                strerror(&error)
            ),
        ),
        Failure::Interrupt => interrupted(),
    }
}

fn holds(ops: &dyn Ops, path: &Path, payload: Option<&[u8]>) -> bool {
    matches!(ops.read(path), Ok(read) if read.as_deref() == payload)
}

/// Whether Guard's own file reached `path`.
struct Landing {
    published: bool,
    /// True, false, or `None` when that cannot be told.
    moved: Option<bool>,
}

/// Write `plan.after` to `plan.path` if the file is still as previewed.
fn apply(ops: &dyn Ops, plan: &ApplyPlan<'_>) -> Result<(), WriteError> {
    let path = plan.path;
    refuse_link(path)?;
    let current = ops.read(path).map_err(|failure| settle(path, failure))?;
    if current.as_deref().map(sha256_hex).as_deref() != plan.before_sha256 {
        return Err(changed_since_preview(path));
    }
    let mode = match current.as_ref() {
        Some(_) => Some(file_mode(path).map_err(|error| {
            WriteError::new(
                "unreadable",
                format!(
                    "{} could not be read ({}).",
                    path.display(),
                    strerror(&error)
                ),
            )
        })?),
        None => None,
    };
    let before = current.as_deref();
    let backup = save_backup(
        ops,
        plan.guard_home,
        &Saved {
            ai_tool: plan.ai_tool,
            path,
            entry: plan.entry,
            replaced_entry: plan.replaced_entry,
            mode,
            before,
            after: plan.after,
        },
    )?;
    let mut landing = Landing {
        published: false,
        moved: Some(false),
    };
    let Err(failure) = write_file(ops, plan, before, mode, &mut landing) else {
        prune_backups(&backups_dir(plan.guard_home, plan.ai_tool));
        return Ok(());
    };
    // An interrupt can land after the move but before it was noted; the file
    // then holds Guard's settings and must be put back too. Matching bytes
    // alone are not proof, since another apply may have written them.
    let mut landed = if landing.published {
        Some(true)
    } else {
        landing.moved
    };
    if landed.is_none() && holds(ops, path, before) {
        // Whether the move happened is unknown, but the file is as it was (or
        // still absent), so there is nothing to put back.
        landed = Some(false);
    }
    let expected = if landing.published {
        None
    } else {
        Some(plan.after)
    };
    let undone = (landed == Some(true)).then(|| put_back(ops, &backup, before, expected));
    match undone {
        // Changed again since Guard's move: leave it, and keep the copy.
        Some(PutBack::Changed) => landed = None,
        Some(PutBack::Failed) => {
            // The copy is the only way back now, so it stays for `restore`, and
            // the record now names what is on disk so restore puts the whole
            // file back.
            record_left_behind(ops, &backup);
            return Err(WriteError::new(
                "put_back_failed",
                format!(
                    "{} did not read back as written, and Guard could not put the earlier file back. \
                     Guard kept its copy; run `hol-guard cloud-actions ai-tools restore {}`.",
                    path.display(),
                    plan.ai_tool
                ),
            ));
        }
        Some(PutBack::Done) | None => {}
    }
    // When Guard cannot tell what is on disk now (landed is None), the copy
    // stays for `restore`. Its record still names Guard's own bytes, so
    // `restore` puts the whole file back only if it still holds them and
    // otherwise removes just Guard's entry, keeping the later edit.
    if landed.is_some() {
        discard_backup(&backup);
    }
    Err(settle(path, failure))
}

fn write_file(
    ops: &dyn Ops,
    plan: &ApplyPlan<'_>,
    before: Option<&[u8]>,
    mode: Option<u32>,
    landing: &mut Landing,
) -> Result<(), Failure> {
    let path = plan.path;
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    fs::create_dir_all(parent)?;
    let create = before.is_none();
    let temporary = ops.write_temporary(path, plan.after, mode.unwrap_or(NEW_FILE_MODE))?;
    // Read again right before the move: the window for a lost edit is the move itself.
    let published = match ops.read(path) {
        Ok(read) if read.as_deref() == before => publish(ops, &temporary, path, create),
        Ok(_) => Err(changed_since_preview(path).into()),
        Err(failure) => Err(failure),
    };
    if published.is_ok() {
        landing.published = true;
    } else {
        landing.moved = ops.moved(&temporary, path, create);
    }
    let _ = remove_if_present(&temporary);
    published?;
    sync_directory(parent);
    if ops.read(path)?.as_deref() != Some(plan.after) {
        return Err(WriteError::new(
            "write_not_verified",
            format!("{} did not read back as written.", path.display()),
        )
        .into());
    }
    Ok(())
}

pub(in crate::cloud_actions_host_apply) fn publish(
    ops: &dyn Ops,
    temporary: &Path,
    path: &Path,
    create: bool,
) -> Result<(), Failure> {
    if !create {
        return ops.replace(temporary, path);
    }
    // A hard link fails if the file appeared since the check, so a file
    // another program just created is never replaced. Without hard links
    // there is no such guarantee, so nothing is written.
    match ops.link(temporary, path) {
        Err(Failure::Io(error)) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            Err(changed_since_preview(path).into())
        }
        Err(Failure::Io(error)) => Err(WriteError::new(
            "write_failed",
            format!(
                "{} could not be created safely ({}), so nothing was written. \
                 Add the entry yourself from the preview.",
                path.display(),
                strerror(&error)
            ),
        )
        .into()),
        other => other,
    }
}

enum PutBack {
    Done,
    /// The file is no longer what Guard wrote, so it was left alone.
    Changed,
    /// The put-back could not be confirmed.
    Failed,
}

/// Put the previewed file back. With `expected`, the file must still hold
/// exactly those bytes right before it is replaced; otherwise it is left alone.
fn put_back(
    ops: &dyn Ops,
    backup: &Backup,
    before: Option<&[u8]>,
    expected: Option<&[u8]>,
) -> PutBack {
    let path = backup.path.as_path();
    let still_expected = || -> Result<bool, Failure> {
        Ok(expected.is_none() || ops.read(path)?.as_deref() == expected)
    };
    let attempt = || -> Result<PutBack, Failure> {
        match before {
            None => {
                if !still_expected()? {
                    return Ok(PutBack::Changed);
                }
                remove_if_present(path)?;
            }
            Some(before) => {
                let temporary = ops.write_temporary(path, before, restore_mode(backup.mode))?;
                let moved = match still_expected() {
                    // Read again right before the replace, so a later edit is never lost.
                    Ok(true) => ops.replace(&temporary, path).map(|()| true),
                    Ok(false) => Ok(false),
                    Err(failure) => Err(failure),
                };
                let _ = remove_if_present(&temporary);
                if !moved? {
                    return Ok(PutBack::Changed);
                }
            }
        }
        sync_parent(path);
        Ok(if ops.read(path)?.as_deref() == before {
            PutBack::Done
        } else {
            PutBack::Failed
        })
    };
    attempt().unwrap_or(PutBack::Failed)
}

pub(super) fn sync_parent(path: &Path) {
    if let Some(parent) = path.parent() {
        sync_directory(parent);
    }
}

#[cfg(test)]
#[path = "cloud_actions_host_apply_tests.rs"]
mod tests;

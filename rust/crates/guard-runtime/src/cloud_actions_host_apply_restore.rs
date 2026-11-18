//! Undo Guard's most recent write to an AI tool's settings file.

use std::fs;
use std::path::Path;

use serde_json::Value;

use super::files::{
    changed_since_preview, file_mode, refuse_link, remove_if_present, sha256_hex, strerror,
    Failure, Ops, WriteError,
};
use super::records::{
    backups_dir, discard_backup, latest_backup, read_copy, restore_mode, Backup, ABSENT,
};
use super::{publish, settle, sync_parent};
use crate::cloud_actions_host_config::undo_text;

#[derive(Debug)]
pub(super) struct Restored {
    pub(super) removed_file: bool,
    /// "file" when the whole earlier file was put back, "entry" when only Guard's entry was.
    pub(super) scope: &'static str,
    pub(super) entry_removed: bool,
}

/// Undo Guard's most recent write to `path`; `None` when there is nothing to undo.
pub(super) fn restore(
    ops: &dyn Ops,
    ai_tool: &str,
    path: &Path,
    guard_home: &Path,
) -> Result<Option<Restored>, WriteError> {
    let Some(backup) = latest_backup(&backups_dir(guard_home, ai_tool), path)? else {
        return Ok(None);
    };
    refuse_link(path)?;
    let current = ops.read(path).map_err(|failure| settle(path, failure))?;
    let before = read_copy(&backup)?;
    let restored = put_back_file(ops, &backup, path, current.as_deref(), before.as_deref())
        .map_err(|failure| match failure {
            Failure::Io(error) => WriteError::new(
                "write_failed",
                format!(
                    "{} could not be put back ({}).",
                    path.display(),
                    strerror(&error)
                ),
            ),
            other => settle(path, other),
        })?;
    discard_backup(&backup);
    Ok(Some(restored))
}

fn put_back_file(
    ops: &dyn Ops,
    backup: &Backup,
    path: &Path,
    current: Option<&[u8]>,
    before: Option<&[u8]>,
) -> Result<Restored, Failure> {
    let whole = |removed_file: bool| Restored {
        removed_file,
        scope: "file",
        entry_removed: !backup.replaced_entry,
    };
    if current.is_none() && backup.after_sha256 == ABSENT {
        // A failed write removed the file; recreate the earlier one.
        if let Some(before) = before {
            let temporary = ops.write_temporary(path, before, restore_mode(backup.mode))?;
            let published = publish(ops, &temporary, path, true);
            let _ = remove_if_present(&temporary);
            published?;
            sync_parent(path);
        }
        return Ok(whole(false));
    }
    if let Some(current) = current.filter(|bytes| sha256_hex(bytes) == backup.after_sha256) {
        match before {
            None => {
                if ops.read(path)?.as_deref() != Some(current) {
                    return Err(changed_since_preview(path).into());
                }
                fs::remove_file(path)?;
                sync_parent(path);
            }
            Some(before) => {
                write_exact(ops, path, before, restore_mode(backup.mode), current)?;
            }
        }
        return Ok(whole(before.is_none()));
    }
    undo_entry(ops, backup, current, before)
}

/// Put back only Guard's entry in a file the AI tool or the user has changed since.
fn undo_entry(
    ops: &dyn Ops,
    backup: &Backup,
    current: Option<&[u8]>,
    before: Option<&[u8]>,
) -> Result<Restored, Failure> {
    let path = backup.path.as_path();
    let changed = || {
        Failure::Write(WriteError::new(
            "changed_since_apply",
            format!(
                "The hol-guard-cloud entry in {} changed after Guard wrote it, so Guard will not change it. \
                 Edit or remove that entry yourself if you no longer want it.",
                path.display()
            ),
        ))
    };
    let current = current.ok_or_else(changed)?;
    let current_text = std::str::from_utf8(current).map_err(|_| changed())?;
    let prior_text = before
        .map(|bytes| std::str::from_utf8(bytes).map_err(|_| changed()))
        .transpose()?;
    let written = Value::Object(backup.entry.clone());
    let (restored, entry_removed) = undo_text(&backup.ai_tool, current_text, &written, prior_text)
        .and_then(Result::ok)
        .ok_or_else(changed)?;
    write_exact(ops, path, restored.as_bytes(), file_mode(path)?, current)?;
    Ok(Restored {
        removed_file: false,
        scope: "entry",
        entry_removed,
    })
}

fn write_exact(
    ops: &dyn Ops,
    path: &Path,
    payload: &[u8],
    mode: u32,
    expected: &[u8],
) -> Result<(), Failure> {
    let temporary = ops.write_temporary(path, payload, mode)?;
    let moved = match ops.read(path) {
        Ok(read) if read.as_deref() == Some(expected) => ops.replace(&temporary, path),
        Ok(_) => Err(changed_since_preview(path).into()),
        Err(failure) => Err(failure),
    };
    let _ = remove_if_present(&temporary);
    moved?;
    sync_parent(path);
    Ok(())
}

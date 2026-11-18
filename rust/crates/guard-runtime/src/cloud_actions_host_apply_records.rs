//! The copy of an AI tool's settings file that Guard keeps before it writes,
//! and the record that says what Guard changed.
//!
//! Each write leaves `<time>-<pid>.before` (the earlier file, when there was
//! one) and `<time>-<pid>.json` (the record) under the Guard home. `restore`
//! finds the newest record for a file and puts back what the record names.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use serde_json::{json, Map, Value};

use super::files::{
    absolute, private_dir, remove_if_present, sha256_hex, strerror, sync_directory, Failure, Ops,
    WriteError, NEW_FILE_MODE,
};

const BACKUP_FORMAT: &str = "guard.cloud-actions.settings-backup.v1";
pub(super) const KEEP_BACKUPS: usize = 10;
/// Recorded as `after_sha256` when Guard's failed write left no file behind.
pub(super) const ABSENT: &str = "absent";

/// What Guard changed in one settings file, and the copy that undoes it.
pub(super) struct Backup {
    pub(super) ai_tool: String,
    pub(super) path: PathBuf,
    pub(super) entry: Map<String, Value>,
    pub(super) replaced_entry: bool,
    pub(super) existed: bool,
    pub(super) mode: Option<u32>,
    pub(super) before_sha256: Option<String>,
    pub(super) after_sha256: String,
    pub(super) record_file: PathBuf,
    pub(super) copy_file: Option<PathBuf>,
}

pub(super) fn backups_dir(guard_home: &Path, ai_tool: &str) -> PathBuf {
    guard_home
        .join("cloud-actions")
        .join("settings-backups")
        .join(ai_tool)
}

/// The mode a file Guard puts back is given: the recorded one, or owner-only.
pub(super) fn restore_mode(mode: Option<u32>) -> u32 {
    mode.filter(|mode| *mode != 0).unwrap_or(NEW_FILE_MODE)
}

pub(super) struct Saved<'a> {
    pub(super) ai_tool: &'a str,
    pub(super) path: &'a Path,
    pub(super) entry: &'a Map<String, Value>,
    pub(super) replaced_entry: bool,
    pub(super) mode: Option<u32>,
    pub(super) before: Option<&'a [u8]>,
    pub(super) after: &'a [u8],
}

pub(super) fn save_backup(
    ops: &dyn Ops,
    guard_home: &Path,
    saved: &Saved<'_>,
) -> Result<Backup, WriteError> {
    let directory = backups_dir(guard_home, saved.ai_tool);
    let kept = || -> Result<Backup, Failure> {
        private_dir(&directory)?;
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |elapsed| elapsed.as_nanos());
        let stem = format!("{nanos:020}-{}", std::process::id());
        let copy_file = match saved.before {
            Some(before) => {
                let copy_file = directory.join(format!("{stem}.before"));
                write_private(ops, &copy_file, before)?;
                Some(copy_file)
            }
            None => None,
        };
        let backup = Backup {
            ai_tool: saved.ai_tool.to_owned(),
            path: absolute(saved.path),
            entry: saved.entry.clone(),
            replaced_entry: saved.replaced_entry,
            existed: saved.before.is_some(),
            mode: saved.mode,
            before_sha256: saved.before.map(sha256_hex),
            after_sha256: sha256_hex(saved.after),
            record_file: directory.join(format!("{stem}.json")),
            copy_file,
        };
        write_record(ops, &backup, &backup.after_sha256)?;
        Ok(backup)
    };
    match kept() {
        Ok(backup) => Ok(backup),
        Err(Failure::Io(error)) => Err(WriteError::new(
            "backup_failed",
            format!(
                "Guard could not keep a copy of {} ({}), so nothing was written.",
                saved.path.display(),
                strerror(&error)
            ),
        )),
        Err(Failure::Write(error)) => Err(error),
        Err(Failure::Interrupt) => Err(interrupted()),
    }
}

pub(super) fn interrupted() -> WriteError {
    WriteError::new(
        "interrupted",
        "Guard was stopped before it finished.".to_owned(),
    )
}

/// Point the kept record at the bytes a failed write left, so `restore`
/// replaces the whole file.
pub(super) fn record_left_behind(ops: &dyn Ops, backup: &Backup) {
    let Ok(on_disk) = ops.read(&backup.path) else {
        return;
    };
    let after = on_disk.map_or_else(|| ABSENT.to_owned(), |bytes| sha256_hex(&bytes));
    let _ = write_record(ops, backup, &after);
}

fn write_record(ops: &dyn Ops, backup: &Backup, after_sha256: &str) -> Result<(), Failure> {
    let record = json!({
        "format": BACKUP_FORMAT,
        "ai_tool": backup.ai_tool,
        "path": backup.path.to_string_lossy(),
        "entry": backup.entry,
        "replaced_entry": backup.replaced_entry,
        "existed": backup.existed,
        "mode": backup.mode,
        "before_sha256": backup.before_sha256,
        "after_sha256": after_sha256,
        "copy": backup.copy_file.as_ref().and_then(|copy| copy.file_name()).map(|name| name.to_string_lossy().into_owned()),
    });
    let mut text = serde_json::to_string(&record).map_err(io::Error::other)?;
    text.push('\n');
    write_private(ops, &backup.record_file, text.as_bytes())
}

fn write_private(ops: &dyn Ops, path: &Path, payload: &[u8]) -> Result<(), Failure> {
    let temporary = ops.write_temporary(path, payload, NEW_FILE_MODE)?;
    let moved = ops.replace(&temporary, path);
    let _ = remove_if_present(&temporary);
    moved?;
    if let Some(parent) = path.parent() {
        sync_directory(parent);
    }
    Ok(())
}

/// Forget the copy and the record of one write.
pub(super) fn discard_backup(backup: &Backup) {
    let _ = remove_if_present(&backup.record_file).and_then(|()| {
        backup
            .copy_file
            .as_deref()
            .map_or(Ok(()), remove_if_present)
    });
}

fn records(directory: &Path) -> Vec<PathBuf> {
    let Ok(entries) = fs::read_dir(directory) else {
        return Vec::new();
    };
    let mut found: Vec<PathBuf> = entries
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .filter(|path| {
            path.extension()
                .is_some_and(|extension| extension == "json")
        })
        .collect();
    found.sort();
    found
}

fn load_backup(record_file: &Path) -> Option<Backup> {
    let raw: Value = serde_json::from_slice(&fs::read(record_file).ok()?).ok()?;
    let raw = raw.as_object()?;
    if raw.get("format").and_then(Value::as_str) != Some(BACKUP_FORMAT) {
        return None;
    }
    let path = raw.get("path")?.as_str()?;
    let entry = recorded_entry(raw)?;
    let after_sha256 = raw.get("after_sha256")?.as_str()?.to_owned();
    let ai_tool = raw.get("ai_tool")?.as_str()?.to_owned();
    let copy_file = match raw.get("copy") {
        None | Some(Value::Null) => None,
        Some(Value::String(name)) if plain_name(name) => Some(
            record_file
                .parent()
                .map_or_else(|| PathBuf::from(name), |parent| parent.join(name)),
        ),
        Some(_) => return None,
    };
    Some(Backup {
        ai_tool,
        path: PathBuf::from(path),
        entry,
        replaced_entry: raw.get("replaced_entry") == Some(&Value::Bool(true)),
        existed: raw.get("existed") == Some(&Value::Bool(true)),
        mode: raw
            .get("mode")
            .and_then(Value::as_u64)
            .filter(|mode| *mode <= 0o7777)
            .and_then(|mode| u32::try_from(mode).ok()),
        before_sha256: raw
            .get("before_sha256")
            .and_then(Value::as_str)
            .map(str::to_owned),
        after_sha256,
        record_file: record_file.to_path_buf(),
        copy_file,
    })
}

/// A file name alone, with no folder in front of it.
fn plain_name(name: &str) -> bool {
    name != "." && !name.contains('/') && !(cfg!(windows) && name.contains('\\'))
}

/// The entry Guard wrote; records from an earlier alpha hold only its address.
fn recorded_entry(raw: &Map<String, Value>) -> Option<Map<String, Value>> {
    match raw.get("entry") {
        Some(Value::Object(entry)) => Some(entry.clone()),
        None | Some(Value::Null) => {
            let url = raw.get("url")?.as_str()?;
            let mut entry = Map::new();
            entry.insert("url".to_owned(), json!(url));
            Some(entry)
        }
        Some(_) => None,
    }
}

/// The newest record that names `path`.
pub(super) fn latest_backup(directory: &Path, path: &Path) -> Result<Option<Backup>, WriteError> {
    let wanted = absolute(path);
    for record_file in records(directory).into_iter().rev() {
        let Some(backup) = load_backup(&record_file) else {
            // A newer record that cannot be read may be the change to undo.
            return Err(WriteError::new(
                "backup_unreadable",
                format!(
                    "Guard's record {} is damaged, so nothing was changed. \
                     Check that file, or remove it to undo earlier changes.",
                    record_file.display()
                ),
            ));
        };
        if absolute(&backup.path) == wanted {
            return Ok(Some(backup));
        }
    }
    Ok(None)
}

/// The earlier file as Guard copied it; `None` when there was none.
pub(super) fn read_copy(backup: &Backup) -> Result<Option<Vec<u8>>, WriteError> {
    if !backup.existed {
        return Ok(None);
    }
    let payload = backup
        .copy_file
        .as_deref()
        .and_then(|copy| fs::read(copy).ok());
    match payload {
        Some(payload) if Some(sha256_hex(&payload)) == backup.before_sha256 => Ok(Some(payload)),
        _ => Err(WriteError::new(
            "backup_unreadable",
            format!(
                "Guard's copy of the earlier {} is missing or damaged, so nothing was changed.",
                backup.path.display()
            ),
        )),
    }
}

/// Keep only the newest copies.
pub(super) fn prune_backups(directory: &Path) {
    let records = records(directory);
    for record_file in &records[..records.len().saturating_sub(KEEP_BACKUPS)] {
        match load_backup(record_file) {
            Some(backup) => discard_backup(&backup),
            None => {
                let _ = fs::remove_file(record_file);
            }
        }
    }
}

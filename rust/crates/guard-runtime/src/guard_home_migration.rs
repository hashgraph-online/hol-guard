//! Moving a legacy Guard home into the canonical one: the legacy tree is
//! copied into a private staging folder beside the canonical home, which is
//! then renamed into place. `guard.db` moves through SQLite's online backup,
//! never a raw copy, and a linked folder is never followed.

use std::fs;
use std::path::Path;
use std::thread;
use std::time::{Duration, Instant};

use rusqlite::backup::{Backup, StepResult};
use rusqlite::Connection;

use super::{has_state, has_sync_credentials, open_read_only, NON_MIGRATED_FILES};

/// How long one `guard.db` backup may take before the move is abandoned.
const BACKUP_TIMEOUT: Duration = Duration::from_secs(5);
/// How long to wait before retrying a backup step that found the source busy.
const BACKUP_RETRY_PAUSE: Duration = Duration::from_millis(50);
const BACKUP_PAGES_PER_STEP: i32 = 128;

/// The move did not finish; the legacy home stays in use.
#[derive(Debug, PartialEq, Eq)]
pub(super) struct Failed;

impl From<std::io::Error> for Failed {
    fn from(_: std::io::Error) -> Self {
        Self
    }
}

impl From<rusqlite::Error> for Failed {
    fn from(_: rusqlite::Error) -> Self {
        Self
    }
}

/// Replace `destination` with a copy of `source`, or leave it untouched.
pub(super) fn migrate_transactionally(source: &Path, destination: &Path) -> Result<(), Failed> {
    let parent = destination.parent().ok_or(Failed)?;
    let name = destination.file_name().ok_or(Failed)?;
    fs::create_dir_all(parent)?;
    let staging = tempfile::Builder::new()
        .prefix(&format!("{}-migration-", name.to_string_lossy()))
        .tempdir_in(parent)?;
    let staged = staging.path().join(name);
    migrate_state(source, &staged, BACKUP_TIMEOUT)?;
    if destination.exists() {
        refuse_live_database_logs(destination)?;
        fs::remove_dir_all(destination)?;
    }
    fs::rename(&staged, destination)?;
    Ok(())
}

/// Merge `source` into `destination`, skipping live process files. An
/// existing `guard.db` and `secrets` folder are replaced only when the
/// destination holds no state of its own.
pub(super) fn migrate_state(
    source: &Path,
    destination: &Path,
    timeout: Duration,
) -> Result<(), Failed> {
    if !source.exists() {
        return Ok(());
    }
    fs::create_dir_all(destination)?;
    let replace_database = !has_sync_credentials(destination) && !has_state(destination);
    for entry in fs::read_dir(source)? {
        let entry = entry?;
        let file_name = entry.file_name();
        let name = file_name.to_string_lossy();
        if NON_MIGRATED_FILES.contains(&&*name) {
            continue;
        }
        let from = entry.path();
        let target = destination.join(&file_name);
        let is_folder = entry.file_type()?.is_dir();
        if target.exists() {
            if replace_database && name == "secrets" && is_folder && target.is_dir() {
                fs::remove_dir_all(&target)?;
                copy_tree(&from, &target)?;
            } else if is_folder && target.is_dir() {
                migrate_state(&from, &target, timeout)?;
            } else if replace_database && name == "guard.db" && from.is_file() {
                copy_database(&from, &target, timeout)?;
            }
            continue;
        }
        if is_folder {
            copy_tree(&from, &target)?;
        } else if name == "guard.db" && from.is_file() {
            copy_database(&from, &target, timeout)?;
        } else {
            fs::copy(&from, &target)?;
        }
    }
    Ok(())
}

/// Never swap `guard.db` out from under a non-empty WAL or rollback journal:
/// a later checkpoint of the old log would write stale pages into the new
/// database, and another Guard process may still hold the old files open.
fn refuse_live_database_logs(destination: &Path) -> Result<(), Failed> {
    for log in ["guard.db-wal", "guard.db-journal"] {
        let path = destination.join(log);
        if path.is_file() && fs::metadata(&path)?.len() > 0 {
            return Err(Failed);
        }
    }
    Ok(())
}

fn copy_tree(source: &Path, destination: &Path) -> Result<(), Failed> {
    fs::create_dir(destination)?;
    for entry in fs::read_dir(source)? {
        let entry = entry?;
        let target = destination.join(entry.file_name());
        if entry.file_type()?.is_dir() {
            copy_tree(&entry.path(), &target)?;
        } else {
            fs::copy(entry.path(), &target)?;
        }
    }
    fs::set_permissions(destination, fs::metadata(source)?.permissions())?;
    Ok(())
}

/// Back `source` up into a sibling of `destination`, drop retired sync
/// credentials from the copy, and rename it into place.
pub(super) fn copy_database(
    source: &Path,
    destination: &Path,
    timeout: Duration,
) -> Result<(), Failed> {
    let name = destination.file_name().ok_or(Failed)?;
    if let Some(parent) = destination.parent() {
        fs::create_dir_all(parent)?;
    }
    let temporary = destination.with_file_name(format!("{}.migrating", name.to_string_lossy()));
    let copied = backup_into(source, &temporary, timeout).and_then(|()| {
        prune_retired_sync_credentials(&temporary);
        fs::rename(&temporary, destination).map_err(Failed::from)
    });
    if copied.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    copied
}

fn backup_into(source: &Path, temporary: &Path, timeout: Duration) -> Result<(), Failed> {
    let deadline = Instant::now() + timeout;
    let from = open_read_only(source)?;
    let mut to = Connection::open(temporary)?;
    let backup = Backup::new(&from, &mut to)?;
    loop {
        match backup.step(BACKUP_PAGES_PER_STEP)? {
            StepResult::Done => return Ok(()),
            StepResult::More => {}
            _ => thread::sleep(BACKUP_RETRY_PAUSE),
        }
        if Instant::now() >= deadline {
            return Err(Failed);
        }
    }
}

fn prune_retired_sync_credentials(database: &Path) {
    if let Ok(connection) = Connection::open(database) {
        let _ = connection.execute("delete from sync_state where state_key = 'credentials'", []);
    }
}

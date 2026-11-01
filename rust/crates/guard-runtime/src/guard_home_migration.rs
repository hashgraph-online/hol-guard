//! Moving a legacy Guard home into the canonical one: the legacy tree is
//! copied into a private staging folder beside the canonical home, which is
//! then renamed into place. `guard.db` moves through SQLite's online backup,
//! never a raw copy. A linked entry is copied as what it points to, as
//! `shutil.copytree` did.
//!
//! The whole move has a deadline well inside the 30 seconds `config.py`
//! gives the runtime, so a slow move gives up and removes its staging folder
//! instead of being killed with key and database copies left behind. A
//! staging folder that a killed runtime left anyway is removed by the next
//! move once it is clearly abandoned.

use std::fs;
use std::path::Path;
use std::thread;
use std::time::{Duration, Instant, SystemTime};

use rusqlite::backup::{Backup, StepResult};
use rusqlite::Connection;

use super::{has_state, has_sync_credentials, open_read_only, NON_MIGRATED_FILES};

/// How long one whole move may take before it is abandoned.
const MOVE_TIMEOUT: Duration = Duration::from_secs(20);
/// How long one `guard.db` backup may take before the move is abandoned.
const BACKUP_TIMEOUT: Duration = Duration::from_secs(5);
/// A staging folder this old belongs to no running move.
const ABANDONED_STAGING_AGE: Duration = Duration::from_secs(10 * 60);
/// Linked folders can form a cycle; no real Guard home nests this deep.
const MAX_DEPTH: usize = 32;
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
    migrate_before(source, destination, Instant::now() + MOVE_TIMEOUT)
}

pub(super) fn migrate_before(
    source: &Path,
    destination: &Path,
    deadline: Instant,
) -> Result<(), Failed> {
    let parent = destination.parent().ok_or(Failed)?;
    let name = destination.file_name().ok_or(Failed)?;
    fs::create_dir_all(parent)?;
    let prefix = format!("{}-migration-", name.to_string_lossy());
    remove_abandoned_staging(parent, &prefix);
    let staging = tempfile::Builder::new()
        .prefix(&prefix)
        .tempdir_in(parent)?;
    let staged = staging.path().join(name);
    migrate_state(source, &staged, deadline)?;
    expire(deadline)?;
    if destination.exists() {
        refuse_live_database_logs(destination)?;
        fs::remove_dir_all(destination)?;
    }
    fs::rename(&staged, destination)?;
    Ok(())
}

/// Remove staging folders a killed move left beside the canonical home.
fn remove_abandoned_staging(parent: &Path, prefix: &str) {
    let Ok(entries) = fs::read_dir(parent) else {
        return;
    };
    for entry in entries.flatten() {
        let abandoned = entry.file_name().to_string_lossy().starts_with(prefix)
            && entry.file_type().is_ok_and(|kind| kind.is_dir())
            && entry
                .metadata()
                .and_then(|metadata| metadata.modified())
                .is_ok_and(|modified| {
                    SystemTime::now()
                        .duration_since(modified)
                        .is_ok_and(|age| age >= ABANDONED_STAGING_AGE)
                });
        if abandoned {
            let _ = fs::remove_dir_all(entry.path());
        }
    }
}

fn expire(deadline: Instant) -> Result<(), Failed> {
    if Instant::now() >= deadline {
        return Err(Failed);
    }
    Ok(())
}

/// Merge `source` into `destination`, skipping live process files. An
/// existing `guard.db` and `secrets` folder are replaced only when the
/// destination holds no state of its own.
pub(super) fn migrate_state(
    source: &Path,
    destination: &Path,
    deadline: Instant,
) -> Result<(), Failed> {
    if !source.exists() {
        return Ok(());
    }
    fs::create_dir_all(destination)?;
    let replace_database = !has_sync_credentials(destination) && !has_state(destination);
    for entry in fs::read_dir(source)? {
        let entry = entry?;
        expire(deadline)?;
        let file_name = entry.file_name();
        let name = file_name.to_string_lossy();
        if NON_MIGRATED_FILES.contains(&&*name) {
            continue;
        }
        let from = entry.path();
        let target = destination.join(&file_name);
        let is_folder = fs::metadata(&from)?.is_dir();
        let backup_deadline = deadline.min(Instant::now() + BACKUP_TIMEOUT);
        if target.exists() {
            if replace_database && name == "secrets" && is_folder && target.is_dir() {
                fs::remove_dir_all(&target)?;
                copy_tree(&from, &target, deadline, 0)?;
            } else if is_folder && target.is_dir() {
                migrate_state(&from, &target, deadline)?;
            } else if replace_database && name == "guard.db" && from.is_file() {
                copy_database(&from, &target, backup_deadline)?;
            }
            continue;
        }
        if is_folder {
            copy_tree(&from, &target, deadline, 0)?;
        } else if name == "guard.db" && from.is_file() {
            copy_database(&from, &target, backup_deadline)?;
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

fn copy_tree(
    source: &Path,
    destination: &Path,
    deadline: Instant,
    depth: usize,
) -> Result<(), Failed> {
    if depth >= MAX_DEPTH {
        return Err(Failed);
    }
    fs::create_dir(destination)?;
    for entry in fs::read_dir(source)? {
        let entry = entry?;
        expire(deadline)?;
        let target = destination.join(entry.file_name());
        if fs::metadata(entry.path())?.is_dir() {
            copy_tree(&entry.path(), &target, deadline, depth + 1)?;
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
    deadline: Instant,
) -> Result<(), Failed> {
    let name = destination.file_name().ok_or(Failed)?;
    if let Some(parent) = destination.parent() {
        fs::create_dir_all(parent)?;
    }
    let temporary = destination.with_file_name(format!("{}.migrating", name.to_string_lossy()));
    let copied = backup_into(source, &temporary, deadline).and_then(|()| {
        prune_retired_sync_credentials(&temporary);
        fs::rename(&temporary, destination).map_err(Failed::from)
    });
    if copied.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    copied
}

/// A step that finishes after `deadline` still abandons the copy.
fn backup_into(source: &Path, temporary: &Path, deadline: Instant) -> Result<(), Failed> {
    let from = open_read_only(source)?;
    let mut to = Connection::open(temporary)?;
    let backup = Backup::new(&from, &mut to)?;
    loop {
        let step = backup.step(BACKUP_PAGES_PER_STEP)?;
        expire(deadline)?;
        match step {
            StepResult::Done => return Ok(()),
            StepResult::More => {}
            _ => thread::sleep(BACKUP_RETRY_PAUSE),
        }
    }
}

fn prune_retired_sync_credentials(database: &Path) {
    if let Ok(connection) = Connection::open(database) {
        let _ = connection.execute("delete from sync_state where state_key = 'credentials'", []);
    }
}

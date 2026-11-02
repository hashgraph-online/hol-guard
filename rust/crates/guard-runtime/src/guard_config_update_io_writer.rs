use super::*;
use std::fs::File;
use std::io::Write;

#[path = "guard_config_update_catalog_io.rs"]
pub(super) mod catalog;
#[path = "guard_config_update_dir.rs"]
mod dir;
#[path = "guard_config_update_lifecycle_io.rs"]
pub(super) mod lifecycle;
#[path = "guard_config_update_staging.rs"]
mod staging;

pub(crate) use dir::Node;
use dir::{Dir, How, Kind, Locked, Names};

const LOCK_NAME: &str = "config-write.lock";
fn failure(code: &str) -> Failure {
    Failure::Error(code.into())
}
#[cfg(test)]
thread_local! { pub(super) static AFTER_RENAME_FAULT: std::cell::Cell<bool> = const { std::cell::Cell::new(false) }; }

#[cfg(all(test, unix))]
pub(crate) fn fail_next_config_write_after_rename() {
    AFTER_RENAME_FAULT.with(|fault| fault.set(true));
}

/// The identity [`WriteLock::root_identity`] reports for `home`, read
/// without taking the writer lock.
pub(crate) fn root_identity_of(home: &Path) -> Result<Node, Failure> {
    let canonical = fs::canonicalize(home).map_err(|_| failure("config_directory_unavailable"))?;
    Dir::open(&canonical)
        .and_then(|d| d.entry())
        .map(|entry| entry.node)
        .map_err(|_| failure("config_directory_changed"))
}

pub(crate) struct WriteLock {
    home: PathBuf,
    canonical: PathBuf,
    directory: Dir,
    lock: Locked,
}
impl WriteLock {
    pub(crate) fn root_identity(&self) -> Result<Node, Failure> {
        self.check()?;
        let entry = self
            .directory
            .entry()
            .map_err(|_| failure("config_directory_changed"))?;
        Ok(entry.node)
    }
    pub(crate) fn acquire(home: &Path) -> Result<Self, Failure> {
        let canonical =
            fs::canonicalize(home).map_err(|_| failure("config_directory_unavailable"))?;
        let directory =
            Dir::open(&canonical).map_err(|_| failure("config_directory_unavailable"))?;
        let entry = directory
            .entry()
            .map_err(|_| failure("config_directory_unavailable"))?;
        if entry.kind != Kind::Directory || !entry.guarded {
            return Err(failure("config_directory_unsafe"));
        }
        let file = directory
            .open_file(LOCK_NAME, How::Lock)
            .map_err(|_| failure("config_lock_unavailable"))?;
        let lock = dir::lock(file).map_err(|_| failure("config_write_busy"))?;
        let result = Self {
            home: home.into(),
            canonical,
            directory,
            lock,
        };
        result.check()?;
        result.recover_staging()?;
        Ok(result)
    }
    fn check(&self) -> Result<(), Failure> {
        let directory = self
            .directory
            .entry()
            .map_err(|_| failure("config_directory_unavailable"))?;
        if fs::canonicalize(&self.home).map_err(|_| failure("config_directory_changed"))?
            != self.canonical
        {
            return Err(failure("config_directory_changed"));
        }
        let current = Dir::open(&self.canonical)
            .and_then(|d| d.entry())
            .map_err(|_| failure("config_directory_changed"))?;
        if directory.node != current.node || current.kind != Kind::Directory || !current.guarded {
            return Err(failure("config_directory_changed"));
        }
        let locked = self
            .directory
            .file_entry(LOCK_NAME, &self.lock)
            .map_err(|_| failure("config_lock_unavailable"))?;
        let path = self
            .directory
            .stat(LOCK_NAME)
            .map_err(|_| failure("config_lock_changed"))?;
        if !locked.private_file()
            || locked.len != 0
            || path.node != locked.node
            || path.kind != Kind::File
        {
            return Err(failure("config_lock_changed"));
        }
        Ok(())
    }
    // Atomic replacement must not bypass an existing config's read-only mode
    // or ACL. Open for writing without truncation before replacing its name.
    fn target_writable(&self, expected: Option<&str>) -> Result<(), Failure> {
        if expected.is_none() {
            return Ok(());
        }
        let file = self
            .directory
            .open_file(HOME_CONFIG_FILENAME, How::Write)
            .map_err(|_| failure("config_file_not_writable"))?;
        let opened = self
            .directory
            .file_entry(HOME_CONFIG_FILENAME, &file)
            .map_err(|_| failure("config_file_not_writable"))?;
        let path = self
            .directory
            .stat(HOME_CONFIG_FILENAME)
            .map_err(|_| failure("config_file_changed"))?;
        if opened.kind != Kind::File
            || opened.links != 1
            || !opened.guarded
            || !opened.writable
            || path.node != opened.node
        {
            return Err(failure("config_file_not_writable"));
        }
        Ok(())
    }
    /// Refuse known write/ACL failures while the existing actor still serves.
    /// The actual publication repeats all checks; this grants no write lease.
    pub(crate) fn preflight(&self, expected: Option<&str>) -> Result<(), Failure> {
        self.check()?;
        if read_home_config(&self.home)?.as_deref() != expected {
            return Err(failure("config_file_changed"));
        }
        self.target_writable(expected)
    }
    /// Unknown outcome after rename is surfaced; callers must inspect current
    /// protected bytes, never replay the write or overwrite a concurrent edit.
    pub(crate) fn publish(&self, expected: Option<&str>, text: &str) -> Result<(), Failure> {
        self.check()?;
        if text.len() > MAX_CONFIG_BYTES || read_home_config(&self.home)?.as_deref() != expected {
            return Err(failure("config_file_changed"));
        }
        self.target_writable(expected)?;
        let mut nonce = [0_u8; 16];
        getrandom::fill(&mut nonce).map_err(|_| failure("config_write_failed"))?;
        let name = format!(
            ".config.toml.{}.{:032x}.tmp",
            std::process::id(),
            u128::from_le_bytes(nonce)
        );
        let mut file = self
            .directory
            .open_file(&name, How::CreateNew)
            .map_err(|_| failure("config_write_failed"))?;
        let created = self
            .directory
            .file_entry(&name, &file)
            .map_err(|_| failure("config_write_failed"))?;
        let written = file
            .write_all(text.as_bytes())
            .and_then(|_| file.sync_all());
        // Windows cannot rename or remove a name that still has an open handle.
        drop(file);
        let result = written
            .map_err(|_| failure("config_write_failed"))
            .and_then(|()| {
                self.check()?;
                if read_home_config(&self.home)?.as_deref() != expected {
                    return Err(failure("config_file_changed"));
                }
                self.target_writable(expected)?;
                let staged = self
                    .directory
                    .stat(&name)
                    .map_err(|_| failure("config_write_failed"))?;
                if staged.node != created.node || !staged.private_file() {
                    return Err(failure("config_write_failed"));
                }
                self.directory
                    .rename(&name, HOME_CONFIG_FILENAME)
                    .map_err(|_| failure("config_write_failed"))?;
                #[cfg(test)]
                if AFTER_RENAME_FAULT.with(|fault| fault.replace(false)) {
                    return Err(failure("config_commit_outcome_unknown"));
                }
                self.directory
                    .sync()
                    .map_err(|_| failure("config_commit_outcome_unknown"))?;
                self.check()
                    .map_err(|_| failure("config_commit_outcome_unknown"))?;
                if read_home_config(&self.home)?.as_deref() != Some(text) {
                    return Err(failure("config_commit_outcome_unknown"));
                }
                Ok(())
            });
        // Remove only our own still-staged file. After a successful rename
        // there is no temporary name, and uncertainty never deletes config.
        if let Ok(staged) = self.directory.stat(&name) {
            if staged.node == created.node {
                let _ = self.directory.remove_file(&name);
            }
        }
        result
    }
}

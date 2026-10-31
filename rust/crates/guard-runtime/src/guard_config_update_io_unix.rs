use super::*;
use nix::fcntl::{open, openat, renameat, AtFlags, Flock, FlockArg, OFlag};
use nix::sys::stat::{fstatat, Mode, SFlag};
use nix::unistd::{unlinkat, UnlinkatFlags};
use std::fs::File;
use std::io::Write;
use std::os::unix::fs::MetadataExt;

#[path = "guard_config_update_catalog_io.rs"]
pub(super) mod catalog;
#[path = "guard_config_update_lifecycle_io.rs"]
pub(super) mod lifecycle;
#[path = "guard_config_update_staging.rs"]
mod staging;

const LOCK_NAME: &str = "config-write.lock";
fn failure(code: &str) -> Failure {
    Failure::Error(code.into())
}
#[cfg(test)]
thread_local! { pub(super) static AFTER_RENAME_FAULT: std::cell::Cell<bool> = const { std::cell::Cell::new(false) }; }

#[cfg(test)]
pub(crate) fn fail_next_config_write_after_rename() {
    AFTER_RENAME_FAULT.with(|fault| fault.set(true));
}

pub(crate) struct WriteLock {
    home: PathBuf,
    canonical: PathBuf,
    directory: File,
    lock: Flock<File>,
}
impl WriteLock {
    pub(crate) fn root_identity(&self) -> Result<(u64, u64), Failure> {
        self.check()?;
        let m = self
            .directory
            .metadata()
            .map_err(|_| failure("config_directory_changed"))?;
        Ok((m.dev(), m.ino()))
    }
    pub(crate) fn acquire(home: &Path) -> Result<Self, Failure> {
        let canonical =
            fs::canonicalize(home).map_err(|_| failure("config_directory_unavailable"))?;
        let directory: File = open(
            &canonical,
            OFlag::O_RDONLY | OFlag::O_DIRECTORY | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC,
            Mode::empty(),
        )
        .map_err(|_| failure("config_directory_unavailable"))?
        .into();
        let metadata = directory
            .metadata()
            .map_err(|_| failure("config_directory_unavailable"))?;
        if !metadata.is_dir()
            || metadata.uid() != nix::unistd::geteuid().as_raw()
            || metadata.mode() & 0o022 != 0
        {
            return Err(failure("config_directory_unsafe"));
        }
        let file: File = openat(
            &directory,
            LOCK_NAME,
            OFlag::O_RDWR
                | OFlag::O_CREAT
                | OFlag::O_NOFOLLOW
                | OFlag::O_CLOEXEC
                | OFlag::O_NONBLOCK,
            Mode::from_bits_truncate(0o600),
        )
        .map_err(|_| failure("config_lock_unavailable"))?
        .into();
        let lock = Flock::lock(file, FlockArg::LockExclusiveNonblock)
            .map_err(|_| failure("config_write_busy"))?;
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
            .metadata()
            .map_err(|_| failure("config_directory_unavailable"))?;
        let current = fs::metadata(&self.home).map_err(|_| failure("config_directory_changed"))?;
        if fs::canonicalize(&self.home).map_err(|_| failure("config_directory_changed"))?
            != self.canonical
            || directory.dev() != current.dev()
            || directory.ino() != current.ino()
            || !current.is_dir()
            || current.uid() != nix::unistd::geteuid().as_raw()
            || current.mode() & 0o022 != 0
        {
            return Err(failure("config_directory_changed"));
        }
        let locked = self
            .lock
            .metadata()
            .map_err(|_| failure("config_lock_unavailable"))?;
        let path = fstatat(&self.directory, LOCK_NAME, AtFlags::AT_SYMLINK_NOFOLLOW)
            .map_err(|_| failure("config_lock_changed"))?;
        if !locked.is_file()
            || locked.len() != 0
            || locked.nlink() != 1
            || locked.uid() != nix::unistd::geteuid().as_raw()
            || locked.mode() & 0o077 != 0
            || path.st_dev as u64 != locked.dev()
            || path.st_ino != locked.ino()
            || !SFlag::from_bits_truncate(path.st_mode).contains(SFlag::S_IFREG)
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
        let file: File = openat(
            &self.directory,
            HOME_CONFIG_FILENAME,
            OFlag::O_WRONLY | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC | OFlag::O_NONBLOCK,
            Mode::empty(),
        )
        .map_err(|_| failure("config_file_not_writable"))?
        .into();
        let metadata = file
            .metadata()
            .map_err(|_| failure("config_file_not_writable"))?;
        let path = fstatat(
            &self.directory,
            HOME_CONFIG_FILENAME,
            AtFlags::AT_SYMLINK_NOFOLLOW,
        )
        .map_err(|_| failure("config_file_changed"))?;
        if !metadata.is_file()
            || metadata.nlink() != 1
            || metadata.uid() != nix::unistd::geteuid().as_raw()
            || metadata.mode() & 0o200 == 0
            || path.st_dev as u64 != metadata.dev()
            || path.st_ino != metadata.ino()
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
    // libc::dev_t differs across Unix targets; the inode comparison uses MetadataExt's u64.
    #[allow(clippy::unnecessary_cast)]
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
        let mut file: File = openat(
            &self.directory,
            name.as_str(),
            OFlag::O_WRONLY | OFlag::O_CREAT | OFlag::O_EXCL | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC,
            Mode::from_bits_truncate(0o600),
        )
        .map_err(|_| failure("config_write_failed"))?
        .into();
        let metadata = file
            .metadata()
            .map_err(|_| failure("config_write_failed"))?;
        let result = (|| {
            file.write_all(text.as_bytes())
                .map_err(|_| failure("config_write_failed"))?;
            file.sync_all()
                .map_err(|_| failure("config_write_failed"))?;
            self.check()?;
            if read_home_config(&self.home)?.as_deref() != expected {
                return Err(failure("config_file_changed"));
            }
            self.target_writable(expected)?;
            let staged = fstatat(&self.directory, name.as_str(), AtFlags::AT_SYMLINK_NOFOLLOW)
                .map_err(|_| failure("config_write_failed"))?;
            if staged.st_dev as u64 != metadata.dev()
                || staged.st_ino != metadata.ino()
                || staged.st_nlink != 1
                || staged.st_mode as u32 & 0o077 != 0
            {
                return Err(failure("config_write_failed"));
            }
            renameat(
                &self.directory,
                name.as_str(),
                &self.directory,
                HOME_CONFIG_FILENAME,
            )
            .map_err(|_| failure("config_write_failed"))?;
            #[cfg(test)]
            if AFTER_RENAME_FAULT.with(|fault| fault.replace(false)) {
                return Err(failure("config_commit_outcome_unknown"));
            }
            self.directory
                .sync_all()
                .map_err(|_| failure("config_commit_outcome_unknown"))?;
            self.check()
                .map_err(|_| failure("config_commit_outcome_unknown"))?;
            if read_home_config(&self.home)?.as_deref() != Some(text) {
                return Err(failure("config_commit_outcome_unknown"));
            }
            Ok(())
        })();
        // Remove only our own still-staged inode. After a successful rename
        // there is no temporary name, and uncertainty never deletes config.
        if let Ok(staged) = fstatat(&self.directory, name.as_str(), AtFlags::AT_SYMLINK_NOFOLLOW) {
            if staged.st_dev as u64 == metadata.dev() && staged.st_ino == metadata.ino() {
                let _ = unlinkat(&self.directory, name.as_str(), UnlinkatFlags::NoRemoveDir);
            }
        }
        result
    }
}

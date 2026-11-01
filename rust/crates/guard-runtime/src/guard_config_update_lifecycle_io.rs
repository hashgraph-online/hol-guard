//! Fixed lifecycle names share the short config-writer lane and pinned home.
//! No caller can supply a destination path or write an arbitrary home file.
use super::*;
use std::io::Read;
#[path = "guard_config_update_lifecycle_staging.rs"]
mod staging;

#[derive(Clone, Copy)]
pub(crate) enum LifecycleFile {
    Record,
    InitialSelection,
    Key,
    Erasure,
    ScopeIndex,
    CatalogTrust,
    CatalogCache,
    CatalogKey,
    CatalogFeed,
}
impl LifecycleFile {
    fn name(self) -> &'static str {
        match self {
            Self::Record => "cigar-lifecycle.json",
            Self::InitialSelection => "cigar-initial-selection.json",
            Self::Key => "cigar-lifecycle.key",
            Self::Erasure => "cigar-erasure.json",
            Self::ScopeIndex => "cigar-scopes.json",
            Self::CatalogTrust => "cigar-catalog-trust.json",
            Self::CatalogCache => "cigar-catalog.json",
            Self::CatalogKey => "cigar-catalog.key",
            Self::CatalogFeed => "cigar-catalog-feed.json",
        }
    }
    fn limit(self) -> usize {
        match self {
            Self::Record => 128 * 1024,
            Self::InitialSelection => 64 * 1024,
            Self::Key => 32,
            Self::Erasure => 4096,
            Self::ScopeIndex => 32 * 1024,
            Self::CatalogTrust => 16 * 1024,
            Self::CatalogCache => 4 * 1024 * 1024,
            Self::CatalogKey => 32,
            Self::CatalogFeed => 4096,
        }
    }
}
#[cfg(test)]
thread_local! { static AFTER_RECORD_RENAME: std::cell::Cell<bool> = const { std::cell::Cell::new(false) }; }
#[cfg(test)]
thread_local! { static AFTER_ERASURE_RENAME: std::cell::Cell<bool> = const { std::cell::Cell::new(false) }; }
#[cfg(test)]
pub(crate) fn fail_next_erasure_intent_after_rename() {
    AFTER_ERASURE_RENAME.with(|f| f.set(true));
}
#[cfg(test)]
pub(crate) fn fail_next_lifecycle_record_after_rename() {
    AFTER_RECORD_RENAME.with(|f| f.set(true));
}
fn checked_file(
    lock: &WriteLock,
    kind: LifecycleFile,
    flags: OFlag,
) -> Result<Option<File>, Failure> {
    lock.check()?;
    let file: File = match openat(
        &lock.directory,
        kind.name(),
        flags | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC | OFlag::O_NONBLOCK,
        Mode::empty(),
    ) {
        Ok(fd) => fd.into(),
        Err(nix::errno::Errno::ENOENT) => return Ok(None),
        Err(_) => return Err(failure("cigar_lifecycle_file_invalid")),
    };
    let m = file
        .metadata()
        .map_err(|_| failure("cigar_lifecycle_file_invalid"))?;
    let n = fstatat(&lock.directory, kind.name(), AtFlags::AT_SYMLINK_NOFOLLOW)
        .map_err(|_| failure("cigar_lifecycle_file_changed"))?;
    if !m.is_file()
        || m.nlink() != 1
        || m.uid() != nix::unistd::geteuid().as_raw()
        || m.mode() & 0o077 != 0
        || m.len() as usize > kind.limit()
        || m.dev() != n.st_dev as u64
        || m.ino() != n.st_ino
        || !SFlag::from_bits_truncate(n.st_mode).contains(SFlag::S_IFREG)
    {
        return Err(failure("cigar_lifecycle_file_invalid"));
    }
    lock.check()?;
    Ok(Some(file))
}
impl WriteLock {
    pub(crate) fn check_erasure_intent(&self, expected: &[u8]) -> Result<(), Failure> {
        if self.lifecycle_bytes(LifecycleFile::Erasure)?.as_deref() != Some(expected) {
            return Err(failure("cigar_lifecycle_record_changed"));
        }
        let file = checked_file(self, LifecycleFile::Erasure, OFlag::O_WRONLY)?
            .ok_or_else(|| failure("cigar_lifecycle_record_changed"))?;
        if file
            .metadata()
            .map_err(|_| failure("cigar_lifecycle_file_invalid"))?
            .mode()
            & 0o200
            == 0
        {
            return Err(failure("cigar_lifecycle_file_not_writable"));
        }
        Ok(())
    }
    pub(crate) fn complete_saved_erasure(&self, expected: &[u8]) -> Result<(), Failure> {
        self.check_erasure_intent(expected)?;
        self.forget_lifecycle_selection()?;
        self.complete_scope_erasure(expected)
    }
    pub(crate) fn complete_scope_erasure(&self, expected: &[u8]) -> Result<(), Failure> {
        self.check_erasure_intent(expected)?;
        unlinkat(
            &self.directory,
            LifecycleFile::Erasure.name(),
            UnlinkatFlags::NoRemoveDir,
        )
        .map_err(|_| failure("cigar_lifecycle_commit_outcome_unknown"))?;
        self.directory
            .sync_all()
            .map_err(|_| failure("cigar_lifecycle_commit_outcome_unknown"))?;
        self.check()
    }

    pub(crate) fn lifecycle_bytes(&self, kind: LifecycleFile) -> Result<Option<Vec<u8>>, Failure> {
        let Some(mut file) = checked_file(self, kind, OFlag::O_RDONLY)? else {
            return Ok(None);
        };
        let before = file
            .metadata()
            .map_err(|_| failure("cigar_lifecycle_file_invalid"))?;
        let mut bytes = Vec::new();
        Read::by_ref(&mut file)
            .take(kind.limit() as u64 + 1)
            .read_to_end(&mut bytes)
            .map_err(|_| failure("cigar_lifecycle_file_invalid"))?;
        let fresh = checked_file(self, kind, OFlag::O_RDONLY)?
            .ok_or_else(|| failure("cigar_lifecycle_file_changed"))?;
        let after = fresh
            .metadata()
            .map_err(|_| failure("cigar_lifecycle_file_invalid"))?;
        if bytes.len() > kind.limit()
            || bytes.len() as u64 != before.len()
            || before.dev() != after.dev()
            || before.ino() != after.ino()
            || before.len() != after.len()
            || before.mtime() != after.mtime()
            || before.mtime_nsec() != after.mtime_nsec()
            || before.ctime() != after.ctime()
            || before.ctime_nsec() != after.ctime_nsec()
        {
            return Err(failure("cigar_lifecycle_file_changed"));
        }
        Ok(Some(bytes))
    }
    // libc::dev_t differs across Unix targets; the inode comparison uses MetadataExt's u64.
    #[allow(clippy::unnecessary_cast)]
    pub(crate) fn publish_lifecycle(
        &self,
        kind: LifecycleFile,
        expected: Option<&[u8]>,
        bytes: &[u8],
    ) -> Result<(), Failure> {
        if bytes.is_empty()
            || bytes.len() > kind.limit()
            || (matches!(kind, LifecycleFile::Key | LifecycleFile::CatalogKey)
                && (expected.is_some() || bytes.len() != 32))
        {
            return Err(failure("cigar_lifecycle_record_invalid"));
        }
        self.check()?;
        self.recover_lifecycle_staging()?;
        if self.lifecycle_bytes(kind)?.as_deref() != expected {
            return Err(failure("cigar_lifecycle_record_changed"));
        }
        if expected.is_some() {
            let file = checked_file(self, kind, OFlag::O_WRONLY)?
                .ok_or_else(|| failure("cigar_lifecycle_record_changed"))?;
            if file
                .metadata()
                .map_err(|_| failure("cigar_lifecycle_file_invalid"))?
                .mode()
                & 0o200
                == 0
            {
                return Err(failure("cigar_lifecycle_file_not_writable"));
            }
        }
        let mut nonce = [0_u8; 16];
        getrandom::fill(&mut nonce).map_err(|_| failure("cigar_lifecycle_write_failed"))?;
        let name = format!(
            ".{}.{}.{:032x}.tmp",
            kind.name(),
            std::process::id(),
            u128::from_le_bytes(nonce)
        );
        let mut file: File = openat(
            &self.directory,
            name.as_str(),
            OFlag::O_WRONLY | OFlag::O_CREAT | OFlag::O_EXCL | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC,
            Mode::from_bits_truncate(0o600),
        )
        .map_err(|_| failure("cigar_lifecycle_write_failed"))?
        .into();
        let m = file
            .metadata()
            .map_err(|_| failure("cigar_lifecycle_write_failed"))?;
        let result = (|| {
            file.write_all(bytes)
                .and_then(|_| file.sync_all())
                .map_err(|_| failure("cigar_lifecycle_write_failed"))?;
            self.check()?;
            if self.lifecycle_bytes(kind)?.as_deref() != expected {
                return Err(failure("cigar_lifecycle_record_changed"));
            }
            let staged = fstatat(&self.directory, name.as_str(), AtFlags::AT_SYMLINK_NOFOLLOW)
                .map_err(|_| failure("cigar_lifecycle_write_failed"))?;
            if staged.st_dev as u64 != m.dev()
                || staged.st_ino != m.ino()
                || staged.st_nlink != 1
                || staged.st_mode as u32 & 0o077 != 0
            {
                return Err(failure("cigar_lifecycle_write_failed"));
            }
            renameat(&self.directory, name.as_str(), &self.directory, kind.name())
                .map_err(|_| failure("cigar_lifecycle_write_failed"))?;
            #[cfg(test)]
            if matches!(kind, LifecycleFile::Record)
                && AFTER_RECORD_RENAME.with(|f| f.replace(false))
            {
                return Err(failure("cigar_lifecycle_commit_outcome_unknown"));
            }
            #[cfg(test)]
            if matches!(kind, LifecycleFile::Erasure)
                && AFTER_ERASURE_RENAME.with(|f| f.replace(false))
            {
                return Err(failure("cigar_lifecycle_commit_outcome_unknown"));
            }
            self.directory
                .sync_all()
                .map_err(|_| failure("cigar_lifecycle_commit_outcome_unknown"))?;
            if self
                .lifecycle_bytes(kind)
                .map_err(|_| failure("cigar_lifecycle_commit_outcome_unknown"))?
                .as_deref()
                != Some(bytes)
            {
                return Err(failure("cigar_lifecycle_commit_outcome_unknown"));
            }
            Ok(())
        })();
        if let Ok(staged) = fstatat(&self.directory, name.as_str(), AtFlags::AT_SYMLINK_NOFOLLOW) {
            if staged.st_dev as u64 == m.dev() && staged.st_ino == m.ino() {
                let _ = unlinkat(&self.directory, name.as_str(), UnlinkatFlags::NoRemoveDir);
            }
        }
        result
    }
}

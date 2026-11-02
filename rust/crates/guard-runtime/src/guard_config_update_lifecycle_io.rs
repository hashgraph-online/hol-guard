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
#[cfg(all(test, unix))]
pub(crate) fn fail_next_erasure_intent_after_rename() {
    AFTER_ERASURE_RENAME.with(|f| f.set(true));
}
#[cfg(all(test, unix))]
pub(crate) fn fail_next_lifecycle_record_after_rename() {
    AFTER_RECORD_RENAME.with(|f| f.set(true));
}
fn checked_file(lock: &WriteLock, kind: LifecycleFile, how: How) -> Result<Option<File>, Failure> {
    lock.check()?;
    let file = match lock.directory.open_file(kind.name(), how) {
        Ok(file) => file,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(_) => return Err(failure("cigar_lifecycle_file_invalid")),
    };
    let m = lock
        .directory
        .file_entry(kind.name(), &file)
        .map_err(|_| failure("cigar_lifecycle_file_invalid"))?;
    let n = lock
        .directory
        .stat(kind.name())
        .map_err(|_| failure("cigar_lifecycle_file_changed"))?;
    if !m.private_file() || m.len > kind.limit() as u64 || m.node != n.node || n.kind != Kind::File
    {
        return Err(failure("cigar_lifecycle_file_invalid"));
    }
    lock.check()?;
    Ok(Some(file))
}
/// Whether the existing file may be replaced: it opens for writing and its
/// owner may write it.
fn replaceable(lock: &WriteLock, kind: LifecycleFile) -> Result<(), Failure> {
    let file = checked_file(lock, kind, How::Write)?
        .ok_or_else(|| failure("cigar_lifecycle_record_changed"))?;
    let entry = lock
        .directory
        .file_entry(kind.name(), &file)
        .map_err(|_| failure("cigar_lifecycle_file_invalid"))?;
    if !entry.writable {
        return Err(failure("cigar_lifecycle_file_not_writable"));
    }
    Ok(())
}
impl WriteLock {
    pub(crate) fn check_erasure_intent(&self, expected: &[u8]) -> Result<(), Failure> {
        if self.lifecycle_bytes(LifecycleFile::Erasure)?.as_deref() != Some(expected) {
            return Err(failure("cigar_lifecycle_record_changed"));
        }
        replaceable(self, LifecycleFile::Erasure)
    }
    pub(crate) fn complete_saved_erasure(&self, expected: &[u8]) -> Result<(), Failure> {
        self.check_erasure_intent(expected)?;
        self.forget_lifecycle_selection()?;
        self.complete_scope_erasure(expected)
    }
    pub(crate) fn complete_scope_erasure(&self, expected: &[u8]) -> Result<(), Failure> {
        self.check_erasure_intent(expected)?;
        self.directory
            .remove_file(LifecycleFile::Erasure.name())
            .and_then(|()| self.directory.sync())
            .map_err(|_| failure("cigar_lifecycle_commit_outcome_unknown"))?;
        self.check()
    }

    pub(crate) fn lifecycle_bytes(&self, kind: LifecycleFile) -> Result<Option<Vec<u8>>, Failure> {
        let Some(mut file) = checked_file(self, kind, How::Read)? else {
            return Ok(None);
        };
        let before = self
            .directory
            .file_entry(kind.name(), &file)
            .map_err(|_| failure("cigar_lifecycle_file_invalid"))?;
        let mut bytes = Vec::new();
        Read::by_ref(&mut file)
            .take(kind.limit() as u64 + 1)
            .read_to_end(&mut bytes)
            .map_err(|_| failure("cigar_lifecycle_file_invalid"))?;
        drop(file);
        let fresh = checked_file(self, kind, How::Read)?
            .ok_or_else(|| failure("cigar_lifecycle_file_changed"))?;
        let after = self
            .directory
            .file_entry(kind.name(), &fresh)
            .map_err(|_| failure("cigar_lifecycle_file_invalid"))?;
        if bytes.len() > kind.limit()
            || bytes.len() as u64 != before.len
            || before.node != after.node
            || before.len != after.len
            || before.times != after.times
        {
            return Err(failure("cigar_lifecycle_file_changed"));
        }
        Ok(Some(bytes))
    }
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
            replaceable(self, kind)?;
        }
        let mut nonce = [0_u8; 16];
        getrandom::fill(&mut nonce).map_err(|_| failure("cigar_lifecycle_write_failed"))?;
        let name = format!(
            ".{}.{}.{:032x}.tmp",
            kind.name(),
            std::process::id(),
            u128::from_le_bytes(nonce)
        );
        let mut file = self
            .directory
            .open_file(&name, How::CreateNew)
            .map_err(|_| failure("cigar_lifecycle_write_failed"))?;
        let created = self
            .directory
            .file_entry(&name, &file)
            .map_err(|_| failure("cigar_lifecycle_write_failed"))?;
        let written = file.write_all(bytes).and_then(|_| file.sync_all());
        // Windows cannot rename or remove a name that still has an open handle.
        drop(file);
        let result = written
            .map_err(|_| failure("cigar_lifecycle_write_failed"))
            .and_then(|()| {
                self.check()?;
                if self.lifecycle_bytes(kind)?.as_deref() != expected {
                    return Err(failure("cigar_lifecycle_record_changed"));
                }
                let staged = self
                    .directory
                    .stat(&name)
                    .map_err(|_| failure("cigar_lifecycle_write_failed"))?;
                if staged.node != created.node || !staged.private_file() {
                    return Err(failure("cigar_lifecycle_write_failed"));
                }
                self.directory
                    .rename(&name, kind.name())
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
                    .sync()
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
            });
        if let Ok(staged) = self.directory.stat(&name) {
            if staged.node == created.node {
                let _ = self.directory.remove_file(&name);
            }
        }
        result
    }
}

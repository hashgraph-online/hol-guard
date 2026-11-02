//! Only bounded private orphan staging inodes are removed under the shared
//! writer lock. Committed records/keys and unrelated files are never matched.
use super::*;

fn temporary(name: &str) -> Option<LifecycleFile> {
    for kind in [
        LifecycleFile::Record,
        LifecycleFile::InitialSelection,
        LifecycleFile::Key,
        LifecycleFile::Erasure,
        LifecycleFile::ScopeIndex,
        LifecycleFile::CatalogTrust,
        LifecycleFile::CatalogCache,
        LifecycleFile::CatalogKey,
        LifecycleFile::CatalogFeed,
    ] {
        let prefix = format!(".{}.", kind.name());
        let Some(rest) = name
            .strip_prefix(&prefix)
            .and_then(|s| s.strip_suffix(".tmp"))
        else {
            continue;
        };
        let (pid, nonce) = rest.split_once('.')?;
        if !pid.is_empty()
            && pid.len() <= 10
            && pid.bytes().all(|b| b.is_ascii_digit())
            && nonce.len() == 32
            && nonce
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return Some(kind);
        }
    }
    None
}
impl WriteLock {
    pub(super) fn recover_lifecycle_staging(&self) -> Result<(), Failure> {
        self.check()?;
        let all = self.directory.names(4096).map_err(|e| match e {
            Names::Limit => failure("cigar_lifecycle_staging_limit"),
            Names::Failed => failure("cigar_lifecycle_staging_unavailable"),
        })?;
        let mut names = Vec::new();
        let mut bytes = 0u64;
        for name in all {
            let Some(kind) = temporary(&name) else {
                continue;
            };
            if names.len() >= 32 {
                return Err(failure("cigar_lifecycle_staging_limit"));
            }
            let file = self
                .directory
                .open_file(&name, How::Read)
                .map_err(|_| failure("cigar_lifecycle_staging_invalid"))?;
            let m = self
                .directory
                .file_entry(&name, &file)
                .map_err(|_| failure("cigar_lifecycle_staging_invalid"))?;
            if !m.private_file() || m.len > kind.limit() as u64 {
                return Err(failure("cigar_lifecycle_staging_invalid"));
            }
            bytes = bytes.saturating_add(m.len);
            if bytes > 4 * 1024 * 1024 {
                return Err(failure("cigar_lifecycle_staging_limit"));
            }
            names.push((name, m));
        }
        for (name, m) in names {
            self.check()?;
            let n = self
                .directory
                .stat(&name)
                .map_err(|_| failure("cigar_lifecycle_staging_invalid"))?;
            if n.node != m.node || n.links != 1 {
                return Err(failure("cigar_lifecycle_staging_invalid"));
            }
            self.directory
                .remove_file(&name)
                .map_err(|_| failure("cigar_lifecycle_commit_outcome_unknown"))?;
        }
        self.directory
            .sync()
            .map_err(|_| failure("cigar_lifecycle_commit_outcome_unknown"))
    }
    pub(crate) fn forget_lifecycle_selection(&self) -> Result<(), Failure> {
        self.check()?;
        self.recover_lifecycle_staging()?;
        for kind in [
            LifecycleFile::ScopeIndex,
            LifecycleFile::Record,
            LifecycleFile::InitialSelection,
            LifecycleFile::Key,
        ] {
            if let Some(file) = checked_file(self, kind, How::Read)? {
                let m = self
                    .directory
                    .file_entry(kind.name(), &file)
                    .map_err(|_| failure("cigar_lifecycle_file_invalid"))?;
                drop(file);
                self.check()?;
                let n = self
                    .directory
                    .stat(kind.name())
                    .map_err(|_| failure("cigar_lifecycle_file_changed"))?;
                if n.node != m.node {
                    return Err(failure("cigar_lifecycle_file_changed"));
                }
                self.directory
                    .remove_file(kind.name())
                    .and_then(|()| self.directory.sync())
                    .map_err(|_| failure("cigar_lifecycle_commit_outcome_unknown"))?;
            }
        }
        self.check()
    }
}

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
        let fd = openat(
            &self.directory,
            ".",
            OFlag::O_RDONLY | OFlag::O_DIRECTORY | OFlag::O_CLOEXEC,
            Mode::empty(),
        )
        .map_err(|_| failure("cigar_lifecycle_staging_unavailable"))?;
        let mut dir = nix::dir::Dir::from_fd(fd)
            .map_err(|_| failure("cigar_lifecycle_staging_unavailable"))?;
        let mut names = Vec::new();
        let mut bytes = 0u64;
        for (index, entry) in dir.iter().enumerate() {
            if index >= 4096 {
                return Err(failure("cigar_lifecycle_staging_limit"));
            }
            let entry = entry.map_err(|_| failure("cigar_lifecycle_staging_unavailable"))?;
            let name = entry
                .file_name()
                .to_str()
                .map_err(|_| failure("cigar_lifecycle_staging_unavailable"))?;
            let Some(kind) = temporary(name) else {
                continue;
            };
            if names.len() >= 32 {
                return Err(failure("cigar_lifecycle_staging_limit"));
            }
            let file: File = openat(
                &self.directory,
                name,
                OFlag::O_RDONLY | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC | OFlag::O_NONBLOCK,
                Mode::empty(),
            )
            .map_err(|_| failure("cigar_lifecycle_staging_invalid"))?
            .into();
            let m = file
                .metadata()
                .map_err(|_| failure("cigar_lifecycle_staging_invalid"))?;
            if !m.is_file()
                || m.nlink() != 1
                || m.uid() != nix::unistd::geteuid().as_raw()
                || m.mode() & 0o077 != 0
                || m.len() > kind.limit() as u64
            {
                return Err(failure("cigar_lifecycle_staging_invalid"));
            }
            bytes = bytes.saturating_add(m.len());
            if bytes > 4 * 1024 * 1024 {
                return Err(failure("cigar_lifecycle_staging_limit"));
            }
            names.push((name.to_owned(), file, m));
        }
        for (name, _file, m) in names {
            self.check()?;
            let n = fstatat(&self.directory, name.as_str(), AtFlags::AT_SYMLINK_NOFOLLOW)
                .map_err(|_| failure("cigar_lifecycle_staging_invalid"))?;
            if n.st_dev as u64 != m.dev() || n.st_ino != m.ino() || n.st_nlink != 1 {
                return Err(failure("cigar_lifecycle_staging_invalid"));
            }
            unlinkat(&self.directory, name.as_str(), UnlinkatFlags::NoRemoveDir)
                .map_err(|_| failure("cigar_lifecycle_commit_outcome_unknown"))?;
        }
        self.directory
            .sync_all()
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
            if let Some(file) = checked_file(self, kind, OFlag::O_RDONLY)? {
                let m = file
                    .metadata()
                    .map_err(|_| failure("cigar_lifecycle_file_invalid"))?;
                self.check()?;
                let n = fstatat(&self.directory, kind.name(), AtFlags::AT_SYMLINK_NOFOLLOW)
                    .map_err(|_| failure("cigar_lifecycle_file_changed"))?;
                if n.st_dev as u64 != m.dev() || n.st_ino != m.ino() {
                    return Err(failure("cigar_lifecycle_file_changed"));
                }
                unlinkat(&self.directory, kind.name(), UnlinkatFlags::NoRemoveDir)
                    .map_err(|_| failure("cigar_lifecycle_commit_outcome_unknown"))?;
                self.directory
                    .sync_all()
                    .map_err(|_| failure("cigar_lifecycle_commit_outcome_unknown"))?;
            }
        }
        self.check()
    }
}

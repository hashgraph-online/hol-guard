//! A first catalog key/cache pair becomes visible in one directory rename.
//! Legacy complete flat pairs stay in place; mixed/incomplete state refuses.
use super::*;
use std::io::Read;
use zeroize::Zeroizing;
#[path = "guard_config_update_catalog_publication.rs"]
mod publication;
#[path = "guard_config_update_catalog_staging.rs"]
mod staging;
#[cfg(test)]
#[path = "guard_config_update_catalog_tests.rs"]
mod tests;
const NAME: &str = "cigar-catalog-state";
const KEY: &str = "key";
const CACHE: &str = "catalog.json";
const LIMIT: usize = 4 * 1024 * 1024;
#[derive(Eq, PartialEq)]
enum Layout {
    Legacy,
    Directory { dev: u64, ino: u64 },
}
pub(crate) struct CatalogPair {
    cache: Vec<u8>,
    key: Zeroizing<[u8; 32]>,
    layout: Layout,
}
impl CatalogPair {
    pub(crate) fn cache(&self) -> &[u8] {
        &self.cache
    }
    pub(crate) fn key(&self) -> &[u8; 32] {
        &self.key
    }
}
fn invalid() -> Failure {
    failure("cigar_catalog_storage_invalid_or_changed")
}
fn same(a: &std::fs::Metadata, b: &std::fs::Metadata) -> bool {
    a.dev() == b.dev()
        && a.ino() == b.ino()
        && a.len() == b.len()
        && a.mtime() == b.mtime()
        && a.mtime_nsec() == b.mtime_nsec()
        && a.ctime() == b.ctime()
        && a.ctime_nsec() == b.ctime_nsec()
}
fn directory(lock: &WriteLock, name: &str) -> Result<Option<File>, Failure> {
    lock.check()?;
    let file: File = match openat(
        &lock.directory,
        name,
        OFlag::O_RDONLY | OFlag::O_DIRECTORY | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC,
        Mode::empty(),
    ) {
        Ok(fd) => fd.into(),
        Err(nix::errno::Errno::ENOENT) => return Ok(None),
        Err(_) => return Err(invalid()),
    };
    check_directory(lock, name, &file)?;
    Ok(Some(file))
}
fn check_directory(lock: &WriteLock, name: &str, file: &File) -> Result<(), Failure> {
    lock.check()?;
    let m = file.metadata().map_err(|_| invalid())?;
    let n = fstatat(&lock.directory, name, AtFlags::AT_SYMLINK_NOFOLLOW).map_err(|_| invalid())?;
    if !m.is_dir()
        || m.uid() != nix::unistd::geteuid().as_raw()
        || m.mode() & 0o077 != 0
        || m.dev() != n.st_dev as u64
        || m.ino() != n.st_ino
        || !SFlag::from_bits_truncate(n.st_mode).contains(SFlag::S_IFDIR)
    {
        return Err(invalid());
    }
    Ok(())
}
fn checked_file(
    parent: &File,
    name: &str,
    limit: usize,
    flags: OFlag,
) -> Result<Option<File>, Failure> {
    let file: File = match openat(
        parent,
        name,
        flags | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC | OFlag::O_NONBLOCK,
        Mode::empty(),
    ) {
        Ok(fd) => fd.into(),
        Err(nix::errno::Errno::ENOENT) => return Ok(None),
        Err(_) => return Err(invalid()),
    };
    let m = file.metadata().map_err(|_| invalid())?;
    let n = fstatat(parent, name, AtFlags::AT_SYMLINK_NOFOLLOW).map_err(|_| invalid())?;
    if !m.is_file()
        || m.nlink() != 1
        || m.uid() != nix::unistd::geteuid().as_raw()
        || m.mode() & 0o077 != 0
        || m.len() as usize > limit
        || m.dev() != n.st_dev as u64
        || m.ino() != n.st_ino
        || !SFlag::from_bits_truncate(n.st_mode).contains(SFlag::S_IFREG)
    {
        return Err(invalid());
    }
    Ok(Some(file))
}
fn read(parent: &File, name: &str, limit: usize) -> Result<Option<Zeroizing<Vec<u8>>>, Failure> {
    let Some(mut f) = checked_file(parent, name, limit, OFlag::O_RDONLY)? else {
        return Ok(None);
    };
    let before = f.metadata().map_err(|_| invalid())?;
    let mut bytes = Zeroizing::new(Vec::new());
    Read::by_ref(&mut f)
        .take(limit as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| invalid())?;
    let fresh = checked_file(parent, name, limit, OFlag::O_RDONLY)?.ok_or_else(invalid)?;
    if bytes.len() > limit
        || bytes.len() as u64 != before.len()
        || !same(&before, &fresh.metadata().map_err(|_| invalid())?)
    {
        return Err(invalid());
    }
    Ok(Some(bytes))
}
fn pair(
    cache: Option<Vec<u8>>,
    key: Option<Zeroizing<Vec<u8>>>,
    layout: Layout,
) -> Result<Option<CatalogPair>, Failure> {
    match (cache, key) {
        (None, None) if layout == Layout::Legacy => Ok(None),
        (Some(cache), Some(key)) if !cache.is_empty() && key.len() == 32 => Ok(Some(CatalogPair {
            cache,
            key: Zeroizing::new(key.as_slice().try_into().map_err(|_| invalid())?),
            layout,
        })),
        _ => Err(failure("cigar_catalog_state_incomplete")),
    }
}
impl WriteLock {
    pub(crate) fn catalog_pair(&self) -> Result<Option<CatalogPair>, Failure> {
        let legacy_cache = self.lifecycle_bytes(lifecycle::LifecycleFile::CatalogCache)?;
        let legacy_key = self
            .lifecycle_bytes(lifecycle::LifecycleFile::CatalogKey)?
            .map(Zeroizing::new);
        let Some(dir) = directory(self, NAME)? else {
            return pair(legacy_cache, legacy_key, Layout::Legacy);
        };
        if legacy_cache.is_some() || legacy_key.is_some() {
            return Err(failure("cigar_catalog_layout_conflict"));
        }
        let meta = dir.metadata().map_err(|_| invalid())?;
        let cache = read(&dir, CACHE, LIMIT)?.map(|v| v.to_vec());
        let key = read(&dir, KEY, 32)?;
        check_directory(self, NAME, &dir)?;
        pair(
            cache,
            key,
            Layout::Directory {
                dev: meta.dev(),
                ino: meta.ino(),
            },
        )
    }
    pub(crate) fn publish_catalog(
        &self,
        expected: Option<&CatalogPair>,
        bytes: &[u8],
        key: &[u8; 32],
    ) -> Result<(), Failure> {
        if bytes.is_empty() || bytes.len() > LIMIT {
            return Err(invalid());
        }
        self.check()?;
        let current = self.catalog_pair()?;
        let matches = match (expected, current.as_ref()) {
            (None, None) => true,
            (Some(a), Some(b)) => {
                a.layout == b.layout && a.cache == b.cache && a.key() == b.key() && b.key() == key
            }
            _ => false,
        };
        if !matches {
            return Err(failure("cigar_catalog_state_changed"));
        }
        staging::recover_directories(self)?;
        match current.as_ref().map(|p| &p.layout) {
            None => publication::initialize(self, bytes, key),
            Some(Layout::Legacy) => self.publish_lifecycle(
                lifecycle::LifecycleFile::CatalogCache,
                Some(expected.ok_or_else(invalid)?.cache()),
                bytes,
            ),
            Some(Layout::Directory { .. }) => {
                publication::replace(self, expected.ok_or_else(invalid)?, bytes)
            }
        }
    }
}
#[cfg(test)]
#[derive(Clone, Copy)]
pub(crate) enum Fault {
    Crash(&'static str),
    Error(&'static str),
}
#[cfg(test)]
thread_local! {static FAULT:std::cell::Cell<Option<Fault>>=const{std::cell::Cell::new(None)};}
#[cfg(test)]
pub(crate) fn fault_next(fault: Fault) {
    FAULT.with(|f| f.set(Some(fault)));
}
fn checkpoint(point: &str) -> Result<(), Failure> {
    #[cfg(test)]
    if let Some(fault) = FAULT.with(|f| f.get()) {
        match fault {
            Fault::Crash(at) if at == point => std::process::exit(86),
            Fault::Error(at) if at == point => {
                FAULT.with(|f| f.set(None));
                return Err(failure(
                    if point.ends_with("renamed") || point.ends_with("synced") {
                        "cigar_catalog_commit_outcome_unknown"
                    } else {
                        "cigar_catalog_write_failed"
                    },
                ));
            }
            _ => {}
        }
    }
    let _ = point;
    Ok(())
}

//! A first catalog key/cache pair becomes visible in one directory rename.
//! Legacy complete flat pairs stay in place; mixed/incomplete state refuses.
use super::*;
use std::io::Read;
use zeroize::Zeroizing;
#[path = "guard_config_update_catalog_publication.rs"]
mod publication;
#[path = "guard_config_update_catalog_staging.rs"]
mod staging;
#[cfg(all(test, unix))]
#[path = "guard_config_update_catalog_tests.rs"]
mod tests;
const NAME: &str = "cigar-catalog-state";
const KEY: &str = "key";
const CACHE: &str = "catalog.json";
const LIMIT: usize = 4 * 1024 * 1024;
#[derive(Eq, PartialEq)]
enum Layout {
    Legacy,
    Directory(Node),
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
fn same(a: &dir::Entry, b: &dir::Entry) -> bool {
    a.node == b.node && a.len == b.len && a.times == b.times
}
fn directory(lock: &WriteLock, name: &str) -> Result<Option<Dir>, Failure> {
    lock.check()?;
    let dir = match lock.directory.open_dir(name) {
        Ok(dir) => dir,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(_) => return Err(invalid()),
    };
    check_directory(lock, name, &dir)?;
    Ok(Some(dir))
}
fn check_directory(lock: &WriteLock, name: &str, dir: &Dir) -> Result<(), Failure> {
    lock.check()?;
    let m = dir.entry().map_err(|_| invalid())?;
    let n = lock.directory.stat(name).map_err(|_| invalid())?;
    if !m.private_directory() || m.node != n.node || n.kind != Kind::Directory {
        return Err(invalid());
    }
    Ok(())
}
/// The file's entry, read through the open handle.
fn entry(parent: &Dir, name: &str, file: &File) -> Result<dir::Entry, Failure> {
    parent.file_entry(name, file).map_err(|_| invalid())
}
fn checked_file(parent: &Dir, name: &str, limit: usize, how: How) -> Result<Option<File>, Failure> {
    let file = match parent.open_file(name, how) {
        Ok(file) => file,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(_) => return Err(invalid()),
    };
    let m = entry(parent, name, &file)?;
    let n = parent.stat(name).map_err(|_| invalid())?;
    if !m.private_file() || m.len > limit as u64 || m.node != n.node || n.kind != Kind::File {
        return Err(invalid());
    }
    Ok(Some(file))
}
fn read(parent: &Dir, name: &str, limit: usize) -> Result<Option<Zeroizing<Vec<u8>>>, Failure> {
    let Some(mut f) = checked_file(parent, name, limit, How::Read)? else {
        return Ok(None);
    };
    let before = entry(parent, name, &f)?;
    let mut bytes = Zeroizing::new(Vec::new());
    Read::by_ref(&mut f)
        .take(limit as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| invalid())?;
    drop(f);
    let fresh = checked_file(parent, name, limit, How::Read)?.ok_or_else(invalid)?;
    if bytes.len() > limit
        || bytes.len() as u64 != before.len
        || !same(&before, &entry(parent, name, &fresh)?)
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
        let node = dir.entry().map_err(|_| invalid())?.node;
        let cache = read(&dir, CACHE, LIMIT)?.map(|v| v.to_vec());
        let key = read(&dir, KEY, 32)?;
        check_directory(self, NAME, &dir)?;
        pair(cache, key, Layout::Directory(node))
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
            Some(Layout::Directory(_)) => {
                publication::replace(self, expected.ok_or_else(invalid)?, bytes)
            }
        }
    }
}
#[cfg(all(test, unix))]
#[derive(Clone, Copy)]
pub(crate) enum Fault {
    Crash(&'static str),
    Error(&'static str),
}
#[cfg(all(test, unix))]
thread_local! {static FAULT:std::cell::Cell<Option<Fault>>=const{std::cell::Cell::new(None)};}
#[cfg(all(test, unix))]
pub(crate) fn fault_next(fault: Fault) {
    FAULT.with(|f| f.set(Some(fault)));
}
fn checkpoint(point: &str) -> Result<(), Failure> {
    #[cfg(all(test, unix))]
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

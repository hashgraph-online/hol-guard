//! Only bounded, private unpublished objects with native temporary names can
//! be removed. None becomes catalog authority or replaces committed state.
use super::*;
fn temporary(name: &str, prefix: &str) -> bool {
    let Some(s) = name
        .strip_prefix(prefix)
        .and_then(|s| s.strip_suffix(".tmp"))
    else {
        return false;
    };
    let Some((pid, nonce)) = s.split_once('.') else {
        return false;
    };
    !pid.is_empty()
        && pid.len() <= 10
        && pid.bytes().all(|b| b.is_ascii_digit())
        && nonce.len() == 32
        && nonce
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn names(parent: &Dir) -> Result<Vec<String>, Failure> {
    parent.names(4096).map_err(|e| match e {
        Names::Limit => failure("cigar_catalog_staging_limit"),
        Names::Failed => invalid(),
    })
}
pub(super) fn recover_directories(lock: &WriteLock) -> Result<(), Failure> {
    let mut pending = Vec::new();
    let mut total = 0_u64;
    for name in names(&lock.directory)? {
        if !temporary(&name, ".cigar-catalog-state.") {
            continue;
        }
        if pending.len() >= 32 {
            return Err(failure("cigar_catalog_staging_limit"));
        }
        let dir = directory(lock, &name)?.ok_or_else(invalid)?;
        let mut files = Vec::new();
        for child in names(&dir)? {
            let limit = match child.as_str() {
                KEY => 32,
                CACHE => LIMIT,
                _ => return Err(failure("cigar_catalog_staging_unsafe")),
            };
            let file = checked_file(&dir, &child, limit, How::Read)?.ok_or_else(invalid)?;
            let m = entry(&dir, &child, &file)?;
            total = total.saturating_add(m.len);
            if total > 128 * 1024 * 1024 {
                return Err(failure("cigar_catalog_staging_limit"));
            }
            files.push((child, m));
        }
        pending.push((name, dir, files));
    }
    // Complete validation precedes removal, so an unknown child or link does
    // not cause partial cleanup of the inventoried roots.
    for (name, dir, files) in pending {
        check_directory(lock, &name, &dir)?;
        for (child, meta) in files {
            let fresh = checked_file(&dir, &child, LIMIT, How::Read)?.ok_or_else(invalid)?;
            let current = entry(&dir, &child, &fresh)?;
            drop(fresh);
            if !same(&meta, &current) {
                return Err(invalid());
            }
            dir.remove_file(&child).map_err(|_| invalid())?;
        }
        check_directory(lock, &name, &dir)?;
        drop(dir);
        lock.directory.remove_dir(&name).map_err(|_| invalid())?;
    }
    lock.directory
        .sync()
        .map_err(|_| failure("cigar_catalog_write_failed"))?;
    lock.check()
}
pub(super) fn recover_files(dir: &Dir) -> Result<(), Failure> {
    let mut pending = Vec::new();
    let mut bytes = 0_u64;
    for name in names(dir)? {
        if !temporary(&name, ".catalog.json.") {
            continue;
        }
        if pending.len() >= 32 {
            return Err(failure("cigar_catalog_staging_limit"));
        }
        let file = checked_file(dir, &name, LIMIT, How::Read)?.ok_or_else(invalid)?;
        let meta = entry(dir, &name, &file)?;
        bytes = bytes.saturating_add(meta.len);
        if bytes > 128 * 1024 * 1024 {
            return Err(failure("cigar_catalog_staging_limit"));
        }
        pending.push((name, meta));
    }
    for (name, meta) in pending {
        let fresh = checked_file(dir, &name, LIMIT, How::Read)?.ok_or_else(invalid)?;
        let current = entry(dir, &name, &fresh)?;
        drop(fresh);
        if !same(&meta, &current) {
            return Err(invalid());
        }
        dir.remove_file(&name).map_err(|_| invalid())?;
    }
    dir.sync()
        .map_err(|_| failure("cigar_catalog_write_failed"))
}

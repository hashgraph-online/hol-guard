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
fn names(parent: &File) -> Result<Vec<String>, Failure> {
    let fd = openat(
        parent,
        ".",
        OFlag::O_RDONLY | OFlag::O_DIRECTORY | OFlag::O_CLOEXEC,
        Mode::empty(),
    )
    .map_err(|_| invalid())?;
    let mut dir = nix::dir::Dir::from_fd(fd).map_err(|_| invalid())?;
    let mut names = Vec::new();
    for (i, e) in dir.iter().enumerate() {
        if i >= 4096 {
            return Err(failure("cigar_catalog_staging_limit"));
        }
        let e = e.map_err(|_| invalid())?;
        let n = e.file_name().to_str().map_err(|_| invalid())?;
        if n != "." && n != ".." {
            names.push(n.into());
        }
    }
    Ok(names)
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
            let file = checked_file(&dir, &child, limit, OFlag::O_RDONLY)?.ok_or_else(invalid)?;
            let m = file.metadata().map_err(|_| invalid())?;
            total = total.saturating_add(m.len());
            if total > 128 * 1024 * 1024 {
                return Err(failure("cigar_catalog_staging_limit"));
            }
            files.push((child, file, m));
        }
        pending.push((name, dir, files));
    }
    // Complete validation precedes removal, so an unknown child or link does
    // not cause partial cleanup of the inventoried roots.
    for (name, dir, files) in pending {
        check_directory(lock, &name, &dir)?;
        for (child, file, meta) in files {
            let fresh = checked_file(&dir, &child, LIMIT, OFlag::O_RDONLY)?.ok_or_else(invalid)?;
            if !same(&meta, &fresh.metadata().map_err(|_| invalid())?)
                || !same(&meta, &file.metadata().map_err(|_| invalid())?)
            {
                return Err(invalid());
            }
            unlinkat(&dir, child.as_str(), UnlinkatFlags::NoRemoveDir).map_err(|_| invalid())?;
        }
        check_directory(lock, &name, &dir)?;
        unlinkat(&lock.directory, name.as_str(), UnlinkatFlags::RemoveDir)
            .map_err(|_| invalid())?;
    }
    lock.directory
        .sync_all()
        .map_err(|_| failure("cigar_catalog_write_failed"))?;
    lock.check()
}
pub(super) fn recover_files(dir: &File) -> Result<(), Failure> {
    let mut pending = Vec::new();
    let mut bytes = 0_u64;
    for name in names(dir)? {
        if !temporary(&name, ".catalog.json.") {
            continue;
        }
        if pending.len() >= 32 {
            return Err(failure("cigar_catalog_staging_limit"));
        }
        let file = checked_file(dir, &name, LIMIT, OFlag::O_RDONLY)?.ok_or_else(invalid)?;
        let meta = file.metadata().map_err(|_| invalid())?;
        bytes = bytes.saturating_add(meta.len());
        if bytes > 128 * 1024 * 1024 {
            return Err(failure("cigar_catalog_staging_limit"));
        }
        pending.push((name, file, meta));
    }
    for (name, file, meta) in pending {
        let fresh = checked_file(dir, &name, LIMIT, OFlag::O_RDONLY)?.ok_or_else(invalid)?;
        if !same(&meta, &fresh.metadata().map_err(|_| invalid())?)
            || !same(&meta, &file.metadata().map_err(|_| invalid())?)
        {
            return Err(invalid());
        }
        unlinkat(dir, name.as_str(), UnlinkatFlags::NoRemoveDir).map_err(|_| invalid())?;
    }
    dir.sync_all()
        .map_err(|_| failure("cigar_catalog_write_failed"))
}

use super::*;
fn random_name(prefix: &str) -> Result<String, Failure> {
    let mut nonce = [0_u8; 16];
    getrandom::fill(&mut nonce).map_err(|_| failure("cigar_catalog_write_failed"))?;
    Ok(format!(
        "{prefix}{}.{:032x}.tmp",
        std::process::id(),
        u128::from_le_bytes(nonce)
    ))
}
fn write_new(parent: &File, name: &str, bytes: &[u8]) -> Result<(), Failure> {
    let mut f: File = openat(
        parent,
        name,
        OFlag::O_WRONLY | OFlag::O_CREAT | OFlag::O_EXCL | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC,
        Mode::from_bits_truncate(0o600),
    )
    .map_err(|_| invalid())?
    .into();
    f.write_all(bytes)
        .and_then(|_| f.sync_all())
        .map_err(|_| failure("cigar_catalog_write_failed"))?;
    let before = f.metadata().map_err(|_| invalid())?;
    let current = checked_file(parent, name, bytes.len(), OFlag::O_RDONLY)?.ok_or_else(invalid)?;
    if !same(&before, &current.metadata().map_err(|_| invalid())?) {
        return Err(invalid());
    }
    Ok(())
}
fn rename_exclusive(parent: &File, source: &str) -> Result<(), Failure> {
    #[cfg(any(target_os = "macos", target_os = "linux"))]
    {
        rustix::fs::renameat_with(
            parent,
            source,
            parent,
            NAME,
            rustix::fs::RenameFlags::NOREPLACE,
        )
        .map_err(|_| failure("cigar_catalog_write_failed"))
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        let _ = (parent, source);
        Err(failure("cigar_catalog_platform_unqualified"))
    }
}
pub(super) fn initialize(lock: &WriteLock, bytes: &[u8], key: &[u8; 32]) -> Result<(), Failure> {
    let name = random_name(".cigar-catalog-state.")?;
    nix::sys::stat::mkdirat(
        &lock.directory,
        name.as_str(),
        Mode::from_bits_truncate(0o700),
    )
    .map_err(|_| invalid())?;
    let dir = directory(lock, &name)?.ok_or_else(invalid)?;
    checkpoint("init_directory")?;
    write_new(&dir, KEY, key)?;
    checkpoint("init_key")?;
    write_new(&dir, CACHE, bytes)?;
    checkpoint("init_cache")?;
    dir.sync_all()
        .map_err(|_| failure("cigar_catalog_write_failed"))?;
    checkpoint("init_synced")?;
    check_directory(lock, &name, &dir)?;
    if lock.catalog_pair()?.is_some() {
        return Err(failure("cigar_catalog_state_changed"));
    }
    rename_exclusive(&lock.directory, &name)?;
    checkpoint("init_renamed")?;
    lock.directory
        .sync_all()
        .map_err(|_| failure("cigar_catalog_commit_outcome_unknown"))?;
    checkpoint("init_parent_synced")?;
    check_directory(lock, NAME, &dir)
        .map_err(|_| failure("cigar_catalog_commit_outcome_unknown"))?;
    let pair = lock
        .catalog_pair()
        .map_err(|_| failure("cigar_catalog_commit_outcome_unknown"))?
        .ok_or_else(|| failure("cigar_catalog_commit_outcome_unknown"))?;
    if pair.cache() != bytes || pair.key() != key {
        return Err(failure("cigar_catalog_commit_outcome_unknown"));
    }
    Ok(())
}
fn writable(parent: &File, expected: &[u8]) -> Result<(), Failure> {
    let f = checked_file(parent, CACHE, LIMIT, OFlag::O_WRONLY)?.ok_or_else(invalid)?;
    if f.metadata().map_err(|_| invalid())?.mode() & 0o200 == 0
        || read(parent, CACHE, LIMIT)?.as_deref().map(|v| v.as_slice()) != Some(expected)
    {
        return Err(failure("cigar_catalog_cache_not_writable_or_changed"));
    }
    Ok(())
}
// libc::dev_t differs across Unix targets; the inode comparison uses MetadataExt's u64.
#[allow(clippy::unnecessary_cast)]
pub(super) fn replace(
    lock: &WriteLock,
    expected: &CatalogPair,
    bytes: &[u8],
) -> Result<(), Failure> {
    let dir = directory(lock, NAME)?.ok_or_else(invalid)?;
    staging::recover_files(&dir)?;
    writable(&dir, expected.cache())?;
    let name = random_name(".catalog.json.")?;
    write_new(&dir, &name, bytes)?;
    let inode = checked_file(&dir, &name, LIMIT, OFlag::O_RDONLY)?
        .ok_or_else(invalid)?
        .metadata()
        .map_err(|_| invalid())?;
    let result = (|| {
        checkpoint("update_written")?;
        check_directory(lock, NAME, &dir)?;
        let current = lock.catalog_pair()?.ok_or_else(invalid)?;
        if current.layout != expected.layout
            || current.cache() != expected.cache()
            || current.key() != expected.key()
        {
            return Err(failure("cigar_catalog_state_changed"));
        }
        writable(&dir, expected.cache())?;
        let staged = checked_file(&dir, &name, LIMIT, OFlag::O_RDONLY)?
            .ok_or_else(invalid)?
            .metadata()
            .map_err(|_| invalid())?;
        if !same(&inode, &staged) {
            return Err(invalid());
        }
        renameat(&dir, name.as_str(), &dir, CACHE)
            .map_err(|_| failure("cigar_catalog_write_failed"))?;
        checkpoint("update_renamed")?;
        dir.sync_all()
            .and_then(|_| lock.directory.sync_all())
            .map_err(|_| failure("cigar_catalog_commit_outcome_unknown"))?;
        checkpoint("update_synced")?;
        check_directory(lock, NAME, &dir)
            .map_err(|_| failure("cigar_catalog_commit_outcome_unknown"))?;
        if read(&dir, CACHE, LIMIT)
            .map_err(|_| failure("cigar_catalog_commit_outcome_unknown"))?
            .as_deref()
            .map(|v| v.as_slice())
            != Some(bytes)
        {
            return Err(failure("cigar_catalog_commit_outcome_unknown"));
        }
        Ok(())
    })();
    if let Ok(m) = fstatat(&dir, name.as_str(), AtFlags::AT_SYMLINK_NOFOLLOW) {
        if m.st_dev as u64 == inode.dev() && m.st_ino == inode.ino() {
            let _ = unlinkat(&dir, name.as_str(), UnlinkatFlags::NoRemoveDir);
        }
    }
    result
}

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
fn write_new(parent: &Dir, name: &str, bytes: &[u8]) -> Result<(), Failure> {
    let mut f = parent
        .open_file(name, How::CreateNew)
        .map_err(|_| invalid())?;
    f.write_all(bytes)
        .and_then(|_| f.sync_all())
        .map_err(|_| failure("cigar_catalog_write_failed"))?;
    let before = entry(parent, name, &f)?;
    drop(f);
    let current = checked_file(parent, name, bytes.len(), How::Read)?.ok_or_else(invalid)?;
    if !same(&before, &entry(parent, name, &current)?) {
        return Err(invalid());
    }
    Ok(())
}
pub(super) fn initialize(lock: &WriteLock, bytes: &[u8], key: &[u8; 32]) -> Result<(), Failure> {
    let name = random_name(".cigar-catalog-state.")?;
    lock.directory.create_dir(&name).map_err(|_| invalid())?;
    let dir = directory(lock, &name)?.ok_or_else(invalid)?;
    checkpoint("init_directory")?;
    write_new(&dir, KEY, key)?;
    checkpoint("init_key")?;
    write_new(&dir, CACHE, bytes)?;
    checkpoint("init_cache")?;
    dir.sync()
        .map_err(|_| failure("cigar_catalog_write_failed"))?;
    checkpoint("init_synced")?;
    check_directory(lock, &name, &dir)?;
    let staged = dir.entry().map_err(|_| invalid())?.node;
    if lock.catalog_pair()?.is_some() {
        return Err(failure("cigar_catalog_state_changed"));
    }
    // Windows names a directory only by its path, so the committed
    // directory is reopened and matched by its file ID.
    drop(dir);
    lock.directory
        .rename_new(&name, NAME)
        .map_err(|_| failure("cigar_catalog_write_failed"))?;
    checkpoint("init_renamed")?;
    lock.directory
        .sync()
        .map_err(|_| failure("cigar_catalog_commit_outcome_unknown"))?;
    checkpoint("init_parent_synced")?;
    let committed = directory(lock, NAME)
        .ok()
        .flatten()
        .and_then(|dir| dir.entry().ok())
        .ok_or_else(|| failure("cigar_catalog_commit_outcome_unknown"))?;
    if committed.node != staged {
        return Err(failure("cigar_catalog_commit_outcome_unknown"));
    }
    let pair = lock
        .catalog_pair()
        .map_err(|_| failure("cigar_catalog_commit_outcome_unknown"))?
        .ok_or_else(|| failure("cigar_catalog_commit_outcome_unknown"))?;
    if pair.cache() != bytes || pair.key() != key {
        return Err(failure("cigar_catalog_commit_outcome_unknown"));
    }
    Ok(())
}
fn writable(parent: &Dir, expected: &[u8]) -> Result<(), Failure> {
    let f = checked_file(parent, CACHE, LIMIT, How::Write)?.ok_or_else(invalid)?;
    let writable = entry(parent, CACHE, &f)?.writable;
    drop(f);
    if !writable || read(parent, CACHE, LIMIT)?.as_deref().map(|v| v.as_slice()) != Some(expected) {
        return Err(failure("cigar_catalog_cache_not_writable_or_changed"));
    }
    Ok(())
}
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
    let staged_file = checked_file(&dir, &name, LIMIT, How::Read)?.ok_or_else(invalid)?;
    let inode = entry(&dir, &name, &staged_file)?;
    drop(staged_file);
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
        let file = checked_file(&dir, &name, LIMIT, How::Read)?.ok_or_else(invalid)?;
        let staged = entry(&dir, &name, &file)?;
        drop(file);
        if !same(&inode, &staged) {
            return Err(invalid());
        }
        dir.rename(&name, CACHE)
            .map_err(|_| failure("cigar_catalog_write_failed"))?;
        checkpoint("update_renamed")?;
        dir.sync()
            .and_then(|_| lock.directory.sync())
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
    if let Ok(m) = dir.stat(&name) {
        if m.node == inode.node {
            let _ = dir.remove_file(&name);
        }
    }
    result
}

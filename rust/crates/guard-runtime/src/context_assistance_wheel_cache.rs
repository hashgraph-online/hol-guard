//! Locked artifact cache. Operator imports and native acquisition share the
//! exact same verification and bounded publication path. No wheel is executed.
use super::*;
use guard_cigar_release::{ResolvedRelease, WheelLock};
use std::collections::BTreeMap;

pub(super) fn cached(home: &Path, lock: &WheelLock) -> Result<Option<PathBuf>, String> {
    let directory = store::directory(home, "artifacts", true)?;
    let path = directory.join(format!("{}.whl", lock.sha256));
    match fs::symlink_metadata(&path) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(_) => return Err(error("install_cache_invalid")),
        Ok(_) => {}
    }
    let cached = guard_secure_fs::read_stable(&path, 128 * 1024 * 1024, false)
        .map_err(|_| error("install_cache_invalid"))?;
    if cached.sha256 != lock.sha256 || cached.bytes.len() as u64 != lock.bytes {
        return Err(error("install_cache_invalid"));
    }
    Ok(Some(path))
}

/// Called only while holding the profile's exclusive preparation lease.
pub(super) fn publish(home: &Path, lock: &WheelLock, bytes: &[u8]) -> Result<PathBuf, String> {
    if bytes.len() as u64 != lock.bytes || format!("{:x}", Sha256::digest(bytes)) != lock.sha256 {
        return Err(error("install_artifact_mismatch"));
    }
    if let Some(path) = cached(home, lock)? {
        return Ok(path);
    }
    let directory = store::directory(home, "artifacts", true)?;
    let mut used = 0u64;
    for (index, entry) in fs::read_dir(&directory)
        .map_err(|_| error("install_cache_invalid"))?
        .take(513)
        .enumerate()
    {
        if index >= 512 {
            return Err(error("install_cache_limit"));
        }
        let entry = entry.map_err(|_| error("install_cache_invalid"))?;
        let metadata =
            fs::symlink_metadata(entry.path()).map_err(|_| error("install_cache_invalid"))?;
        if !metadata.is_file() || metadata.file_type().is_symlink() {
            return Err(error("install_cache_invalid"));
        }
        used = used
            .checked_add(metadata.len())
            .ok_or_else(|| error("install_cache_limit"))?;
    }
    if used.saturating_add(lock.bytes) > 512 * 1024 * 1024 {
        return Err(error("install_cache_limit"));
    }
    worker::space(home, lock.bytes)?;
    let path = directory.join(format!("{}.whl", lock.sha256));
    persist_private_bytes(&path, bytes, 128 * 1024 * 1024, "cigar_artifact", home)
        .map_err(|_| error("install_cache_write_failed"))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o400))
            .map_err(|_| error("install_cache_write_failed"))?;
    }
    // The read-only attribute is the Windows counterpart of mode 0400.
    #[cfg(windows)]
    {
        let mut permissions = fs::metadata(&path)
            .map_err(|_| error("install_cache_write_failed"))?
            .permissions();
        permissions.set_readonly(true);
        fs::set_permissions(&path, permissions).map_err(|_| error("install_cache_write_failed"))?;
    }
    Ok(path)
}

pub(super) fn import(
    home: &Path,
    release: &ResolvedRelease,
    inputs: &BTreeMap<String, PathBuf>,
) -> Result<(), String> {
    worker::policy(home)?;
    let locks: Vec<_> = release
        .platform()
        .wheel
        .iter()
        .chain(&release.platform().dependencies)
        .collect();
    if inputs.len() != locks.len()
        || locks
            .iter()
            .any(|lock| !inputs.contains_key(&lock.filename))
    {
        return Err(error("install_inputs_invalid"));
    }
    let _lease = store::lease(home)?;
    for lock in locks {
        let input = guard_secure_fs::read_stable(&inputs[&lock.filename], 128 * 1024 * 1024, false)
            .map_err(|_| error("install_artifact_unreadable"))?;
        publish(home, lock, &input.bytes)?;
    }
    Ok(())
}

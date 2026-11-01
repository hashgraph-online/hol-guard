//! Exact interpreter archive cache for native acquisition and explicit imports.
use super::*;
use guard_cigar_release::ResolvedInterpreterBuild;
pub(super) fn cached(
    home: &Path,
    build: &ResolvedInterpreterBuild,
) -> Result<Option<PathBuf>, String> {
    let path = store::directory(home, "python-artifacts", true)?
        .join(format!("{}.tar.gz", build.build().archive_sha256));
    match fs::symlink_metadata(&path) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(_) => return Err(error("install_cache_invalid")),
        Ok(_) => {}
    }
    let read = guard_secure_fs::read_stable(&path, 128 * 1024 * 1024, false)
        .map_err(|_| error("install_cache_invalid"))?;
    if read.sha256 != build.build().archive_sha256
        || read.bytes.len() as u64 != build.build().archive_bytes
    {
        return Err(error("install_cache_invalid"));
    }
    Ok(Some(path))
}
/// The caller owns the common preparation lease, including native downloads.
pub(super) fn publish(
    home: &Path,
    build: &ResolvedInterpreterBuild,
    bytes: &[u8],
) -> Result<PathBuf, String> {
    if bytes.len() as u64 != build.build().archive_bytes
        || format!("{:x}", Sha256::digest(bytes)) != build.build().archive_sha256
    {
        return Err(error("install_artifact_mismatch"));
    }
    if let Some(path) = cached(home, build)? {
        return Ok(path);
    }
    let directory = store::directory(home, "python-artifacts", true)?;
    let mut used = 0u64;
    for (index, entry) in fs::read_dir(&directory)
        .map_err(|_| error("install_cache_invalid"))?
        .take(33)
        .enumerate()
    {
        if index >= 32 {
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
    if used.saturating_add(build.build().archive_bytes) > 512 * 1024 * 1024 {
        return Err(error("install_cache_limit"));
    }
    worker::space(home, build.build().archive_bytes)?;
    let path = directory.join(format!("{}.tar.gz", build.build().archive_sha256));
    persist_private_bytes(
        &path,
        bytes,
        128 * 1024 * 1024,
        "cigar_python_artifact",
        home,
    )
    .map_err(|_| error("install_cache_write_failed"))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o400))
            .map_err(|_| error("install_cache_write_failed"))?;
    }
    Ok(path)
}
pub(super) fn import(
    home: &Path,
    build: &ResolvedInterpreterBuild,
    path: &Path,
) -> Result<(), String> {
    worker::policy(home)?;
    let _lease = store::lease(home)?;
    let read = guard_secure_fs::read_stable(path, 128 * 1024 * 1024, false)
        .map_err(|_| error("install_artifact_unreadable"))?;
    publish(home, build, &read.bytes).map(|_| ())
}

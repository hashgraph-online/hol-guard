//! Private lifecycle files shared by CIGAR switch jobs: the profile lease,
//! the bounded job directories and race-tolerant private JSON reads.
use super::*;

pub(super) fn directory(home: &Path, name: &str, create: bool) -> Result<PathBuf, String> {
    if !matches!(name, "jobs" | "switch-jobs")
        || !home.is_absolute()
        || home
            .components()
            .any(|c| matches!(c, std::path::Component::ParentDir))
    {
        return Err(error("home_invalid"));
    }
    if create {
        crate::resident_state::ensure_private_directory_under(home, home, true)
            .map_err(|_| error("install_storage_unavailable"))?;
    }
    validate_private_directory(home).map_err(|_| error("registry_not_private"))?;
    let home = fs::canonicalize(home).map_err(|_| error("home_invalid"))?;
    let assistance = home.join("context-assistance");
    let jobs = assistance.join(name);
    for path in [&assistance, &jobs] {
        if create {
            crate::resident_state::ensure_private_directory_under(path, &home, true)
                .map_err(|_| error("install_storage_unavailable"))?;
        }
        validate_private_directory(path).map_err(|_| error("install_storage_unavailable"))?;
    }
    Ok(jobs)
}
pub(super) fn lease(home: &Path) -> Result<fs::File, String> {
    let jobs = directory(home, "jobs", true)?;
    let home = fs::canonicalize(home).map_err(|_| error("home_invalid"))?;
    let file = crate::resident_state::private_lock_file(&jobs.join("preparation.lock"), &home)
        .map_err(|_| error("install_storage_unavailable"))?;
    // The lock lives in the file handle; the checked directory binding is
    // only needed while the file is opened.
    #[cfg(windows)]
    let (file, _binding) = file;
    crate::resident_state::try_lock_exclusive_briefly(&file).map_err(|_| error("install_busy"))?;
    Ok(file)
}
pub(super) fn private_read<T: serde::de::DeserializeOwned>(
    home: &Path,
    path: &Path,
    limit: u64,
    kind: &str,
) -> Result<Option<T>, String> {
    for _ in 0..4 {
        // A rename can race the first path stat/open; malformed bytes still fail.
        let (value, bytes) = match read_private_json(path, limit, kind, home) {
            Ok(Some(snapshot)) => snapshot,
            Ok(None) if replacement_candidate(path) => {
                std::thread::yield_now();
                continue;
            }
            Ok(None) => return Ok(None),
            Err(_cause)
                if replacement_candidate(path)
                    && fs::symlink_metadata(path).is_ok_and(|meta| meta.len() <= limit) =>
            {
                // A stable malformed payload is corruption, not a rename race.
                if guard_secure_fs::read_stable(path, limit as usize, false)
                    .is_ok_and(|current| crate::strict_json_value(&current.bytes).is_err())
                {
                    return Err(error("install_metadata_invalid"));
                }
                std::thread::yield_now();
                continue;
            }
            Err(_cause) => {
                #[cfg(test)]
                eprintln!("private_read first read rejected: {_cause}");
                return Err(error("install_metadata_invalid"));
            }
        };
        let stable = match guard_secure_fs::read_stable(path, limit as usize, false) {
            Ok(stable) => stable,
            Err(cause) if atomic_replacement(path, &cause) => {
                std::thread::yield_now();
                continue;
            }
            Err(_cause) => {
                #[cfg(test)]
                eprintln!("private_read stable read rejected: {_cause:?}");
                return Err(error("install_metadata_invalid"));
            }
        };
        if stable.bytes == bytes {
            return crate::strict_json::from_value(value)
                .map(Some)
                .map_err(|_| {
                    #[cfg(test)]
                    eprintln!("private_read typed decode rejected");
                    error("install_metadata_invalid")
                });
        }
    }
    Err(error("install_metadata_changed"))
}
fn atomic_replacement(path: &Path, cause: &guard_secure_fs::SecureReadError) -> bool {
    use guard_secure_fs::SecureReadError;
    if matches!(
        cause,
        SecureReadError::Changed | SecureReadError::PathChanged
    ) {
        return true;
    }
    // A rename can invalidate any stage of the descriptor walk. Retry other
    // read errors only if the current named leaf is private and single-linked.
    if matches!(cause, SecureReadError::TooLarge) {
        return false;
    }
    if replacement_candidate(path) {
        return true;
    }
    let _ = path;
    false
}
fn replacement_candidate(path: &Path) -> bool {
    #[cfg(windows)]
    {
        let Some(parent) = path
            .parent()
            .and_then(|parent| fs::symlink_metadata(parent).ok())
        else {
            return false;
        };
        fs::symlink_metadata(path).is_ok_and(|meta| {
            parent.is_dir() && guard_cigar_artifacts::host::private_file(path, &meta)
        })
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        let Some(parent) = path
            .parent()
            .and_then(|parent| fs::symlink_metadata(parent).ok())
        else {
            return false;
        };
        fs::symlink_metadata(path).is_ok_and(|meta| {
            parent.is_dir()
                && meta.is_file()
                && meta.nlink() == 1
                && meta.uid() == parent.uid()
                && meta.permissions().mode() & 0o077 == 0
                && meta.permissions().mode() & 0o400 != 0
        })
    }
}
pub(super) fn temporary_name(name: &str) -> bool {
    let Some(name) = name
        .strip_prefix('.')
        .and_then(|name| name.strip_suffix(".tmp"))
    else {
        return false;
    };
    let mut parts = name.rsplitn(3, '.');
    let (Some(stamp), Some(pid), Some(file)) = (parts.next(), parts.next(), parts.next()) else {
        return false;
    };
    let Some(stem) = file
        .strip_suffix(".cancel.json")
        .or_else(|| file.strip_suffix(".json"))
    else {
        return false;
    };
    is_lower_hex(stem, 64)
        && !stamp.is_empty()
        && stamp.len() <= 32
        && stamp.bytes().all(|b| b.is_ascii_digit())
        && !pid.is_empty()
        && pid.len() <= 10
        && pid.bytes().all(|b| b.is_ascii_digit())
}

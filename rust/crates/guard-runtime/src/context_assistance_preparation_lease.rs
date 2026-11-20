//! Lifecycle locking and read-only job lookup do not provision installations.
use super::*;

pub(super) fn directory(home: &Path, name: &str, create: bool) -> Result<PathBuf, String> {
    if !matches!(
        name,
        "jobs" | "python-jobs" | "switch-jobs" | "catalog-jobs" | "catalog-downloads"
    ) || !home.is_absolute()
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
pub(super) fn acquire(home: &Path) -> Result<fs::File, String> {
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

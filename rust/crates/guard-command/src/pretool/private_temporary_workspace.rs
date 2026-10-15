//! macOS gives each user a private temporary directory at
//! `/private/var/folders/<a>/<b>/T`. A workspace created below it (for example
//! with `mktemp -d`) belongs to that user, so paths inside the workspace are
//! not system state even though they sit below `/private/var`.

use std::path::Path;

/// Whether `canonical` lies inside the session's working directory and that
/// directory sits strictly below the home owner's private temporary directory.
#[cfg(target_os = "macos")]
pub(super) fn inside_private_temporary_workspace(
    canonical: &Path,
    home_dir: Option<&str>,
    cwd: Option<&str>,
) -> bool {
    use std::os::unix::fs::MetadataExt;

    let Some(workspace) = cwd.and_then(|cwd| std::fs::canonicalize(cwd).ok()) else {
        return false;
    };
    if !canonical.starts_with(&workspace) {
        return false;
    }
    // Below the root: private/var/folders/<a>/<b>/T/<workspace>...
    let names: Vec<&std::ffi::OsStr> = workspace
        .components()
        .skip(1)
        .map(|part| part.as_os_str())
        .collect();
    if names.len() < 7 || names[..3] != ["private", "var", "folders"] || names[5] != "T" {
        return false;
    }
    let temporary = Path::new("/").join(names[..6].iter().collect::<std::path::PathBuf>());
    let Some(owner) = home_dir
        .and_then(|home| std::fs::metadata(home).ok())
        .map(|metadata| metadata.uid())
    else {
        return false;
    };
    std::fs::symlink_metadata(&temporary).is_ok_and(|metadata| {
        metadata.is_dir() && metadata.uid() == owner && metadata.mode() & 0o077 == 0
    })
}

#[cfg(not(target_os = "macos"))]
pub(super) fn inside_private_temporary_workspace(
    _canonical: &Path,
    _home_dir: Option<&str>,
    _cwd: Option<&str>,
) -> bool {
    false
}

//! macOS gives each user a private temporary directory at
//! `/private/var/folders/<a>/<b>/T`, and `$TMPDIR` points there. Agents keep
//! scratch files in it (a patch to check, a log to read back, a workspace from
//! `mktemp -d`). Only its owner can create an entry in it, so a file below it
//! belongs to that user and is not system state, even though it sits below
//! `/private/var`. Every other screen still runs on the path, so a credential
//! or sensitive file kept there keeps its review.
//!
//! Reading any entry below the directory is routine. Changing files is quiet
//! only inside a workspace created below it; the directory itself is not a
//! workspace.

use std::path::Path;

/// Whether `canonical` lies inside the session's working directory and that
/// directory sits strictly below the home owner's private temporary directory.
pub(super) fn inside_private_temporary_workspace(
    canonical: &Path,
    home_dir: Option<&str>,
    cwd: Option<&str>,
) -> bool {
    cwd.and_then(|cwd| std::fs::canonicalize(cwd).ok())
        .is_some_and(|workspace| {
            canonical.starts_with(&workspace)
                && inside_private_temporary_directory(&workspace, home_dir)
        })
}

/// Whether `canonical` lies strictly below the home owner's private
/// temporary directory, and that directory is owned by the home owner with no
/// access for anyone else.
#[cfg(target_os = "macos")]
pub(super) fn inside_private_temporary_directory(canonical: &Path, home_dir: Option<&str>) -> bool {
    use std::os::unix::fs::MetadataExt;

    // Below the root: private/var/folders/<a>/<b>/T/<entry>...
    let names: Vec<&std::ffi::OsStr> = canonical
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
pub(super) fn inside_private_temporary_directory(
    _canonical: &Path,
    _home_dir: Option<&str>,
) -> bool {
    false
}

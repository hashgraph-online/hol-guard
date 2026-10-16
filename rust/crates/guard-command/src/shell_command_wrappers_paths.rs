//! Native executable-path observations used by transparent wrappers.
#[cfg(unix)]
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
const TRUSTED_INSTALL_DIRS: &[&str] = &["/opt/homebrew/bin", "/usr/local/bin"];

/// POSIX system program directories. On Windows, Git Bash and MSYS2 (the
/// shells harnesses run POSIX commands in) map them into their own install
/// tree, which the host filesystem cannot inspect under these spellings.
const POSIX_SYSTEM_BIN_DIRS: &[&str] =
    &["/bin", "/usr/bin", "/sbin", "/usr/sbin", "/usr/local/bin"];

/// On a Windows host, `Path::is_absolute` rejects a drive-less POSIX spelling
/// such as `/bin/sh` or `/usr/bin/env`, so a wrapper launched through one was
/// never unwrapped and the command it runs escaped inspection. A program that
/// sits directly in a POSIX system directory names the same system tool a
/// bare `sh` lookup does (which is unwrapped by name), so its basename is
/// returned. Any other spelling, and every spelling on a POSIX host (where the
/// path is absolute and checked on disk), returns `None`.
pub(super) fn posix_system_command_basename(token: &str) -> Option<&str> {
    if !cfg!(windows) || token.starts_with("//") || token.contains('\\') {
        return None;
    }
    let (directory, name) = token.rsplit_once('/')?;
    (POSIX_SYSTEM_BIN_DIRS.contains(&directory) && !matches!(name, "" | "." | "..")).then_some(name)
}

/// `is_trusted_absolute_command_path` (:337-349).
pub fn is_trusted_absolute_command_path(
    command_path: &Path,
    cwd: Option<&Path>,
    home_dir: Option<&Path>,
) -> bool {
    if path_is_under(command_path, cwd) || !stable_non_writable_path(command_path) {
        return false;
    }
    if root_owned_path_chain(command_path) {
        return true;
    }
    path_is_under_trusted_install_dir(command_path, home_dir)
}

/// `_stable_non_writable_path` (:352-362).
fn stable_non_writable_path(path: &Path) -> bool {
    for candidate in path.ancestors() {
        if candidate.is_symlink() {
            if !trusted_symlink_component(candidate) {
                return false;
            }
            continue;
        }
        if !path_is_non_writable(candidate) {
            return false;
        }
        if candidate == candidate.parent().unwrap_or(candidate) {
            break;
        }
    }
    true
}

/// `_root_owned_path_chain` (:365-366).
fn root_owned_path_chain(path: &Path) -> bool {
    path.ancestors().all(path_is_root_owned)
}

/// `_path_is_under_trusted_install_dir` (:369-371).
fn path_is_under_trusted_install_dir(path: &Path, _home_dir: Option<&Path>) -> bool {
    TRUSTED_INSTALL_DIRS
        .iter()
        .any(|d| path_is_under(path, Some(Path::new(d))))
}

/// `_path_is_under` (:374-381).
fn path_is_under(path: &Path, base: Option<&Path>) -> bool {
    let Some(base) = base else {
        return false;
    };
    let resolved = resolve(path);
    let base_resolved = resolve(base);
    resolved.starts_with(&base_resolved)
}

/// `Path.resolve(strict=False)` — canonicalize what exists; fall back to the
/// lexically normalized absolute path for missing tails.
fn resolve(path: &Path) -> PathBuf {
    std::fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf())
}

/// `_path_is_root_owned` (:384-385). Missing path → not root-owned.
/// POSIX-only concept; Windows ACLs have no st_uid — treat as not root-owned
/// so downstream checks fall to the non-writable leg (fail-closed parity with
/// the Python early-exit on non-POSIX).
fn path_is_root_owned(path: &Path) -> bool {
    #[cfg(unix)]
    {
        std::fs::metadata(path)
            .map(|m| m.uid() == 0)
            .unwrap_or(false)
    }
    #[cfg(not(unix))]
    {
        let _ = path;
        false
    }
}

/// `_trusted_symlink_component` (:388-397).
fn trusted_symlink_component(path: &Path) -> bool {
    let Ok(meta) = std::fs::symlink_metadata(path) else {
        return false;
    };
    #[cfg(unix)]
    if meta.uid() != 0 {
        return false;
    }
    #[cfg(not(unix))]
    let _ = &meta;
    let Ok(resolved) = std::fs::canonicalize(path) else {
        return false;
    };
    path_is_root_owned(&resolved) && path_is_non_writable(&resolved)
}

/// `_path_is_non_writable` (:400-401).
fn path_is_non_writable(path: &Path) -> bool {
    #[cfg(unix)]
    {
        std::fs::metadata(path)
            .map(|m| m.mode() & 0o022 == 0)
            .unwrap_or(false)
    }
    #[cfg(not(unix))]
    {
        std::fs::metadata(path)
            .map(|m| m.permissions().readonly())
            .unwrap_or(false)
    }
}

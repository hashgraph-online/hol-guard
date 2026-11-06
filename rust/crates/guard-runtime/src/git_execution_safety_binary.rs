//! Git executable resolution and trust.

use std::fs;
use std::path::{Path, PathBuf};

use crate::git_execution_safety_config::Environment;

/// `os.defpath` on POSIX, used when the snapshot carries no `PATH`.
const DEFAULT_PATH: &str = "/bin:/usr/bin";

#[cfg(unix)]
pub(crate) fn executable_file(path: &Path) -> bool {
    use nix::unistd::{access, AccessFlags};
    path.is_file() && access(path, AccessFlags::X_OK).is_ok()
}

#[cfg(not(unix))]
pub(crate) fn executable_file(path: &Path) -> bool {
    path.is_file()
}

/// A path that exists and can be executed. Windows treats every existing path
/// as executable because mode bits carry no ACL evidence.
pub(crate) fn exists_and_executable(path: &Path) -> bool {
    path.exists() && (cfg!(not(unix)) || executable_file(path))
}

fn expand_user(entry: &str, environment: &Environment, home: &Path) -> PathBuf {
    let configured = environment
        .get("HOME")
        .filter(|value| !value.is_empty())
        .map(Path::new)
        .unwrap_or(home);
    if entry == "~" {
        configured.to_path_buf()
    } else if let Some(rest) = entry.strip_prefix("~/") {
        configured.join(rest)
    } else {
        PathBuf::from(entry)
    }
}

/// Resolve `command` with relative `PATH` entries interpreted from `cwd`.
pub(crate) fn which_for_cwd(
    command: &str,
    cwd: &Path,
    environment: &Environment,
    home: &Path,
) -> Option<PathBuf> {
    let path = environment.get("PATH").map_or(DEFAULT_PATH, String::as_str);
    path.split(if cfg!(windows) { ';' } else { ':' })
        .map(|entry| {
            let candidate = expand_user(
                if entry.is_empty() { "." } else { entry },
                environment,
                home,
            );
            if candidate.is_absolute() {
                candidate
            } else {
                cwd.join(candidate)
            }
        })
        .map(|directory| directory.join(command))
        .find(|candidate| executable_file(candidate))
}

/// Reject Git executables from user-controlled or broadly writable roots.
#[cfg(unix)]
pub(crate) fn binary_path_is_trusted(
    git_path: &Path,
    cwd: &Path,
    home: &Path,
    groups: &[u32],
) -> bool {
    use nix::unistd::getuid;
    use std::os::unix::fs::MetadataExt;
    if !git_path.is_absolute() {
        return false;
    }
    let (Ok(cwd), Ok(home)) = (fs::canonicalize(cwd), fs::canonicalize(home)) else {
        return false;
    };
    let mut untrusted = vec![home, PathBuf::from("/tmp"), PathBuf::from("/private/tmp")];
    if let Ok(resolved) = fs::canonicalize("/tmp") {
        untrusted.push(resolved);
    }
    if cwd != Path::new("/") {
        untrusted.push(cwd);
    }
    if untrusted.iter().any(|root| git_path.starts_with(root)) {
        return false;
    }
    let uid = getuid().as_raw();
    for candidate in git_path.ancestors() {
        let Ok(metadata) = fs::metadata(candidate) else {
            return false;
        };
        let mode = metadata.mode();
        if mode & 0o002 != 0 {
            return false;
        }
        if mode & 0o020 != 0 && !groups.contains(&metadata.gid()) {
            return false;
        }
        if candidate == git_path && metadata.uid() != 0 && metadata.uid() != uid {
            return false;
        }
    }
    true
}

/// Windows has no verified POSIX ownership evidence; the proof stays closed.
#[cfg(not(unix))]
pub(crate) fn binary_path_is_trusted(
    _git_path: &Path,
    _cwd: &Path,
    _home: &Path,
    _groups: &[u32],
) -> bool {
    false
}

/// Resolve Git from the snapshot `PATH` and reject user-controlled binaries.
pub(crate) fn resolve_trusted_git(
    cwd: &Path,
    environment: &Environment,
    home: &Path,
    groups: &[u32],
) -> Option<PathBuf> {
    let execution_cwd = fs::canonicalize(cwd).ok()?;
    let found = which_for_cwd("git", &execution_cwd, environment, home)?;
    let resolved = fs::canonicalize(found).ok()?;
    binary_path_is_trusted(&resolved, &execution_cwd, home, groups).then_some(resolved)
}

/// Whether the current account's passwd home matches the configured `HOME`
/// and `XDG_CONFIG_HOME`, so global Git configuration is the account's own.
#[cfg(unix)]
pub(crate) fn global_config_environment_is_stable(
    environment: &Environment,
    account_home: Option<&str>,
) -> bool {
    let Some(account) = account_home.and_then(|path| fs::canonicalize(path).ok()) else {
        return false;
    };
    let Some(configured) = environment
        .get("HOME")
        .and_then(|path| fs::canonicalize(path).ok())
    else {
        return false;
    };
    let xdg = environment
        .get("XDG_CONFIG_HOME")
        .map_or("", String::as_str);
    configured == account
        && (xdg.is_empty()
            || resolve_non_strict(Path::new(xdg))
                .is_some_and(|resolved| resolved == account.join(".config")))
}

/// Resolve symlinks in the longest existing prefix and append the remaining
/// components, so a configured directory that does not exist yet still compares
/// equal to its final location. Relative `.`/`..` in the missing tail fail closed.
#[cfg(unix)]
fn resolve_non_strict(path: &Path) -> Option<PathBuf> {
    use std::path::Component;
    let mut existing = path;
    let mut tail: Vec<&std::ffi::OsStr> = Vec::new();
    loop {
        if let Ok(resolved) = fs::canonicalize(existing) {
            let mut resolved = resolved;
            for name in tail.iter().rev() {
                resolved.push(name);
            }
            return Some(resolved);
        }
        let name = match existing.components().next_back()? {
            Component::Normal(name) => name,
            _ => return None,
        };
        tail.push(name);
        existing = existing.parent()?;
    }
}

#[cfg(not(unix))]
pub(crate) fn global_config_environment_is_stable(
    _environment: &Environment,
    _account_home: Option<&str>,
) -> bool {
    false
}

/// Accept a stable global hook while rejecting repository-controlled hooks.
#[cfg(unix)]
pub(crate) fn trusted_global_push_hook(path: &Path, repository: &Path) -> bool {
    use nix::unistd::getuid;
    use std::os::unix::fs::MetadataExt;
    if path.starts_with(repository) {
        return false;
    }
    let Ok(metadata) = fs::metadata(path) else {
        return false;
    };
    let is_link = fs::symlink_metadata(path).is_ok_and(|link| link.file_type().is_symlink());
    metadata.is_file()
        && !is_link
        && (metadata.uid() == 0 || metadata.uid() == getuid().as_raw())
        && metadata.mode() & 0o022 == 0
}

#[cfg(not(unix))]
pub(crate) fn trusted_global_push_hook(_path: &Path, _repository: &Path) -> bool {
    false
}

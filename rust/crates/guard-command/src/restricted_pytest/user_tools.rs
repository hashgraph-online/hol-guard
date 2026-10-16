//! The caller's own tool directories a workspace sandbox may execute from.
//!
//! A `bin` directory on the caller's PATH, such as `~/.local/bin` or a
//! language SDK's, or a package manager's home that holds its shims
//! directly (`PNPM_HOME`), names tools a run expects to find. It is granted,
//! read-only, only when it lies outside the workspace, credential folders
//! and agent state, and when no account but this user or root can change it
//! or any directory above it, so nothing it names can be swapped by anyone
//! else. The ownership rule is `pretool::path_trust::private_directory`.
use super::*;
use std::os::unix::fs::MetadataExt;
use std::path::Component;

/// Package-manager homes that hold their shims directly instead of in `bin`,
/// relative to HOME. They are granted even below `Library`.
const TOOL_HOMES: &[&str] = &["Library/pnpm", ".local/share/pnpm"];
/// Agent and Guard state below HOME. Guard's package shims live there and
/// must never answer for a tool inside the sandbox.
const AGENT_STATE: &[&str] = &[".claude", ".codex", ".hol-guard", ".omp"];
/// Corepack's default cache, relative to HOME.
const COREPACK_CACHE: &str = ".cache/node/corepack";

/// `canonical`, the resolved PATH entry, when it is a sealed tool directory
/// of the caller's that a workspace run may read and execute from.
pub(super) fn tool_root(canonical: &Path, homes: &[PathBuf], workspace: &Path) -> Option<PathBuf> {
    let workspace = workspace
        .canonicalize()
        .unwrap_or_else(|_| workspace.to_path_buf());
    let tool_home = homes.iter().any(|home| {
        TOOL_HOMES
            .iter()
            .any(|tool| home.join(tool).as_path() == canonical)
    });
    let named = canonical.file_name().and_then(OsStr::to_str) == Some("bin");
    let depth = canonical
        .components()
        .filter(|component| matches!(component, Component::Normal(_)))
        .count();
    let admitted = (named || tool_home)
        && canonical.is_absolute()
        && depth >= 2
        && !homes.is_empty()
        && !canonical.starts_with(&workspace)
        && !workspace.starts_with(canonical)
        && homes.iter().all(|home| {
            !AGENT_STATE
                .iter()
                .any(|state| canonical.starts_with(home.join(state)))
                && (tool_home || !sensitive_for_exec(canonical, home))
        })
        && sealed_ancestry(canonical);
    admitted.then(|| canonical.to_path_buf())
}

/// Corepack's cache below `home`, when it is sealed like a tool directory.
/// A Corepack shim (`pnpm`, `yarn`) runs the package-manager version stored
/// there; the sandbox has no network to fetch it again, so the cache is
/// granted read-only rather than replaced by an empty private one.
pub(super) fn corepack_home(home: &Path) -> Option<PathBuf> {
    let cache = home.join(COREPACK_CACHE).canonicalize().ok()?;
    (cache.starts_with(home) && cache.is_dir() && sealed_ancestry(&cache)).then_some(cache)
}

/// [`corepack_home`] for this account's HOME from the password database.
pub(in crate::restricted_pytest) fn host_corepack_home() -> Option<PathBuf> {
    corepack_home(&host_home_directory()?)
}

/// Every directory from `/` down to `path` is this user's or root's and no
/// other account can write it, sticky or not.
fn sealed_ancestry(path: &Path) -> bool {
    let uid = nix::unistd::geteuid().as_raw();
    path.ancestors()
        .all(|directory| private_directory(directory, uid))
}

/// `path_trust::private_directory`: a directory, read without following a
/// link, that belongs to `uid` or root and that no other user can write.
fn private_directory(path: &Path, uid: u32) -> bool {
    std::fs::symlink_metadata(path).is_ok_and(|metadata| {
        metadata.is_dir()
            && (metadata.uid() == uid || metadata.uid() == 0)
            && metadata.mode() & 0o022 == 0
    })
}

#[cfg(test)]
#[path = "user_tools_tests.rs"]
mod tests;

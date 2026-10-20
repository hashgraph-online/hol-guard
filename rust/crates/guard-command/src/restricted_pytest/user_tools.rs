//! The caller's own tool directories a workspace sandbox may execute from.
//!
//! A `bin` or `shims` directory on the caller's PATH, such as `~/.local/bin`,
//! a language SDK's, or a version manager's (`~/.pyenv/shims`), or a package
//! manager's home that holds its shims directly (`PNPM_HOME`), names tools a
//! run expects to find. It is granted, read-only, only when it lies outside
//! the workspace, credential folders and agent state, and when no account but
//! this user or root can change it or any directory above it, so nothing it
//! names can be swapped by anyone else. The ownership rule is
//! `pretool::path_trust::private_directory`.
use super::*;
use std::os::unix::fs::MetadataExt;
use std::path::Component;

/// Package-manager homes that hold their shims directly instead of in `bin`,
/// relative to HOME. They are granted even below `Library`.
const TOOL_HOMES: &[&str] = &["Library/pnpm", ".local/share/pnpm"];
/// Directory names a PATH entry uses for the tools it offers. A version
/// manager (pyenv, rye, asdf, rbenv) puts its `shims` directory on PATH, not
/// the `bin` directory the shims dispatch to; both name tools the same way.
const TOOL_DIRECTORY_NAMES: &[&str] = &["bin", "shims"];
/// Agent and Guard state below HOME. Guard's package shims live there and
/// must never answer for a tool inside the sandbox.
const AGENT_STATE: &[&str] = &[".claude", ".codex", ".hol-guard", ".omp"];
/// Corepack's default cache, relative to HOME.
const COREPACK_CACHE: &str = ".cache/node/corepack";
/// Go's module cache, below GOPATH's default. It holds the dependency sources
/// a build compiles, written read-only by `go` itself.
const GO_MODULE_CACHE: &str = "go/pkg/mod";
/// Cargo's caches of fetched crate sources, relative to HOME. The run gets
/// its own `CARGO_HOME`, where cargo takes its locks, with these linked into
/// it.
const CARGO_CACHES: &[&str] = &[".cargo/registry", ".cargo/git"];
/// A rustup installation, relative to HOME.
const RUSTUP_HOME: &str = ".rustup";

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
    let named = canonical
        .file_name()
        .and_then(OsStr::to_str)
        .is_some_and(|name| TOOL_DIRECTORY_NAMES.contains(&name));
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

/// Shared directories below HOME that many unrelated tools write into. A
/// `shims` directory inside one of them names its own tools, but its
/// neighbours are not that manager's machinery, so none of them is granted.
const SHARED_HOME_ROOTS: &[&str] = &[".cache", ".local", ".var"];

/// The version manager's own root, as the parent of an accepted `shims`
/// directory, when granting that root's contents grants only this manager.
/// It has to be a directory of the manager's own directly below a home
/// (`~/.pyenv`, `~/.rye`), never a home itself, agent state, a credential
/// folder, or a shared area such as `~/.local` that other tools also fill.
fn manager_root<'a>(shims: &'a Path, homes: &[PathBuf]) -> Option<&'a Path> {
    let root = shims.parent()?;
    let home = homes
        .iter()
        .find(|home| root.parent() == Some(home.as_path()))?;
    let name = root.file_name().and_then(OsStr::to_str)?;
    let shared = SHARED_HOME_ROOTS.contains(&name) || AGENT_STATE.contains(&name);
    (!shared && !sensitive_for_exec(root, home)).then_some(root)
}

/// The sealed sibling directories of an accepted `shims` directory, which
/// hold the machinery its shims dispatch to. A pyenv shim runs
/// `~/.pyenv/libexec/pyenv`, which runs an interpreter in
/// `~/.pyenv/versions`; rye's shims run its own tree. Granting the shims
/// directory alone contains the command and then fails it. Directories only,
/// so a credential file beside them (`~/.rye/credentials`) is never read, and
/// each must clear what [`tool_root`] asks of the shims directory itself.
pub(super) fn shim_siblings(shims: &Path, homes: &[PathBuf], workspace: &Path) -> Vec<PathBuf> {
    if shims.file_name().and_then(OsStr::to_str) != Some("shims") {
        return Vec::new();
    }
    let Some(root) = manager_root(shims, homes) else {
        return Vec::new();
    };
    let Ok(entries) = std::fs::read_dir(root) else {
        return Vec::new();
    };
    let workspace = workspace
        .canonicalize()
        .unwrap_or_else(|_| workspace.to_path_buf());
    let mut siblings: Vec<PathBuf> = Vec::new();
    for entry in entries.flatten().take(64) {
        let path = entry.path();
        if path == shims || !path.is_dir() {
            continue;
        }
        let Ok(canonical) = path.canonicalize() else {
            continue;
        };
        if canonical.starts_with(shims)
            || canonical.starts_with(&workspace)
            || workspace.starts_with(&canonical)
            || !sealed_ancestry(&canonical)
            || homes.iter().any(|home| {
                AGENT_STATE
                    .iter()
                    .any(|state| canonical.starts_with(home.join(state)))
                    || sensitive_for_exec(&canonical, home)
            })
        {
            continue;
        }
        if !siblings.contains(&canonical) {
            siblings.push(canonical);
        }
        if siblings.len() == 16 {
            break;
        }
    }
    siblings
}

/// `relative` below `home`, when it is sealed like a tool directory. A
/// toolchain cache holds what a build reads and the sandbox has no network to
/// fetch again, so it is granted read-only rather than replaced by an empty
/// private one; what the build writes goes to a private directory instead.
fn sealed_cache(home: &Path, relative: &str) -> Option<PathBuf> {
    let cache = home.join(relative).canonicalize().ok()?;
    (cache.starts_with(home) && cache.is_dir() && sealed_ancestry(&cache)).then_some(cache)
}

/// Corepack's cache, from which a shim (`pnpm`, `yarn`) runs the
/// package-manager version it stores.
pub(super) fn corepack_home(home: &Path) -> Option<PathBuf> {
    sealed_cache(home, COREPACK_CACHE)
}

/// Go's module cache, holding the dependency sources a build compiles. `go`
/// never writes it during a build.
pub(super) fn go_module_cache(home: &Path) -> Option<PathBuf> {
    sealed_cache(home, GO_MODULE_CACHE)
}

/// Cargo's registry and git checkouts, holding the crate sources a build
/// compiles. They sit beside `credentials.toml`, which stays out of reach
/// because each directory is granted on its own.
pub(super) fn cargo_caches(home: &Path) -> Vec<(&'static str, PathBuf)> {
    CARGO_CACHES
        .iter()
        .filter_map(|relative| {
            let name = relative.rsplit('/').next()?;
            Some((name, sealed_cache(home, relative)?))
        })
        .collect()
}

/// The rustup installation, from which `cargo` and `rustc` resolve the
/// toolchain a build runs.
pub(super) fn rustup_home(home: &Path) -> Option<PathBuf> {
    sealed_cache(home, RUSTUP_HOME)
}

/// [`go_module_cache`] for this account's HOME from the password database.
pub(in crate::restricted_pytest) fn host_go_module_cache() -> Option<PathBuf> {
    go_module_cache(&host_home_directory()?)
}

/// [`cargo_caches`] for this account's HOME from the password database.
pub(in crate::restricted_pytest) fn host_cargo_caches() -> Vec<(&'static str, PathBuf)> {
    host_home_directory()
        .map(|home| cargo_caches(&home))
        .unwrap_or_default()
}

/// [`rustup_home`] for this account's HOME from the password database.
pub(in crate::restricted_pytest) fn host_rustup_home() -> Option<PathBuf> {
    rustup_home(&host_home_directory()?)
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

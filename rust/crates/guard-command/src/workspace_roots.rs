//! Which directory a contained run may treat as its workspace.
//!
//! A workspace must be a real directory that is neither a filesystem root nor
//! a sensitive place inside somebody's home, because a sandbox rooted there
//! would grant the run the account's credentials along with its source. The
//! restricted launchers and the pre-tool containment review both decide this,
//! so the rule lives at the crate's base rather than inside either of them.

use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::sync::LazyLock;

static SENSITIVE_HOME_ROOT_NAMES: LazyLock<HashSet<&'static str>> = LazyLock::new(|| {
    HashSet::from([
        ".aws", ".azure", ".config", ".docker", ".gnupg", ".kube", ".ssh", "Library",
    ])
});

/// The account home from the password database, which `$HOME` cannot move.
pub(crate) fn host_home_directory() -> Option<PathBuf> {
    nix::unistd::User::from_uid(nix::unistd::getuid())
        .ok()
        .flatten()?
        .dir
        .canonicalize()
        .ok()
}

/// The canonical workspace for `cwd`, or `None` for a missing directory or a
/// filesystem, home, temporary or credential-directory root.
pub(crate) fn workspace_admissible(cwd: &Path, home: Option<&Path>) -> Option<PathBuf> {
    let resolved = cwd.canonicalize().ok()?;
    (resolved.is_dir() && !workspace_is_broad_or_sensitive_for_home(&resolved, home))
        .then_some(resolved)
}

pub(crate) fn workspace_is_broad_or_sensitive_for_home(
    workspace: &Path,
    home: Option<&Path>,
) -> bool {
    let broad_roots: HashSet<PathBuf> = [
        "/",
        "/Users",
        "/etc",
        "/home",
        "/private",
        "/private/tmp",
        "/private/var",
        "/tmp",
        "/var",
        "/var/tmp",
    ]
    .iter()
    .map(PathBuf::from)
    .collect();
    if broad_roots.contains(workspace) {
        return true;
    }
    // The caller home is an extra root. It must not replace the account home
    // from the password database, or a different `$HOME` would hide that root.
    let mut homes = Vec::new();
    if let Some(host) = host_home_directory() {
        homes.push(host);
    }
    if let Some(path) = home {
        let caller = path.canonicalize().unwrap_or_else(|_| path.to_path_buf());
        if !homes.iter().any(|existing| existing == &caller) {
            homes.push(caller);
        }
    }
    if homes.is_empty() {
        return true;
    }
    homes
        .iter()
        .any(|home| sensitive_under_home(workspace, home))
}

fn sensitive_under_home(workspace: &Path, home: &Path) -> bool {
    if workspace == home
        || home
            .ancestors()
            .skip(1)
            .any(|ancestor| ancestor == workspace)
    {
        return true;
    }
    let Ok(relative) = workspace.strip_prefix(home) else {
        return false;
    };
    match relative.components().next() {
        Some(component) => {
            SENSITIVE_HOME_ROOT_NAMES.contains(component.as_os_str().to_string_lossy().as_ref())
        }
        None => false,
    }
}

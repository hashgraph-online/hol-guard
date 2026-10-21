use std::path::{Path, PathBuf};

pub(super) fn canonical_write_target(target: &Path) -> Option<PathBuf> {
    let mut existing = target;
    let mut missing = Vec::new();
    loop {
        match existing.symlink_metadata() {
            Ok(_) => {
                // Resolve existing links, including the ancestor of a new subtree.
                // Dangling links and non-directory ancestors are not new paths.
                let canonical = std::fs::canonicalize(existing).ok()?;
                if missing.is_empty() {
                    return canonical.is_file().then_some(canonical);
                }
                if !canonical.is_dir() {
                    return None;
                }
                return Some(
                    missing
                        .iter()
                        .rev()
                        .fold(canonical, |path, name| path.join(name)),
                );
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                missing.push(existing.file_name()?.to_os_string());
                existing = existing.parent()?;
            }
            Err(_) => return None,
        }
    }
}

// A matching repository name is not proof. Git's common directory and the
// registered worktree backlink must agree after resolving every symlink.
pub(super) fn same_repository_worktree(workspace: &Path, target: &Path) -> bool {
    let Some((source_root, source)) = repository_common_directory(workspace) else {
        return false;
    };
    let Some((root, admin)) = target.ancestors().find_map(|root| {
        let text = bounded_git_metadata(&root.join(".git"))?;
        let path = text.trim().strip_prefix("gitdir: ")?;
        let admin = std::fs::canonicalize(root.join(path)).ok()?;
        Some((root, admin))
    }) else {
        return false;
    };
    let Some(common) = bounded_git_metadata(&admin.join("commondir"))
        .and_then(|path| std::fs::canonicalize(admin.join(path.trim())).ok())
    else {
        return false;
    };
    root != source_root
        && common == source
        && admin.starts_with(common.join("worktrees"))
        && bounded_git_metadata(&admin.join("gitdir"))
            .and_then(|path| std::fs::canonicalize(admin.join(path.trim())).ok())
            .is_some_and(|backlink| backlink == root.join(".git"))
}

/// The shared git directory of the linked worktree that contains `workspace`.
/// The worktree's admin entry must sit under `<common>/worktrees` and its
/// `gitdir` backlink must name this checkout, so a stray `.git` file cannot
/// nominate an unrelated directory.
pub(in crate::pretool) fn linked_worktree_common_dir(workspace: &Path) -> Option<PathBuf> {
    let root = workspace
        .ancestors()
        .find(|root| root.join(".git").symlink_metadata().is_ok())?;
    let text = bounded_git_metadata(&root.join(".git"))?;
    let admin = std::fs::canonicalize(root.join(text.trim().strip_prefix("gitdir: ")?)).ok()?;
    let common = bounded_git_metadata(&admin.join("commondir"))
        .and_then(|path| std::fs::canonicalize(admin.join(path.trim())).ok())?;
    let backlink = bounded_git_metadata(&admin.join("gitdir"))
        .and_then(|path| std::fs::canonicalize(admin.join(path.trim())).ok())?;
    let root = std::fs::canonicalize(root).ok()?;
    (common.file_name() == Some(".git".as_ref())
        && admin.starts_with(common.join("worktrees"))
        && backlink == root.join(".git"))
    .then_some(common)
}

/// The shared Git directory and admin entry of the linked worktree rooted at
/// `root`, both canonical. `root/.git` must be a plain gitfile naming an
/// admin entry directly under `<common>/worktrees` whose `gitdir` backlink
/// names it, the common directory must be a checkout's `.git`, and neither
/// may hold the other.
pub(crate) fn linked_worktree_dirs(root: &Path) -> Option<(PathBuf, PathBuf)> {
    let root = std::fs::canonicalize(root).ok()?;
    if !root.join(".git").symlink_metadata().ok()?.is_file() {
        return None;
    }
    let text = bounded_git_metadata(&root.join(".git"))?;
    let admin = std::fs::canonicalize(root.join(text.trim().strip_prefix("gitdir: ")?)).ok()?;
    let common = bounded_git_metadata(&admin.join("commondir"))
        .and_then(|path| std::fs::canonicalize(admin.join(path.trim())).ok())?;
    let backlink = bounded_git_metadata(&admin.join("gitdir"))
        .and_then(|path| std::fs::canonicalize(admin.join(path.trim())).ok())?;
    (common.file_name() == Some(".git".as_ref())
        && common.is_dir()
        && admin.parent() == Some(common.join("worktrees").as_path())
        && backlink == root.join(".git")
        && !root.starts_with(&common)
        && !common.starts_with(&root))
    .then_some((common, admin))
}

pub(in crate::pretool) fn repository_common_directory(
    workspace: &Path,
) -> Option<(PathBuf, PathBuf)> {
    for root in workspace.ancestors() {
        let marker = root.join(".git");
        if marker.is_dir() {
            return std::fs::canonicalize(marker)
                .ok()
                .map(|common| (root.to_path_buf(), common));
        }
        if let Some(text) = bounded_git_metadata(&marker) {
            let admin =
                std::fs::canonicalize(root.join(text.trim().strip_prefix("gitdir: ")?)).ok()?;
            return bounded_git_metadata(&admin.join("commondir"))
                .and_then(|path| std::fs::canonicalize(admin.join(path.trim())).ok())
                .map(|common| (root.to_path_buf(), common));
        }
    }
    None
}

fn bounded_git_metadata(path: &Path) -> Option<String> {
    use std::io::Read;
    // A named pipe would block File::open until a writer appears and hold a
    // resident worker past the request deadline. Open without blocking, then
    // keep only a regular file.
    let file = open_git_metadata(path)?;
    if !file.metadata().ok()?.is_file() {
        return None;
    }
    let mut text = String::new();
    file.take(4097).read_to_string(&mut text).ok()?;
    (text.len() <= 4096).then_some(text)
}

#[cfg(unix)]
fn open_git_metadata(path: &Path) -> Option<std::fs::File> {
    use std::os::unix::fs::OpenOptionsExt;
    std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NONBLOCK)
        .open(path)
        .ok()
}

#[cfg(not(unix))]
fn open_git_metadata(path: &Path) -> Option<std::fs::File> {
    if !path.symlink_metadata().ok()?.file_type().is_file() {
        return None;
    }
    std::fs::File::open(path).ok()
}

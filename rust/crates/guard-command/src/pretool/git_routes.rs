#[path = "git_routes_temporary.rs"]
mod temporary;

use temporary::owned_below;
pub(in crate::pretool) use temporary::owned_temporary_directory;
pub(in crate::pretool) use temporary::owned_temporary_roots;
pub(in crate::pretool) use temporary::temporary_checkout_parent;

pub(crate) fn git_route_within_workspace(target: &str, context: super::PathContext<'_>) -> bool {
    let Some(cwd) = context.cwd else {
        return false;
    };
    if !std::path::Path::new(cwd).is_absolute() {
        return false;
    }
    let expand_context_path = |value: &str| {
        let Some(rest) = value.strip_prefix('~') else {
            return Some(std::path::PathBuf::from(value));
        };
        if !rest.is_empty() && !rest.starts_with('/') {
            return None;
        }
        let home = context.home_dir?;
        Some(std::path::Path::new(home).join(rest.trim_start_matches('/')))
    };
    let Some(workspace) =
        expand_context_path(cwd).and_then(|path| std::fs::canonicalize(path).ok())
    else {
        return false;
    };
    let Some(target) = expand_context_path(target) else {
        return false;
    };
    let target = if target.is_absolute() {
        target
    } else {
        workspace.join(target)
    };
    let Ok(target) = std::fs::canonicalize(target) else {
        return false;
    };
    if !target.is_dir() {
        return false;
    }
    if !target.starts_with(&workspace) {
        return registered_worktree_of_workspace(&target, &workspace)
            || repository_below_home(&target, context)
            || repository_owned_outside_home(&target, context);
    }
    target
        .ancestors()
        .take_while(|path| path.starts_with(&workspace))
        .find_map(|path| {
            let entry = path.join(".git");
            let metadata = std::fs::symlink_metadata(&entry).ok()?;
            Some(git_entry_within_workspace(&entry, &metadata, &workspace))
        })
        .is_some_and(|allowed| allowed)
}

/// Agents working from a multi-repository parent read sibling repositories
/// with `git -C ../other log`. A route outside the working directory is
/// treated like a read of that directory: it must sit strictly below home or
/// below the shared temporary directory, every component below that root must
/// be a non-hidden directory that clears the sensitive-path screens, and the
/// repository root must hold a real `.git` directory below such a root or be a
/// registered linked worktree of such a repository, so neither the root
/// itself nor a symlinked or forged repository qualifies. Below `/tmp` every
/// directory must also belong to the home owner and be writable by no one
/// else, so another user cannot have planted or swapped the checkout. The Git
/// configuration probe still runs against the `-C` target and rejects
/// executable helpers.
pub(in crate::pretool) fn repository_below_home(
    target: &std::path::Path,
    context: super::PathContext<'_>,
) -> bool {
    let Some(home) = context
        .home_dir
        .and_then(|home| std::fs::canonicalize(home).ok())
    else {
        return false;
    };
    let temporary = owned_temporary_roots();
    let root_of = |path: &std::path::Path| {
        if path.starts_with(&home) {
            Some((home.as_path(), false))
        } else {
            temporary
                .iter()
                .find(|root| path.starts_with(root))
                .map(|root| (root.as_path(), true))
        }
    };
    let below_root = |path: &std::path::Path| {
        let Some((root, owned)) = root_of(path) else {
            return false;
        };
        path.strip_prefix(root).is_ok_and(|relative| {
            !relative.as_os_str().is_empty()
                && relative.components().all(|part| {
                    matches!(part, std::path::Component::Normal(name) if !name.to_string_lossy().starts_with('.'))
                })
        }) && (!owned || owned_below(root, path, &home))
            && super::read_paths::resolved_path_allowed(path, context.home_dir, context.cwd)
            && !super::read_paths::inside_agent_state_tree(path, context.home_dir)
    };
    let Some((root, _)) = root_of(target).filter(|_| below_root(target)) else {
        return false;
    };
    target
        .ancestors()
        .take_while(|path| *path != root)
        .find_map(|path| Some((path, std::fs::symlink_metadata(path.join(".git")).ok()?)))
        .is_some_and(|(repository, metadata)| {
            metadata.is_dir()
                || (metadata.is_file() && linked_worktree_of_repository(repository, &below_root))
        })
}

/// Agents clone or create linked worktrees under a scratch location such as
/// `/tmp` and read them with `git -C`. A repository outside both the working
/// directory and home is routable under the same proofs as one below home,
/// plus ownership: the work tree root, its `.git` entry and every path
/// component are non-hidden, the path clears the sensitive-path screens, the
/// root holds a real `.git` directory (or a registered linked worktree of
/// one) and both are owned by the current user and writable by no one else.
/// Git itself refuses a repository owned by someone else. The configuration
/// probe still rejects executable helpers for the `-C` target.
#[cfg(unix)]
fn repository_owned_outside_home(
    target: &std::path::Path,
    context: super::PathContext<'_>,
) -> bool {
    use std::os::unix::fs::MetadataExt;
    let Some(home) = context
        .home_dir
        .and_then(|home| std::fs::canonicalize(home).ok())
    else {
        return false;
    };
    if target.starts_with(&home) || home.starts_with(target) {
        return false;
    }
    let screened = |path: &std::path::Path| {
        path.is_absolute()
            && path.components().count() > 2
            && path.components().all(|part| match part {
                std::path::Component::RootDir => true,
                std::path::Component::Normal(name) => !name.to_string_lossy().starts_with('.'),
                _ => false,
            })
            && super::read_paths::resolved_path_allowed(path, context.home_dir, context.cwd)
            && !super::read_paths::inside_agent_state_tree(path, context.home_dir)
    };
    if !screened(target) {
        return false;
    }
    let me = nix::unistd::geteuid().as_raw();
    // Nobody else may write there either, or another user could swap the
    // `.git` entry after this check.
    let owned = |path: &std::path::Path| {
        std::fs::symlink_metadata(path)
            .is_ok_and(|metadata| metadata.uid() == me && metadata.mode() & 0o022 == 0)
    };
    let Some((root, metadata)) = target
        .ancestors()
        .find_map(|path| Some((path, std::fs::symlink_metadata(path.join(".git")).ok()?)))
    else {
        return false;
    };
    screened(root)
        && owned(root)
        && owned(&root.join(".git"))
        && (metadata.is_dir()
            || (metadata.is_file()
                && linked_worktree_of_repository(root, &|primary| {
                    screened(primary) && owned(primary) && owned(&primary.join(".git"))
                })))
}

#[cfg(not(unix))]
fn repository_owned_outside_home(
    _target: &std::path::Path,
    _context: super::PathContext<'_>,
) -> bool {
    false
}

/// A linked worktree's `.git` file must name an entry of the
/// `<repository>/.git/worktrees` registry whose `commondir` resolves back to
/// that repository's `.git` directory and whose `gitdir` backlink names this
/// worktree, and the owning repository must itself pass `repository_root`.
/// The administrative directory of `worktree` when it is a linked worktree
/// registered with the primary checkout at `repository` (both canonical).
pub(in crate::pretool) fn linked_worktree_admin(
    worktree: &std::path::Path,
    repository: &std::path::Path,
) -> Option<std::path::PathBuf> {
    let common = repository.join(".git");
    if worktree == repository
        || !std::fs::symlink_metadata(&common).is_ok_and(|metadata| metadata.is_dir())
        || !linked_worktree_of_repository(worktree, &|root| root == repository)
    {
        return None;
    }
    let pointer = bounded_git_metadata(&worktree.join(".git"))?;
    let admin =
        std::fs::canonicalize(worktree.join(pointer.trim().strip_prefix("gitdir: ")?)).ok()?;
    admin.starts_with(common.join("worktrees")).then_some(admin)
}

fn linked_worktree_of_repository(
    root: &std::path::Path,
    repository_root: &dyn Fn(&std::path::Path) -> bool,
) -> bool {
    let entry = root.join(".git");
    let Some(pointer) = bounded_git_metadata(&entry).and_then(|contents| {
        let mut lines = contents.lines();
        let pointer = lines.next()?.strip_prefix("gitdir: ")?.trim().to_owned();
        lines.next().is_none().then_some(pointer)
    }) else {
        return false;
    };
    let Ok(pointer) = std::fs::canonicalize(root.join(pointer)) else {
        return false;
    };
    let Some(common) = pointer
        .parent()
        .filter(|registry| registry.file_name().is_some_and(|name| name == "worktrees"))
        .and_then(std::path::Path::parent)
        .filter(|common| common.file_name().is_some_and(|name| name == ".git"))
    else {
        return false;
    };
    let resolves = |file: &str, expected: &std::path::Path| {
        bounded_git_metadata(&pointer.join(file))
            .and_then(|path| std::fs::canonicalize(pointer.join(path.trim())).ok())
            .is_some_and(|resolved| resolved == expected)
    };
    common.parent().is_some_and(repository_root)
        && std::fs::symlink_metadata(common).is_ok_and(|metadata| metadata.is_dir())
        && resolves("commondir", common)
        && std::fs::canonicalize(&entry).is_ok_and(|entry| resolves("gitdir", &entry))
}

fn git_entry_within_workspace(
    entry: &std::path::Path,
    metadata: &std::fs::Metadata,
    workspace: &std::path::Path,
) -> bool {
    if metadata.file_type().is_symlink() {
        return false;
    }
    if metadata.is_dir() {
        return true;
    }
    if !metadata.is_file() {
        return false;
    }
    use std::io::Read;
    let mut contents = String::new();
    if std::fs::File::open(entry)
        .and_then(|file| file.take(4097).read_to_string(&mut contents))
        .is_err()
        || contents.len() > 4096
    {
        return false;
    }
    let mut lines = contents.lines();
    let Some(pointer) = lines.next().and_then(|line| line.strip_prefix("gitdir: ")) else {
        return false;
    };
    if lines.next().is_some() || pointer.trim().is_empty() {
        return false;
    }
    let pointer = std::path::Path::new(pointer.trim());
    let pointer = if pointer.is_absolute() {
        pointer.to_path_buf()
    } else {
        let Some(parent) = entry.parent() else {
            return false;
        };
        parent.join(pointer)
    };
    let Ok(pointer) = std::fs::canonicalize(pointer) else {
        return false;
    };
    pointer.starts_with(workspace)
        || linked_worktree_git_entry_within_workspace(entry, &pointer, workspace)
}

fn linked_worktree_git_entry_within_workspace(
    entry: &std::path::Path,
    admin: &std::path::Path,
    workspace: &std::path::Path,
) -> bool {
    // The administrative directory is named after the worktree that owns this
    // `.git` entry, which may be a `-C` target below the workspace rather than
    // the workspace itself. The entry is already contained in the workspace.
    // Shape/backlink checks establish a linked-worktree route, not authenticity.
    // The separate Git configuration probe must still reject executable helpers,
    // including a forged but well-formed external common directory. Native home
    // writes cannot plant `.git` metadata and shell redirections remain guarded.
    let Some(worktree) = std::fs::canonicalize(entry)
        .ok()
        .and_then(|entry| entry.parent().map(std::path::Path::to_path_buf))
    else {
        return false;
    };
    // Git suffixes administrative names on collisions (feature, feature1), so
    // the name is not compared; the two-way gitdir link below binds the pair.
    if !worktree.starts_with(workspace) || !admin.is_dir() {
        return false;
    }
    let Some(common) = bounded_git_metadata(&admin.join("commondir"))
        .and_then(|path| std::fs::canonicalize(admin.join(path.trim())).ok())
    else {
        return false;
    };
    if admin.parent() != Some(common.join("worktrees").as_path()) {
        return false;
    }
    bounded_git_metadata(&admin.join("gitdir"))
        .and_then(|path| std::fs::canonicalize(admin.join(path.trim())).ok())
        .is_some_and(|backlink| std::fs::canonicalize(entry).is_ok_and(|entry| backlink == entry))
}

fn bounded_git_metadata(path: &std::path::Path) -> Option<String> {
    use std::io::Read;
    let mut contents = String::new();
    std::fs::File::open(path)
        .ok()?
        .take(4097)
        .read_to_string(&mut contents)
        .ok()?;
    (contents.len() <= 4096).then_some(contents)
}

// A linked worktree outside the working directory is routable only when the
// repository that contains the working directory registers exactly that path.
// Authenticity comes from the working directory's own repository metadata: its
// `worktrees/<name>/gitdir` must point at the target's `.git` file, and that
// file must point back at the same administrative directory.
fn registered_worktree_of_workspace(target: &std::path::Path, workspace: &std::path::Path) -> bool {
    let entry = target.join(".git");
    let Ok(metadata) = std::fs::symlink_metadata(&entry) else {
        return false;
    };
    if !metadata.is_file() {
        return false;
    }
    let Some(pointer) = bounded_git_metadata(&entry)
        .and_then(|contents| {
            let mut lines = contents.lines();
            let pointer = lines.next()?.strip_prefix("gitdir: ")?.trim().to_owned();
            lines.next().is_none().then_some(pointer)
        })
        .and_then(|pointer| {
            let pointer = std::path::Path::new(&pointer);
            let pointer = if pointer.is_absolute() {
                pointer.to_path_buf()
            } else {
                target.join(pointer)
            };
            std::fs::canonicalize(pointer).ok()
        })
    else {
        return false;
    };
    let Ok(entry) = std::fs::canonicalize(&entry) else {
        return false;
    };
    let Some(common) = workspace
        .ancestors()
        .find_map(|path| {
            let dot_git = path.join(".git");
            let metadata = std::fs::symlink_metadata(&dot_git).ok()?;
            if metadata.file_type().is_symlink() {
                return Some(None);
            }
            let git_dir = if metadata.is_dir() {
                dot_git
            } else {
                let contents = bounded_git_metadata(&dot_git)?;
                let pointer = contents.lines().next()?.strip_prefix("gitdir: ")?.trim();
                let pointer = std::path::Path::new(pointer);
                std::fs::canonicalize(if pointer.is_absolute() {
                    pointer.to_path_buf()
                } else {
                    path.join(pointer)
                })
                .ok()?
            };
            let common = match bounded_git_metadata(&git_dir.join("commondir")) {
                Some(relative) => std::fs::canonicalize(git_dir.join(relative.trim())).ok(),
                None => std::fs::canonicalize(&git_dir).ok(),
            };
            Some(common)
        })
        .flatten()
    else {
        return false;
    };
    // The pointer must be a direct entry of the registry; look it up directly
    // instead of scanning, so there is no enumeration cap to fall off.
    if pointer.parent() != Some(common.join("worktrees").as_path()) {
        return false;
    }
    bounded_git_metadata(&pointer.join("gitdir"))
        .and_then(|path| std::fs::canonicalize(pointer.join(path.trim())).ok())
        .is_some_and(|backlink| backlink == entry)
}

/// `git --git-dir=<bare repository>` reads a repository without a work tree,
/// and `--git-dir=<work tree>/.git` reads the repository of a work tree at
/// or below the current directory.
/// The directory must be a real (non-symlink) bare-shaped git directory
/// (`HEAD`, `objects/`, `refs/`) owned by the current user that clears the
/// same non-hidden and sensitive-path screens as a `-C` route outside home.
/// The configuration probe still runs against it and rejects helpers.
#[cfg(unix)]
pub(crate) fn git_dir_route_within_scope(value: &str, context: super::PathContext<'_>) -> bool {
    use std::os::unix::fs::MetadataExt;
    let (Some(cwd), Some(home_dir)) = (context.cwd, context.home_dir) else {
        return false;
    };
    let (Ok(workspace), Ok(home)) = (std::fs::canonicalize(cwd), std::fs::canonicalize(home_dir))
    else {
        return false;
    };
    let supplied = match value.strip_prefix('~') {
        Some("") => home.clone(),
        Some(rest) if rest.starts_with('/') => home.join(rest.trim_start_matches('/')),
        Some(_) => return false,
        None => std::path::PathBuf::from(value),
    };
    let supplied = if supplied.is_absolute() {
        supplied
    } else {
        workspace.join(supplied)
    };
    let Ok(git_dir) = std::fs::canonicalize(supplied) else {
        return false;
    };
    let real = |name: &str, directory: bool| {
        std::fs::symlink_metadata(git_dir.join(name)).is_ok_and(|m| {
            if directory {
                m.is_dir()
            } else {
                m.is_file()
            }
        })
    };
    // A work tree's own `.git` directory passes the screens through its work
    // tree. Git then takes the current directory as the work tree, so the
    // repository must sit inside it; a `.git` reached from another checkout
    // would pair one repository with an unrelated tree.
    let work_tree_git = git_dir.file_name().is_some_and(|name| name == ".git");
    let screened = match git_dir.parent() {
        Some(parent) if work_tree_git => parent,
        _ => git_dir.as_path(),
    };
    if git_dir == home
        || (work_tree_git && !screened.starts_with(&workspace))
        || screened == home
        || !real("HEAD", false)
        || !real("objects", true)
        || !real("refs", true)
        || !screened.components().all(|part| match part {
            std::path::Component::RootDir => true,
            std::path::Component::Normal(name) => !name.to_string_lossy().starts_with('.'),
            _ => false,
        })
        || !super::read_paths::resolved_path_allowed(screened, context.home_dir, context.cwd)
        || super::read_paths::inside_agent_state_tree(screened, context.home_dir)
    {
        return false;
    }
    std::fs::symlink_metadata(&git_dir).is_ok_and(|m| m.uid() == nix::unistd::geteuid().as_raw())
}

#[cfg(not(unix))]
pub(crate) fn git_dir_route_within_scope(_value: &str, _context: super::PathContext<'_>) -> bool {
    false
}

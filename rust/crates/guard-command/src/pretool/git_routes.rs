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
            || repository_below_home(&target, context);
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
/// treated like a read of that directory: it must sit strictly below home,
/// every component below home must be a non-hidden directory that clears the
/// sensitive-path screens, and the repository root must hold a real `.git`
/// directory below home or be a registered linked worktree of such a
/// repository, so neither the home directory itself nor a symlinked or
/// forged repository qualifies. The Git configuration probe still runs
/// against the `-C` target and rejects executable helpers.
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
    let below_home = |path: &std::path::Path| {
        path.strip_prefix(&home).is_ok_and(|relative| {
            !relative.as_os_str().is_empty()
                && relative.components().all(|part| {
                    matches!(part, std::path::Component::Normal(name) if !name.to_string_lossy().starts_with('.'))
                })
        }) && super::read_paths::resolved_path_allowed(path, context.home_dir, context.cwd)
            && !super::read_paths::inside_agent_state_tree(path, context.home_dir)
    };
    if !below_home(target) {
        return false;
    }
    target
        .ancestors()
        .take_while(|path| *path != home)
        .find_map(|path| Some((path, std::fs::symlink_metadata(path.join(".git")).ok()?)))
        .is_some_and(|(root, metadata)| {
            metadata.is_dir()
                || (metadata.is_file() && linked_worktree_of_repository(root, &below_home))
        })
}

/// A linked worktree's `.git` file must name an entry of the
/// `<repository>/.git/worktrees` registry whose `commondir` resolves back to
/// that repository's `.git` directory and whose `gitdir` backlink names this
/// worktree, and the owning repository must itself pass `repository_root`.
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

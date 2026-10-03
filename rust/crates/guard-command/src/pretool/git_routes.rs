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
    if !target.is_dir() || !target.starts_with(&workspace) {
        return false;
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
    // Shape/backlink checks establish a linked-worktree route, not authenticity.
    // The separate Git configuration probe must still reject executable helpers,
    // including a forged but well-formed external common directory. Native home
    // writes cannot plant `.git` metadata and shell redirections remain guarded.
    if admin.file_name() != workspace.file_name() || !admin.is_dir() {
        return false;
    }
    let Some(common) = bounded_git_metadata(&admin.join("commondir"))
        .and_then(|path| std::fs::canonicalize(admin.join(path.trim())).ok())
    else {
        return false;
    };
    if !admin.starts_with(common.join("worktrees")) {
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

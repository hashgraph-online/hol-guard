use super::read_paths::{
    bounded_file_read_target, existing_regular_read_target, expand_home_read_path,
    resolved_path_allowed,
};

pub(super) fn bounded_file_write_target(
    value: &str,
    home_dir: Option<&str>,
    cwd: Option<&str>,
) -> bool {
    bounded_write_target(value, home_dir, cwd, false, false)
}

pub(super) fn bounded_native_file_write_target(
    value: &str,
    home_dir: Option<&str>,
    cwd: Option<&str>,
) -> bool {
    bounded_write_target(value, home_dir, cwd, false, true)
}

fn bounded_write_target(
    value: &str,
    home_dir: Option<&str>,
    cwd: Option<&str>,
    directory: bool,
    allow_home: bool,
) -> bool {
    let Some(workspace) = cwd.and_then(|root| {
        let expanded = expand_home_read_path(root, home_dir).unwrap_or_else(|| root.to_owned());
        std::fs::canonicalize(expanded).ok()
    }) else {
        return false;
    };
    if value.is_empty()
        || value.len() > 4096
        || value.contains([
            '$', '`', '|', ';', '&', '<', '>', '\n', '\r', '\0', '*', '?', '[', ']', '{', '}',
        ])
        || value.split(['/', '\\']).any(|part| part == "..")
    {
        return false;
    }
    if value.starts_with('~') && expand_home_read_path(value, home_dir).is_none() {
        return false;
    }
    let expanded = expand_home_read_path(value, home_dir).unwrap_or_else(|| value.to_owned());
    let supplied = std::path::Path::new(&expanded);
    let target = if supplied.is_absolute() {
        supplied.to_path_buf()
    } else {
        workspace.join(supplied)
    };
    let canonical = if directory && target.is_dir() {
        std::fs::canonicalize(&target).ok()
    } else {
        super::worktree_writes::canonical_write_target(&target)
    };
    let Some(canonical) = canonical else {
        return false;
    };
    let inside_verified_home = allow_home
        && home_dir
            .and_then(|home| std::fs::canonicalize(home).ok())
            .is_some_and(|home| {
                // A filesystem root must never turn into an unrestricted write scope.
                home.parent().and_then(std::path::Path::parent).is_some()
                    && canonical.starts_with(&home)
                    // Normalize only the trusted home-root alias. The suffix
                    // must still resolve exactly, rejecting redirected targets.
                    && home_spelling_matches_target(&target, &canonical, home_dir, &home)
                    && single_link_write_target(&target)
                    && !home_execution_control_target(&canonical, &home, &workspace)
            });
    (canonical.starts_with(&workspace)
        || super::worktree_writes::same_repository_worktree(&workspace, &canonical)
        || inside_verified_home)
        && guard_secure_fs::hidden_read_parts_allowed(&canonical)
        && resolved_path_allowed(&canonical, home_dir, workspace.to_str())
        && !autostart_write_target(&canonical)
}

pub(super) fn safe_copy_arguments(arguments: &[String], context: super::PathContext<'_>) -> bool {
    let paths = match arguments {
        [source, destination] => (source, destination),
        [separator, source, destination] if separator == "--" => (source, destination),
        _ => return false,
    };
    let expanded =
        expand_home_read_path(paths.1, context.home_dir).unwrap_or_else(|| paths.1.clone());
    let destination = std::path::Path::new(&expanded);
    let destination = if destination.is_absolute() {
        destination.to_path_buf()
    } else if let Some(cwd) = context.cwd {
        std::path::Path::new(
            &expand_home_read_path(cwd, context.home_dir).unwrap_or_else(|| cwd.to_owned()),
        )
        .join(destination)
    } else {
        return false;
    };
    let destination = if destination.is_dir() {
        let Some(name) = std::path::Path::new(paths.0).file_name() else {
            return false;
        };
        destination.join(name)
    } else {
        destination
    };
    let Some(destination_text) = destination.to_str() else {
        return false;
    };
    if destination
        .symlink_metadata()
        .is_ok_and(|metadata| metadata.file_type().is_symlink())
    {
        return false;
    }
    // Only a single file-to-file copy. Flags, directory destinations and
    // recursive copies need separate evaluation; cp follows destination links.
    !paths.0.starts_with('-')
        && !paths.1.starts_with('-')
        && paths.0.trim() == paths.0
        && bounded_file_read_target(paths.0, context.home_dir, context.cwd)
        && (bounded_file_write_target(destination_text, context.home_dir, context.cwd)
            // The temporary carve-out is only for destinations the user
            // spelled absolutely. A relative destination joined onto a /tmp
            // workspace must not sidestep the workspace boundary check above.
            || (std::path::Path::new(&expanded).is_absolute()
                && bounded_temporary_copy_target(destination_text, context)))
}

pub(super) fn safe_file_mutation_arguments(
    command: &str,
    arguments: &[String],
    context: super::PathContext<'_>,
) -> bool {
    match (command, arguments) {
        ("mkdir", [target]) => {
            !target.starts_with('-')
                && bounded_write_target(target, context.home_dir, context.cwd, true, false)
        }
        ("mkdir", [flag, target]) if matches!(flag.as_str(), "-p" | "--parents" | "--") => {
            !target.starts_with('-')
                && bounded_write_target(target, context.home_dir, context.cwd, true, false)
        }
        ("touch", [target]) => {
            !target.starts_with('-')
                && bounded_file_write_target(target, context.home_dir, context.cwd)
        }
        ("touch", [flag, target]) if flag == "--" => {
            !target.starts_with('-')
                && bounded_file_write_target(target, context.home_dir, context.cwd)
        }
        ("mv", [source, destination]) => {
            existing_regular_read_target(source, context.home_dir, context.cwd)
                && bounded_file_write_target(source, context.home_dir, context.cwd)
                && bounded_file_write_target(destination, context.home_dir, context.cwd)
                && absent_move_destination(destination, context)
                && safe_copy_arguments(arguments, context)
        }
        _ => false,
    }
}

fn absent_move_destination(value: &str, context: super::PathContext<'_>) -> bool {
    let expanded =
        expand_home_read_path(value, context.home_dir).unwrap_or_else(|| value.to_owned());
    let supplied = std::path::Path::new(&expanded);
    let target = if supplied.is_absolute() {
        supplied.to_path_buf()
    } else if let Some(cwd) = context.cwd {
        std::path::Path::new(
            &expand_home_read_path(cwd, context.home_dir).unwrap_or_else(|| cwd.to_owned()),
        )
        .join(supplied)
    } else {
        return false;
    };
    matches!(target.symlink_metadata(), Err(error) if error.kind() == std::io::ErrorKind::NotFound)
}

#[cfg(unix)]
fn bounded_temporary_copy_target(value: &str, context: super::PathContext<'_>) -> bool {
    use super::read_paths::resolved_path_allowed_in_scope;
    use std::os::unix::fs::MetadataExt;
    use std::path::Path;

    let Some(owner) = context
        .home_dir
        .and_then(|home| std::fs::metadata(home).ok())
        .map(|m| m.uid())
    else {
        return false;
    };
    let path = Path::new(value);
    if !path.is_absolute()
        || value.len() > 4096
        || value.contains([
            '$', '`', '|', ';', '&', '<', '>', '\n', '\r', '\0', '*', '?', '[', ']', '{', '}',
        ])
        || path
            .components()
            .any(|part| matches!(part, std::path::Component::ParentDir))
    {
        return false;
    }
    let Some(parent) = path.parent().and_then(|p| std::fs::canonicalize(p).ok()) else {
        return false;
    };
    let Ok(parent_metadata) = parent.metadata() else {
        return false;
    };
    let roots = [Path::new("/tmp"), Path::new("/var/tmp")];
    let in_scope = roots
        .iter()
        .filter_map(|root| std::fs::canonicalize(root).ok())
        .any(|root| {
            parent.starts_with(&root)
                && (parent == root
                    || (parent_metadata.uid() == owner && parent_metadata.mode() & 0o022 == 0))
        });
    if !in_scope || !parent_metadata.is_dir() {
        return false;
    }
    // Do not follow a pre-existing leaf symlink or overwrite another user's
    // file (including a hard-link alias) in a shared temporary directory.
    match path.symlink_metadata() {
        Ok(metadata) if !metadata.is_file() || metadata.uid() != owner || metadata.nlink() != 1 => {
            return false
        }
        Ok(_) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(_) => return false,
    }
    let Some(target) = path.file_name().map(|name| parent.join(name)) else {
        return false;
    };
    // The temporary carve-out must never sidestep the ordinary home or
    // workspace boundaries when either happens to live under a temporary
    // root (ephemeral runners, tests, installer sandboxes).
    let inside_home = context
        .home_dir
        .and_then(|home| std::fs::canonicalize(home).ok())
        .is_some_and(|home| target.starts_with(home));
    let inside_workspace = context
        .cwd
        .map(|cwd| expand_home_read_path(cwd, context.home_dir).unwrap_or_else(|| cwd.to_owned()))
        .and_then(|cwd| std::fs::canonicalize(cwd).ok())
        .is_some_and(|workspace| target.starts_with(workspace));
    if inside_home || inside_workspace {
        return false;
    }
    resolved_path_allowed_in_scope(&target, context.home_dir, context.cwd, true)
        && guard_secure_fs::hidden_read_parts_allowed(&target)
        && !autostart_write_target(&target)
}

#[cfg(not(unix))]
fn bounded_temporary_copy_target(_value: &str, _context: super::PathContext<'_>) -> bool {
    false
}

fn autostart_write_target(path: &std::path::Path) -> bool {
    let rendered = path
        .to_string_lossy()
        .replace('\\', "/")
        .to_ascii_lowercase();
    let parts: Vec<&str> = rendered
        .split('/')
        .filter(|part| !part.is_empty())
        .collect();
    parts.windows(2).any(|pair| {
        matches!(
            pair,
            ["library", "launchagents"]
                | ["library", "launchdaemons"]
                | [".config", "autostart"]
                | [".config", "systemd"]
        )
    }) || parts
        .windows(3)
        .any(|parts| parts == ["start menu", "programs", "startup"])
}

fn single_link_write_target(path: &std::path::Path) -> bool {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;

        match path.symlink_metadata() {
            Ok(metadata) => !metadata.is_file() || metadata.nlink() == 1,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => true,
            Err(_) => false,
        }
    }
    #[cfg(windows)]
    {
        match path.symlink_metadata() {
            Ok(metadata) if !metadata.is_file() => false,
            Ok(_) => guard_runtime_windows_process::is_single_link_file(path).unwrap_or(false),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => true,
            Err(_) => false,
        }
    }
    #[cfg(all(not(unix), not(windows)))]
    {
        let _ = path;
        false
    }
}

fn home_execution_control_target(
    path: &std::path::Path,
    home: &std::path::Path,
    workspace: &std::path::Path,
) -> bool {
    if path.starts_with(workspace) {
        return false;
    }
    let parts: Vec<String> = path
        .strip_prefix(home)
        .ok()
        .into_iter()
        .flat_map(std::path::Path::components)
        .filter_map(|component| match component {
            std::path::Component::Normal(value) => {
                Some(value.to_string_lossy().to_ascii_lowercase())
            }
            _ => None,
        })
        .collect();
    parts.iter().any(|part| {
        matches!(part.as_str(), "bin" | "appdata" | "site-packages" | "dist-packages")
            || part.ends_with(".pth")
            || matches!(part.as_str(), "sitecustomize.py" | "usercustomize.py")
    }) || parts.windows(2).any(|pair| {
        matches!(
            pair,
            [first, second]
                if first == "library"
                    && matches!(second.as_str(), "application support" | "application scripts" | "python")
                    || (first == ".local" && second == "bin")
                    || (first == ".github" && second == "workflows")
        )
    })
}

fn home_spelling_matches_target(
    target: &std::path::Path,
    canonical: &std::path::Path,
    supplied_home: Option<&str>,
    canonical_home: &std::path::Path,
) -> bool {
    let relative = target.strip_prefix(canonical_home).ok().or_else(|| {
        supplied_home.and_then(|home| target.strip_prefix(std::path::Path::new(home)).ok())
    });
    relative.is_some_and(|relative| canonical_home.join(relative) == canonical)
}

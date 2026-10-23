#[path = "safe_copies.rs"]
mod copies;
#[path = "hooks_path_writes.rs"]
mod hooks_path;
#[path = "plan_note_writes.rs"]
mod plan_notes;
#[path = "write_target_screens.rs"]
mod screens;
use super::read_paths::{
    existing_regular_read_target, expand_home_read_path, resolved_location_allowed,
};
pub(super) use copies::{safe_copy_arguments, safe_copy_arguments_into};
pub(crate) use plan_notes::plan_note_write_sources;
pub(super) use plan_notes::plan_note_write_target;
pub(super) use screens::autostart_write_target;
use screens::home_execution_control_target;
pub(super) use screens::home_spelling_matches_target;
#[cfg(windows)]
use screens::shared_library_part;

pub(super) fn bounded_file_write_target(
    value: &str,
    home_dir: Option<&str>,
    cwd: Option<&str>,
) -> bool {
    bounded_write_target(value, home_dir, cwd, false, false, false)
}

pub(super) fn bounded_native_file_write_target(
    value: &str,
    home_dir: Option<&str>,
    cwd: Option<&str>,
) -> bool {
    bounded_write_target(value, home_dir, cwd, false, true, false)
}

/// A structured write tool opens its path literally, so `[id]` in a Next.js,
/// SvelteKit or Nuxt route directory and `$postId` in a Remix or TanStack
/// Router route file are names, not globs or expansions. Only brackets and `$`
/// are accepted; every other metacharacter and every location, protected-file,
/// hidden-part and hard-link screen still applies to the resolved target.
pub(super) fn bounded_structured_file_write_target(
    value: &str,
    home_dir: Option<&str>,
    cwd: Option<&str>,
) -> bool {
    bounded_write_target(value, home_dir, cwd, false, true, true)
}

/// A new directory path, screened like `mkdir`: the workspace, a linked
/// worktree or the verified home.
pub(super) fn bounded_new_directory_write_target(
    value: &str,
    home_dir: Option<&str>,
    cwd: Option<&str>,
) -> bool {
    bounded_write_target(value, home_dir, cwd, true, true, false)
}

/// A single absolute file write into a temporary directory the user owns.
/// It never widens the workspace or home boundaries; see the copy carve-out.
pub(super) fn bounded_native_temporary_write_target(
    value: &str,
    home_dir: Option<&str>,
    cwd: Option<&str>,
) -> bool {
    bounded_temporary_copy_target(
        value,
        super::PathContext {
            home_dir,
            cwd,
            cdpath_unset: false,
            rustup_override_absent: false,
            npm_config_inert: false,
            pip_config_inert: false,
            shell_home_matches: false,
            ripgrep_config_absent: false,
            psql_environment: Default::default(),
        },
    )
}

fn bounded_write_target(
    value: &str,
    home_dir: Option<&str>,
    cwd: Option<&str>,
    directory: bool,
    allow_home: bool,
    literal_names: bool,
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
            '`', '|', ';', '&', '<', '>', '\n', '\r', '\0', '*', '?', '{', '}',
        ])
        || (!literal_names && value.contains(['$', '[', ']']))
        // `$` never reaches a colon past the drive, such as an NTFS `::$DATA`
        // stream selector, so a literal name always names the file itself.
        || (value.contains('$') && value.char_indices().any(|(at, c)| c == ':' && at > 1))
        || (!literal_names && value.split(['/', '\\']).any(|part| part == ".."))
    {
        return false;
    }
    if value.split(['/', '\\']).any(|part| part == "..") {
        // A host file tool resolves `../notes.md` against its working
        // directory by spelling, so screen that resolved path, but only when
        // the filesystem walks `..` to the same place.
        return parent_relative_write_target(value, home_dir, cwd, &workspace).is_some_and(
            |resolved| {
                bounded_write_target(
                    &resolved,
                    home_dir,
                    cwd,
                    directory,
                    allow_home,
                    literal_names,
                )
            },
        );
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
    let verified_home = allow_home
        .then(|| home_dir.and_then(|home| std::fs::canonicalize(home).ok()))
        .flatten()
        .filter(|home| {
            // A filesystem root must never turn into an unrestricted write scope.
            home.parent().and_then(std::path::Path::parent).is_some()
                && canonical.starts_with(home)
                // Normalize only the trusted home-root alias. The suffix
                // must still resolve exactly, rejecting redirected targets.
                && home_spelling_matches_target(&target, &canonical, home_dir, home)
                && !home_execution_control_target(&canonical, home, &workspace)
        });
    // A plan note is a document, not harness configuration, so it is the one
    // thing the harness-directory and hidden-name screens let through.
    let plan_note = !directory
        && verified_home
            .as_deref()
            .is_some_and(|home| plan_notes::plan_note_path(&canonical, home));
    // Plugins, hooks, settings and instruction files that a harness loads on
    // its next start are reviewed even inside the workspace.
    if !plan_note
        && crate::harness_config_names::write_target_protected(supplied, &canonical, &workspace)
    {
        return false;
    }
    (canonical.starts_with(&workspace)
        || super::worktree_writes::same_repository_worktree(&workspace, &canonical)
        || verified_home.is_some())
        && resolved_location_allowed(&canonical, home_dir, workspace.to_str(), false)
        && (plan_note
            || guard_secure_fs::hidden_read_parts_allowed(&canonical)
            || screens::plain_dot_scratch_target(&canonical, home_dir))
        // A safe pathname can alias a protected inode through a hard link.
        && ((directory && canonical.is_dir()) || single_link_write_target(&canonical))
        && !autostart_write_target(&canonical)
        && !hooks_path::configured_hooks_write(&canonical, home_dir, workspace.to_str())
}

/// The absolute path a relative `..` write names, when the cwd's spelling and
/// the filesystem agree on it. A symlinked cwd makes them differ, and is refused.
fn parent_relative_write_target(
    value: &str,
    home_dir: Option<&str>,
    cwd: Option<&str>,
    workspace: &std::path::Path,
) -> Option<String> {
    let supplied = std::path::Path::new(value);
    if value.starts_with('~') || supplied.has_root() || supplied.is_absolute() {
        return None;
    }
    let root = cwd?;
    let base = expand_home_read_path(root, home_dir).unwrap_or_else(|| root.to_owned());
    let base = std::path::Path::new(&base);
    if !base.is_absolute() {
        return None;
    }
    let mut lexical = std::path::PathBuf::new();
    for component in base.join(supplied).components() {
        match component {
            std::path::Component::CurDir => {}
            std::path::Component::ParentDir => {
                if !lexical.pop() || lexical.parent().is_none() {
                    return None;
                }
            }
            other => lexical.push(other.as_os_str()),
        }
    }
    let physical = super::worktree_writes::canonical_write_target(&workspace.join(supplied))?;
    (super::worktree_writes::canonical_write_target(&lexical)? == physical)
        .then(|| lexical.to_str().map(str::to_owned))
        .flatten()
}

pub(super) fn safe_file_mutation_arguments(
    command: &str,
    arguments: &[String],
    context: super::PathContext<'_>,
) -> bool {
    match (command, arguments) {
        // The standard directory-only form creates one unique private leaf;
        // it never opens, overwrites, or removes an existing path. Subsequent
        // writes still require the separate owned-temporary-directory proof.
        ("mktemp", [flag]) if flag == "-d" => {
            super::safe_reads::verified_path_context(context.home_dir, context.cwd)
        }
        ("mkdir", [target]) => !target.starts_with('-') && creatable_target(target, context, true),
        ("mkdir", [flag, target]) if matches!(flag.as_str(), "-p" | "--parents" | "--") => {
            !target.starts_with('-') && creatable_target(target, context, true)
        }
        ("touch", [target]) => !target.starts_with('-') && creatable_target(target, context, false),
        ("touch", [flag, target]) if flag == "--" => {
            !target.starts_with('-') && creatable_target(target, context, false)
        }
        ("mv", [source, destination]) => {
            existing_regular_read_target(source, context.home_dir, context.cwd)
                && bounded_file_write_target(source, context.home_dir, context.cwd)
                && bounded_file_write_target(destination, context.home_dir, context.cwd)
                && absent_move_destination(destination, context)
                && safe_copy_arguments(arguments, context)
        }
        ("ln", [flag, source, destination]) if flag == "-s" => {
            super::safe_links::safe_symlink_arguments(source, destination, context)
        }
        ("ln", [flag, separator, source, destination]) if flag == "-s" && separator == "--" => {
            super::safe_links::safe_symlink_arguments(source, destination, context)
        }
        ("rm", operands) => super::safe_links::safe_remove_arguments(operands, context),
        _ => false,
    }
}

/// `mkdir` and `touch` only create a path or bump a timestamp, so they share
/// the screens of `cp`: the workspace, a linked worktree, the verified home,
/// or a path spelled absolutely inside a private temporary directory.
pub(super) fn creatable_target(
    value: &str,
    context: super::PathContext<'_>,
    directory: bool,
) -> bool {
    bounded_write_target(value, context.home_dir, context.cwd, directory, true, false)
        || (std::path::Path::new(value).is_absolute()
            && bounded_temporary_copy_target(value, context))
}

pub(super) fn absent_move_destination(value: &str, context: super::PathContext<'_>) -> bool {
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
    // macOS mktemp uses the user's configured Darwin temp root, outside /tmp.
    // Admit only that exact root after proving private ownership, not the
    // entire /var/folders tree or another user's temporary directories.
    #[cfg(target_os = "macos")]
    let darwin_temp = std::fs::canonicalize(std::env::temp_dir())
        .ok()
        .filter(|root| {
            root.starts_with("/private/var/folders")
                && root.metadata().is_ok_and(|metadata| {
                    metadata.is_dir() && metadata.uid() == owner && metadata.mode() & 0o077 == 0
                })
        });
    #[cfg(not(target_os = "macos"))]
    let darwin_temp: Option<std::path::PathBuf> = None;
    let in_scope = roots
        .iter()
        .filter_map(|root| std::fs::canonicalize(root).ok())
        .chain(darwin_temp)
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
        && !hooks_path::configured_hooks_write(&target, context.home_dir, context.cwd)
}

/// Windows `mktemp -d` (Git Bash `/tmp`) creates its directory in the user's
/// profile temp folder. A file in the exact `<home>\AppData\Local\Temp`, or
/// in a directory below it, is admitted, located from the canonical home
/// rather than the caller-controlled `TEMP`/`TMP`. A file directly in that
/// folder is what Git Bash writes for `/tmp/name`, which the POSIX spelling
/// already admits. The profile ACL keeps other non-administrator users out of
/// that tree, and the exact-spelling checks reject junctions, short names and
/// case aliases on the way there.
#[cfg(windows)]
fn bounded_temporary_copy_target(value: &str, context: super::PathContext<'_>) -> bool {
    use super::directory_targets::exact_drive_spelling;
    use super::read_paths::resolved_path_allowed_in_scope;
    use std::path::Path;

    let path = Path::new(value);
    if !path.is_absolute()
        || value.len() > 4096
        || value.contains([
            '$', '`', '|', ';', '&', '<', '>', '\n', '\r', '\0', '*', '?', '[', ']', '{', '}', '~',
        ])
        || value.get(2..).is_some_and(|rest| rest.contains(':'))
        || path
            .components()
            .any(|part| matches!(part, std::path::Component::ParentDir))
    {
        return false;
    }
    let Some(home) = context
        .home_dir
        .and_then(|home| std::fs::canonicalize(home).ok())
    else {
        return false;
    };
    let temp_root = home.join("AppData").join("Local").join("Temp");
    if std::fs::canonicalize(&temp_root).ok().as_deref() != Some(temp_root.as_path()) {
        return false;
    }
    let (Some(parent_text), Some(name)) = (
        path.parent().and_then(Path::to_str),
        path.file_name().and_then(|name| name.to_str()),
    ) else {
        return false;
    };
    let Some(parent) = std::fs::canonicalize(parent_text).ok() else {
        return false;
    };
    if !exact_drive_spelling(parent_text, &parent)
        || !parent.starts_with(&temp_root)
        || !parent.is_dir()
        || shared_library_part(&name.to_ascii_lowercase())
    {
        return false;
    }
    let target = parent.join(name);
    let inside_workspace = context
        .cwd
        .and_then(|cwd| std::fs::canonicalize(cwd).ok())
        .is_some_and(|workspace| target.starts_with(workspace));
    !inside_workspace
        && single_link_write_target(&target)
        && resolved_path_allowed_in_scope(&target, context.home_dir, context.cwd, true)
        && guard_secure_fs::hidden_read_parts_allowed(&target)
        && !autostart_write_target(&target)
        && !hooks_path::configured_hooks_write(&target, context.home_dir, context.cwd)
}

#[cfg(all(not(unix), not(windows)))]
fn bounded_temporary_copy_target(_value: &str, _context: super::PathContext<'_>) -> bool {
    false
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

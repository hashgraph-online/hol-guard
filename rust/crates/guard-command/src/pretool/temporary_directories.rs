//! New paths below a private temporary directory.
//!
//! `mkdir -p /tmp/run/logs/a` creates `/tmp/run`, then each directory below
//! it. The screen a single new temporary path clears already admits the
//! first of those, and every later one is created inside a directory the
//! command itself just made, so the nested form needs no wider trust than
//! the single-level form `mkdir -p /tmp/run` has.

use super::super::PathContext;
#[cfg(unix)]
use std::path::Path;

/// The screens a new temporary path clears once its existing parent has been
/// resolved.
///
/// The temporary carve-out must never sidestep the ordinary home or workspace
/// boundaries when either happens to live under a temporary root (ephemeral
/// runners, tests, installer sandboxes), and the target must still pass the
/// shared write-location screens. Windows keeps its own copy of these
/// screens beside its profile temp-folder proof.
#[cfg(unix)]
pub(super) fn temporary_target_allowed(target: &Path, context: PathContext<'_>) -> bool {
    let inside_home = context
        .home_dir
        .and_then(|home| std::fs::canonicalize(home).ok())
        .is_some_and(|home| target.starts_with(home));
    let inside_workspace = context
        .cwd
        .map(|cwd| {
            super::expand_home_read_path(cwd, context.home_dir).unwrap_or_else(|| cwd.to_owned())
        })
        .and_then(|cwd| std::fs::canonicalize(cwd).ok())
        .is_some_and(|workspace| target.starts_with(workspace));
    if inside_home || inside_workspace {
        return false;
    }
    super::super::read_paths::resolved_path_allowed_in_scope(
        target,
        context.home_dir,
        context.cwd,
        true,
    ) && guard_secure_fs::hidden_write_parts_allowed(target)
        && !super::autostart_write_target(target)
        && !super::hooks_path::configured_hooks_write(target, context.home_dir, context.cwd)
}

/// `mkdir -p` of an absolute path whose parent is missing.
///
/// The nearest existing ancestor has to be a directory the single-level
/// screen accepts as a parent: one of the temporary roots, or a directory
/// below one that the user owns and nobody else may write to. A link at that
/// ancestor is resolved before the check, so one pointing out of the
/// temporary roots is refused. The first missing component is then screened
/// exactly as `mkdir -p /tmp/name` is, and the full path is screened again
/// below the resolved ancestor, so a hidden or hook directory deeper down
/// keeps its review.
#[cfg(unix)]
pub(super) fn nested_temporary_directory(value: &str, context: PathContext<'_>) -> bool {
    use std::path::Component;

    let path = Path::new(value);
    if !path.is_absolute()
        || value.len() > 4096
        || value.contains([
            '$', '`', '|', ';', '&', '<', '>', '\n', '\r', '\0', '*', '?', '[', ']', '{', '}',
        ])
        || !path
            .components()
            .all(|part| matches!(part, Component::RootDir | Component::Normal(_)))
    {
        return false;
    }
    let (Some(leaf), Some(mut existing)) = (path.file_name(), path.parent()) else {
        return false;
    };
    let mut missing = Vec::new();
    loop {
        match existing.symlink_metadata() {
            Ok(_) => break,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(_) => return false,
        }
        let (Some(name), Some(parent)) = (existing.file_name(), existing.parent()) else {
            return false;
        };
        missing.push(name);
        existing = parent;
    }
    let Some(first) = missing.last() else {
        return false;
    };
    let Some(first) = existing.join(first).to_str().map(str::to_owned) else {
        return false;
    };
    let Ok(mut target) = std::fs::canonicalize(existing) else {
        return false;
    };
    target.extend(missing.iter().rev());
    target.push(leaf);
    super::bounded_temporary_copy_target(&first, context)
        && temporary_target_allowed(&target, context)
}

#[cfg(not(unix))]
pub(super) fn nested_temporary_directory(_value: &str, _context: PathContext<'_>) -> bool {
    false
}

/// Whether `parent` sits in the temporary `root` with every folder between
/// them, `parent` included, owned by `owner` and closed to other writers.
///
/// A folder another user may write to lets that user rename the folder below
/// it aside and put a link in its place after the check and before the
/// command runs, so a write or removal meant for scratch would land wherever
/// the link points. `root` itself is the shared temporary root, which the
/// sticky bit already guards.
#[cfg(unix)]
pub(super) fn private_chain(root: &Path, parent: &Path, owner: u32) -> bool {
    use std::os::unix::fs::MetadataExt;
    parent.starts_with(root)
        && parent
            .ancestors()
            .take_while(|folder| *folder != root)
            .all(|folder| {
                folder.symlink_metadata().is_ok_and(|metadata| {
                    metadata.is_dir() && metadata.uid() == owner && metadata.mode() & 0o022 == 0
                })
            })
}

//! New links and single-file removals inside the workspace.
//!
//! Both mirror the `mv` proof: every path is screened with the same bounded
//! write target, so a link or removal never reaches a hidden, sensitive or
//! autostart location, and never leaves the workspace or a sibling worktree
//! of the same repository.
use super::read_paths::{existing_regular_read_target, expand_home_read_path};
use super::safe_writes::{absent_move_destination, bounded_file_write_target};

/// `ln -s SOURCE LINK` that only adds a new link inside the workspace or a
/// sibling worktree of the same repository.
///
/// A relative source resolves against the link's directory, not the cwd, so
/// only absolute and `~/` sources are proved. The source may be a directory
/// but never the home directory or one of its ancestors, and never a path
/// that contains the workspace: later reads through the link still resolve
/// to the target, yet a link that exposes the whole home is not routine.
pub(super) fn safe_symlink_arguments(
    source: &str,
    destination: &str,
    context: super::PathContext<'_>,
) -> bool {
    if source.starts_with('-')
        || destination.starts_with('-')
        || source.trim() != source
        || !workspace_below_home(context)
    {
        return false;
    }
    let Some(expanded) = expand_home_read_path(source, context.home_dir).or_else(|| {
        std::path::Path::new(source)
            .is_absolute()
            .then(|| source.to_owned())
    }) else {
        return false;
    };
    let Ok(target) = std::fs::canonicalize(&expanded) else {
        return false;
    };
    let contains_session_root = [context.home_dir, context.cwd]
        .into_iter()
        .flatten()
        .filter_map(|root| {
            let root =
                expand_home_read_path(root, context.home_dir).unwrap_or_else(|| root.to_owned());
            std::fs::canonicalize(root).ok()
        })
        .any(|root| root.starts_with(&target));
    !contains_session_root
        && super::read_paths::bounded_read_target(source, context.home_dir, context.cwd, true)
        && bounded_file_write_target(destination, context.home_dir, context.cwd)
        && absent_move_destination(destination, context)
}

/// `rm [-f] [--] FILE...` over a few existing regular files in the workspace.
///
/// Each operand must be the file itself, not a link, so the screen applies to
/// the entry that is removed. The one link admitted is one at the root of a
/// linked worktree of the session's repository, such as a shared
/// `node_modules`: removing it leaves its target alone. Directories,
/// recursion and home-wide paths stay under review.
pub(super) fn safe_remove_arguments(arguments: &[String], context: super::PathContext<'_>) -> bool {
    if !workspace_below_home(context) {
        return false;
    }
    let mut options = true;
    let mut operands = 0;
    for argument in arguments {
        if options && argument == "--" {
            options = false;
            continue;
        }
        if options && argument == "-f" {
            continue;
        }
        if argument.starts_with('-') {
            return false;
        }
        options = false;
        operands += 1;
        if operands > 16
            || !(removable_regular_file(argument, context)
                || super::directory_targets::sibling::removable_link(argument, context))
        {
            return false;
        }
    }
    operands > 0
}

fn removable_regular_file(value: &str, context: super::PathContext<'_>) -> bool {
    let expanded =
        expand_home_read_path(value, context.home_dir).unwrap_or_else(|| value.to_owned());
    let supplied = std::path::Path::new(&expanded);
    let entry = if supplied.is_absolute() {
        supplied.to_path_buf()
    } else if let Some(cwd) = context.cwd {
        std::path::Path::new(
            &expand_home_read_path(cwd, context.home_dir).unwrap_or_else(|| cwd.to_owned()),
        )
        .join(supplied)
    } else {
        return false;
    };
    entry
        .symlink_metadata()
        .is_ok_and(|metadata| metadata.file_type().is_file())
        && existing_regular_read_target(value, context.home_dir, context.cwd)
        && bounded_file_write_target(value, context.home_dir, context.cwd)
}

/// A session started in the home directory, or above it, has no workspace
/// boundary: every visible file in the home would count as a workspace file.
fn workspace_below_home(context: super::PathContext<'_>) -> bool {
    let (Some(home), Some(cwd)) = (context.home_dir, context.cwd) else {
        return false;
    };
    let cwd = expand_home_read_path(cwd, Some(home)).unwrap_or_else(|| cwd.to_owned());
    match (std::fs::canonicalize(home), std::fs::canonicalize(cwd)) {
        (Ok(home), Ok(cwd)) => !home.starts_with(cwd),
        _ => false,
    }
}

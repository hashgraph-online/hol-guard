//! Absolute and `~` roots that name a real directory below a base.
use super::tree::{expanded_operand, home_relative, inside_agent_state, HAZARDS};
use super::ReadContext;
use std::path::Path;

/// An absolute or `~` `rg` root that names a real directory below the cwd is
/// the same search as its cwd-relative spelling, which `rg` already confines
/// to non-hidden, non-ignored entries without following links. Agents working
/// from a multi-repository parent spell child repositories this way, and the
/// metadata walk would refuse them for their `.git` directory alone.
///
/// Every component below the cwd must be a non-hidden real directory, so the
/// root cannot reach a dot directory or leave the cwd through a link, and the
/// relative spelling must clear the same screens as a typed relative operand.
pub(in crate::pretool) fn rg_root_inside_cwd(value: &str, context: ReadContext<'_>) -> bool {
    home_relative(context.cwd.unwrap_or_default(), context.home_dir)
        .and_then(|cwd| crate::runtime_read_paths::canonicalize_text(&cwd).ok())
        .is_some_and(|cwd| root_below(value, context, &cwd, false))
}

/// `rg PATTERN ..` run from a folder inside a repository searches a folder of
/// that same repository; from `src/` it is the whole checkout, the same search
/// `rg PATTERN .` makes from the root. Only a parent spelling that climbs above
/// the repository root reaches unrelated sibling projects, which the
/// broad-parent rule keeps at review. A root admitted here still has to clear
/// the ordinary reading proofs; this only stops the blanket refusal.
pub(in crate::pretool) fn parent_root_inside_repository(
    value: &str,
    context: ReadContext<'_>,
) -> bool {
    if value.len() > 4096
        || !value
            .split('/')
            .all(|part| part.is_empty() || part == "." || part == "..")
    {
        return false;
    }
    let canonical = |path: &Path| crate::runtime_read_paths::canonicalize_text(path).ok();
    let Some(cwd) = home_relative(context.cwd.unwrap_or_default(), context.home_dir)
        .and_then(|cwd| canonical(&cwd))
    else {
        return false;
    };
    let Some(target) = expanded_operand(value, context).and_then(|root| canonical(&root)) else {
        return false;
    };
    let home = context.home_dir.and_then(|home| canonical(Path::new(home)));
    cwd.ancestors()
        .take(64)
        .find(|directory| std::fs::symlink_metadata(directory.join(".git")).is_ok())
        .is_some_and(|repository| {
            repository.parent().is_some()
                && home.as_deref() != Some(repository)
                && target.is_dir()
                && target.starts_with(repository)
        })
}

/// `fd` prints names, never contents, and skips hidden and ignored entries
/// without following links. A names-only listing may therefore start at any
/// non-hidden directory strictly below home, such as the parent that holds the
/// current repository and its siblings, under the same component screens.
pub(in crate::pretool) fn listing_root_below_home(value: &str, context: ReadContext<'_>) -> bool {
    context
        .home_dir
        .and_then(|home| crate::runtime_read_paths::canonicalize_text(Path::new(home)).ok())
        .is_some_and(|home| root_below(value, context, &home, true))
}

/// Paths are compared without the Windows `\\?\` prefix, so the spelled root
/// must still match its canonical path exactly (case, short names, links).
/// A Windows root with no drive (`/x`) is refused: Git Bash maps it below its
/// own install directory, not below the current drive.
fn root_below(value: &str, context: ReadContext<'_>, base: &Path, strict: bool) -> bool {
    if !value.starts_with(['/', '~'])
        || cfg!(windows) && value.starts_with('/')
        || value.len() > 4096
        || value.contains(HAZARDS)
        || value.contains(['*', '?', '[', ']', '{', '}'])
        || value.split('/').any(|part| part == "..")
        || !super::super::safe_reads::verified_path_context(context.home_dir, context.cwd)
    {
        return false;
    }
    let Some(root) = expanded_operand(value, context) else {
        return false;
    };
    let Ok(canonical) = crate::runtime_read_paths::canonicalize_text(&root) else {
        return false;
    };
    let Ok(relative) = canonical.strip_prefix(base) else {
        return false;
    };
    let relative = relative.to_string_lossy().replace('\\', "/");
    canonical == root
        && canonical.is_dir()
        && !(strict && relative.is_empty())
        && relative
            .split('/')
            .filter(|part| !part.is_empty())
            .all(|part| !part.starts_with('.'))
        && !inside_agent_state(&canonical, context)
        && (relative.is_empty()
            || !(super::sensitive_path_argument(&relative)
                || super::glob_can_select_sensitive_path(&relative)))
}

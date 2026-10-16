//! `ln -s <directory> <repo>/<name>`: sharing a dependency directory such as
//! `node_modules` between checkouts of one repository. The link must be a
//! fresh, non-hidden name directly inside a verified workspace checkout, and
//! the target an existing, non-hidden directory of another checkout with the
//! same Git common directory, or inside the working directory. A symbolic
//! link runs nothing; these bounds keep it from replacing any existing path
//! or exposing data outside the repository.

use std::fs;
use std::path::{Component, Path, PathBuf};

/// One `ln` beside read-only peers: `ln -s <a>/node_modules <wt>/node_modules
/// && ls -la <wt>/ | grep node_module`. The `ln` is still proven on its own,
/// so a chain only adds peers that print or filter. `cp`, `mv`, `rm`, `cd`,
/// Git and a second `ln` stay out: nothing may write through, replace or
/// re-anchor the fresh link before a later step runs. Redirects stay out too,
/// since a write to `<link>/file` could not be proven before the link exists.
/// `grep` and `rg` only filter piped output: a file operand could read
/// through the fresh link, which did not exist when the operand was proven.
pub(super) fn link_chain(model: &crate::CanonicalCommandV1) -> bool {
    let links = |name: &str| {
        model
            .segments
            .iter()
            .filter(|segment| segment.executable.as_deref() == Some(name))
            .count()
    };
    model.segments.len() > 1
        && links("ln") == 1
        && links("cp") == 0
        && super::chain_temporary::plain_chain(model, &["ln"])
        && model.segments.iter().all(|segment| {
            !segment.text.replace("2>&1", "").contains(['>', '<'])
                && (segment.executable.as_deref() != Some("ln") || segment.pipeline_index == 0)
                && (!matches!(segment.executable.as_deref(), Some("grep" | "rg"))
                    || (segment.pipeline_index > 0
                        && super::segment_proof::stdin_filter_segment(segment)))
        })
}

pub(super) fn safe_symlink_arguments(
    segment: &crate::CommandSegmentV1,
    context: super::PathContext<'_>,
) -> bool {
    if segment.pipeline_index != 0
        || segment.path_overridden
        || !segment.wrapper_chain.is_empty()
        || !segment.environment_names.is_empty()
        || segment.text.contains([
            '>', '<', '$', '`', '|', '&', ';', '\n', '\r', '*', '?', '[', '{', '~', '\\',
        ])
    {
        return false;
    }
    let [flag, target, link] = segment.arguments.as_slice() else {
        return false;
    };
    // Relative targets resolve against the link's directory, which an
    // agent rarely means; the workspace proof rejects them as well.
    if flag != "-s" || !target.starts_with('/') || link.starts_with('-') {
        return false;
    }
    let Some(cwd) = context
        .cwd
        .map(Path::new)
        .filter(|cwd| cwd.is_absolute())
        .and_then(|cwd| fs::canonicalize(cwd).ok())
    else {
        return false;
    };
    let Some((parent, name)) = fresh_link(link, &cwd) else {
        return false;
    };
    let Some(link_common) = checkout_common_directory(&parent, &cwd) else {
        return false;
    };
    let parent_text = parent.to_string_lossy();
    if !super::git_route_within_workspace(&parent_text, context)
        || !super::read_paths::resolved_path_allowed(
            &parent.join(name),
            context.home_dir,
            context.cwd,
        )
    {
        return false;
    }
    let Some(target) = fs::canonicalize(parent.join(target))
        .ok()
        .filter(|target| target.is_dir())
    else {
        return false;
    };
    if !super::read_paths::resolved_path_allowed(&target, context.home_dir, context.cwd) {
        return false;
    }
    match super::worktree_writes::repository_common_directory(&target) {
        Some((root, common)) => {
            let Some(relative) = target.strip_prefix(&root).ok() else {
                return false;
            };
            let visible = relative.components().all(|component| {
                matches!(component, Component::Normal(part) if !part.to_string_lossy().starts_with('.'))
            });
            visible
                && !relative.as_os_str().is_empty()
                && ((common == link_common && root != parent) || target.starts_with(&cwd))
        }
        None => false,
    }
}

/// The canonical parent and file name of a link path that does not exist yet.
/// `..` may reach a sibling checkout (`../report/node_modules`): the kernel
/// resolves it against the physical cwd, which canonicalizing the parent
/// reproduces, and the caller screens that canonical parent.
fn fresh_link<'a>(link: &'a str, cwd: &Path) -> Option<(PathBuf, &'a str)> {
    let lexical = Path::new(link);
    if lexical
        .components()
        .any(|component| matches!(component, Component::CurDir))
        || matches!(link.rsplit('/').next(), Some("." | ".."))
    {
        return None;
    }
    let name = lexical.file_name()?.to_str()?;
    if name.starts_with('.') || name.is_empty() {
        return None;
    }
    let parent = lexical
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty());
    let parent = match parent {
        Some(parent) if parent.is_absolute() => parent.to_path_buf(),
        Some(parent) => cwd.join(parent),
        None => cwd.to_path_buf(),
    };
    let parent = fs::canonicalize(parent).ok()?;
    match fs::symlink_metadata(parent.join(name)) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Some((parent, name)),
        _ => None,
    }
}

/// The common directory of the checkout rooted exactly at `root`: a verified
/// linked worktree, or a primary checkout inside the working directory.
fn checkout_common_directory(root: &Path, cwd: &Path) -> Option<PathBuf> {
    let marker = fs::symlink_metadata(root.join(".git")).ok()?;
    if marker.is_file() {
        let common = super::worktree_writes::linked_worktree_common_dir(root)?;
        return (common.parent() != Some(root)).then_some(common);
    }
    if marker.is_dir() && !marker.file_type().is_symlink() && root.starts_with(cwd) {
        return fs::canonicalize(root.join(".git")).ok();
    }
    None
}

//! `ln -s <directory> <repo>/<name>`: sharing a dependency directory such as
//! `node_modules` between checkouts of one repository. The link path must be
//! a non-hidden name directly inside a verified workspace checkout, and the
//! target an existing, non-hidden directory of another checkout with the same
//! Git common directory, of a separate clone of the same repository, or
//! inside the working directory. The name is free, or already a directory
//! `ln` writes the link inside under the target's own base name, which must
//! be free there. A symbolic link runs nothing; these bounds keep it from
//! replacing any existing path or exposing data outside the repository.

use std::fs;
use std::path::{Component, Path, PathBuf};

/// One `ln` beside read-only peers: `ln -s <a>/node_modules <wt>/node_modules
/// && ls -la <wt>/ | grep node_module`. The `ln` is still proven on its own,
/// so a chain only adds peers that print or filter. `cp`, `mv`, `rm`, `cd`
/// and a second `ln` stay out: nothing may write through, replace or
/// re-anchor the fresh link before a later step runs. Redirects stay out too,
/// since a write to `<link>/file` could not be proven before the link exists.
/// `grep` and `rg` only filter piped output: a file operand could read
/// through the fresh link, which did not exist when the operand was proven.
///
/// Git joins only as `git branch --show-current` (see [`current_branch_read`]).
/// Branch and tag listings can start a configured pager, and `git status`,
/// `git diff` and `git grep` read the working tree, so they stay out.
pub(super) fn link_chain(
    model: &crate::CanonicalCommandV1,
    context: super::PathContext<'_>,
) -> bool {
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
        && super::chain_temporary::plain_chain(model, &["ln", "git"])
        && model.segments.iter().all(|segment| {
            !segment.text.replace("2>&1", "").contains(['>', '<'])
                && (segment.executable.as_deref() != Some("ln") || segment.pipeline_index == 0)
                && (segment.executable.as_deref() != Some("git")
                    || current_branch_read(segment, context))
                && (!matches!(segment.executable.as_deref(), Some("grep" | "rg"))
                    || (segment.pipeline_index > 0
                        && super::segment_proof::stdin_filter_segment(segment)))
        })
}

/// `git [-C <dir>] branch --show-current`: Git prints the branch HEAD names
/// and returns before it sets up a pager, so no configured helper runs
/// whatever the repository configuration holds, including configuration a
/// link created earlier in the command makes reachable. The `-C` route must
/// already hold a repository: a route that does not exist yet could be the
/// fresh link itself, which the configuration probe never saw.
pub(super) fn current_branch_read(
    segment: &crate::CommandSegmentV1,
    context: super::PathContext<'_>,
) -> bool {
    let Some(inspected) =
        crate::command_compatibility::git_inspection_arguments(&segment.arguments, context)
    else {
        return false;
    };
    // The leading options name the route the read runs in; a sensitive one
    // is refused here as it is for a Git read standing on its own.
    let leading = &segment.arguments[..segment.arguments.len() - inspected.len()];
    if leading
        .iter()
        .any(|value| value.starts_with(':') || super::sensitive_read_path_argument(value))
    {
        return false;
    }
    matches!(inspected, [subcommand, flag] if subcommand == "branch" && flag == "--show-current")
        && !super::git_helper_context::routes_to_no_repository(segment, context)
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
    // A relative target resolves against the directory the link is written
    // in, which is how a dependency directory is shared between sibling
    // checkouts (`ln -s ../app-portal/node_modules ../app-portal-fix/node_modules`).
    // Resolving it that way below leaves every screen on the canonical target,
    // so the spelling changes nothing a proof depends on.
    if flag != "-s" || target.is_empty() || target.starts_with('-') || link.starts_with('-') {
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
    let Some((parent, written, name)) = fresh_link(link, target, &cwd) else {
        return false;
    };
    let Some(link_common) = checkout_common_directory(&parent, &cwd) else {
        return false;
    };
    let parent_text = parent.to_string_lossy();
    if !super::git_route_within_workspace(&parent_text, context)
        || !super::read_paths::resolved_path_allowed(
            &written.join(&name),
            context.home_dir,
            context.cwd,
        )
    {
        return false;
    }
    // `written` is the directory holding the new link, which is where the
    // kernel resolves a relative target from. An absolute target ignores it.
    let Some(target) = fs::canonicalize(written.join(target))
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
                && ((common == link_common && root != parent)
                    || target.starts_with(&cwd)
                    || super::clone_siblings::related_clones(&root, &parent))
        }
        None => false,
    }
}

/// The checkout directory the link path names, the directory the link is
/// actually written in, and its file name. `..` may reach a sibling checkout
/// (`../report/node_modules`): the kernel resolves it against the physical
/// cwd, which canonicalizing the parent reproduces, and the caller screens
/// that canonical parent.
///
/// `ln -s <target> <link>` writes `<link>` only while that name is free. When
/// it already names a directory the link goes inside it, under the target's
/// own base name, which is the ordinary second run of `ln -s
/// <checkout>/node_modules <worktree>/node_modules` once the worktree has its
/// own install. That deeper name must be free in turn, so nothing is replaced
/// either way, and the directory the caller screens is still the one the link
/// path names.
fn fresh_link(link: &str, target: &str, cwd: &Path) -> Option<(PathBuf, PathBuf, String)> {
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
    let named = parent.join(name);
    match fs::symlink_metadata(&named) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            Some((parent.clone(), parent, name.to_owned()))
        }
        // A symbolic link in the way is left alone: `ln` would write through
        // whatever it points at, which this screen has not proven.
        Ok(metadata) if metadata.is_dir() => {
            let inner = Path::new(target).file_name()?.to_str()?;
            if inner.starts_with('.') || inner.is_empty() {
                return None;
            }
            let written = fs::canonicalize(&named).ok()?;
            match fs::symlink_metadata(written.join(inner)) {
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                    Some((parent, written, inner.to_owned()))
                }
                _ => None,
            }
        }
        _ => None,
    }
}

/// The common directory of the checkout rooted exactly at `root`: a verified
/// linked worktree, or a primary checkout inside the working directory or
/// cloned from the repository the working directory belongs to.
fn checkout_common_directory(root: &Path, cwd: &Path) -> Option<PathBuf> {
    let marker = fs::symlink_metadata(root.join(".git")).ok()?;
    if marker.is_file() {
        let common = super::worktree_writes::linked_worktree_common_dir(root)?;
        return (common.parent() != Some(root)).then_some(common);
    }
    if marker.is_dir()
        && !marker.file_type().is_symlink()
        && (root.starts_with(cwd) || clone_of_workspace(root, cwd))
    {
        return fs::canonicalize(root.join(".git")).ok();
    }
    None
}

/// Whether `root` is the checkout holding `cwd` (the command runs in one of
/// its subdirectories) or a separate clone of that checkout's repository.
fn clone_of_workspace(root: &Path, cwd: &Path) -> bool {
    super::worktree_writes::repository_common_directory(cwd).is_some_and(|(workspace, _)| {
        workspace == root || super::clone_siblings::related_clones(&workspace, root)
    })
}

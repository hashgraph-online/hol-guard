//! Paths that climb out of the session's checkout into a linked worktree of
//! the same repository, such as `cd ../report-wt` after `git worktree add
//! ../report-wt`.
//!
//! The worktree shares the session repository's objects, configuration and
//! hooks, so entering it reaches nothing the workspace does not already
//! expose. A relative `..` is proved only from a reported cwd that is its own
//! canonical path, through plain, non-hidden names to the exact root of a
//! linked worktree whose shared Git directory is the session's. The root's
//! `.git` must be a plain gitfile naming an admin entry of that directory
//! whose backlink names the root, so a sibling with its own `.git`
//! directory, a `.git` symlink or a worktree of another repository is not
//! one.
//!
//! A file operation resolves `..` against the process's physical directory,
//! which the reported cwd names. A shell `cd` resolves it against its logical
//! `$PWD` instead; the two agree unless the session was entered through a
//! symlink the reported cwd does not show, the same residual the checkout a
//! chain creates accepts.

use std::path::{Component, Path, PathBuf};

/// The canonical root a `cd ../<name>` enters when that root is a linked
/// worktree of the session's repository.
pub(crate) fn linked_root(value: &str, cwd: &Path) -> Option<PathBuf> {
    if !value.starts_with("../") {
        return None;
    }
    let target = resolved(value, cwd)?;
    same_repository_root(&target, cwd).then_some(target)
}

/// `rm` of a symbolic link that sits directly in the root of a linked
/// worktree of the session's repository, named by an absolute path or one
/// that climbs out of the cwd. Only the link is removed, never its target.
pub(crate) fn removable_link(value: &str, context: super::super::PathContext<'_>) -> bool {
    context
        .cwd
        .and_then(|cwd| resolved(value, Path::new(cwd)))
        .is_some_and(|entry| root_link(&entry, context))
}

/// Whether `entry` is a symbolic link directly in the root of a linked
/// worktree of the session's repository that no harness reads.
fn root_link(entry: &Path, context: super::super::PathContext<'_>) -> bool {
    let (Some(cwd), Some(root)) = (context.cwd.map(Path::new), entry.parent()) else {
        return false;
    };
    entry
        .symlink_metadata()
        .is_ok_and(|metadata| metadata.file_type().is_symlink())
        && same_repository_root(root, cwd)
        && !crate::harness_config_names::write_target_protected(entry, entry, root)
        && super::super::read_paths::resolved_location_allowed(
            entry,
            context.home_dir,
            context.cwd,
            false,
        )
}

/// `rm <name>` right after the command's leading `cd ../<worktree>`, as in
/// `cd ../report-wt && rm node_modules && git add . && git commit -m x`.
/// The `cd` enters the root of a linked worktree of the session's
/// repository, every step up to `index` is a plain `rm` of one link directly
/// in that root, and the whole command is joined by `&&`, so each removal
/// runs there, only after the `cd` succeeded. The plain name rules out flags,
/// nested paths and every dot name (`.git`, `.gitmodules`, `.gitattributes`):
/// only a link Git reads nothing through goes, never its target, so the
/// configuration and repository the later Git steps were proven against stay
/// the same.
pub(crate) fn entered_link_removal(
    model: &crate::CanonicalCommandV1,
    index: usize,
    context: super::super::PathContext<'_>,
) -> bool {
    let (Some(cwd), Some(enter)) = (context.cwd.map(Path::new), model.segments.first()) else {
        return false;
    };
    let root = match enter.arguments.as_slice() {
        [value] if enter.executable.as_deref() == Some("cd") && plain_step(enter) => {
            linked_root(value, cwd)
        }
        _ => None,
    };
    let Some(root) = root else {
        return false;
    };
    let unlinks = |segment: &crate::CommandSegmentV1| {
        segment.executable.as_deref() == Some("rm")
            && plain_step(segment)
            && matches!(
                segment.arguments.as_slice(),
                [name] if plain(name) && root_link(&root.join(name), context)
            )
    };
    model.confidence == "exact"
        && !model.path_overridden
        && model.wrapper_chain.is_empty()
        && (1..model.segments.len()).all(|right| {
            super::super::worktree_add::separator_between(model, right - 1, right)
                .is_some_and(|separator| separator.trim() == "&&")
        })
        && index > 0
        && model
            .segments
            .get(1..=index)
            .is_some_and(|steps| steps.iter().all(unlinks))
}

fn plain_step(segment: &crate::CommandSegmentV1) -> bool {
    segment.pipeline_index == 0
        && segment.environment_names.is_empty()
        && segment.wrapper_chain.is_empty()
        && !segment.path_overridden
        && !segment
            .text
            .contains(['>', '<', '$', '`', '|', '&', ';', '\n', '\r'])
}

/// `rm [-f] [--] <link>...` removing only links at the root of linked
/// worktrees of the session's repository, which an agent places there (Git
/// refuses to remove a worktree that still holds them). It deletes no data,
/// so it is not a destructive delete.
pub(crate) fn link_removal(
    segment: &crate::CommandSegmentV1,
    context: super::super::PathContext<'_>,
) -> bool {
    // Options end at the first `--`; every argument after it is an operand.
    let mut operands = Vec::new();
    let mut options = true;
    for argument in &segment.arguments {
        match argument.as_str() {
            "--" if options => options = false,
            "-f" if options => {}
            _ => {
                options = false;
                operands.push(argument);
            }
        }
    }
    segment.executable.as_deref() == Some("rm")
        && !segment
            .text
            .contains(['>', '<', '$', '`', '|', '&', ';', '\n', '\r'])
        && super::drive_targets_quoted(segment)
        && super::home_targets_unquoted(segment)
        && (1..=16).contains(&operands.len())
        && operands.iter().all(|value| removable_link(value, context))
}

/// `value` resolved lexically: an absolute path, or a leading run of `..`
/// from `cwd`, followed only by plain names. `None` for any other spelling,
/// for a `cwd` that is not its own canonical path, and for a result that
/// holds the cwd.
fn resolved(value: &str, cwd: &Path) -> Option<PathBuf> {
    let absolute = value.starts_with('/');
    if cfg!(windows)
        || value.len() > 4096
        || !(absolute || value.starts_with("../"))
        || !cwd.is_absolute()
        || std::fs::canonicalize(cwd).ok()? != cwd
    {
        return None;
    }
    let mut target = if absolute {
        PathBuf::from("/")
    } else {
        cwd.to_path_buf()
    };
    let mut named = false;
    for component in Path::new(value).components() {
        match component {
            Component::RootDir if absolute => {}
            Component::ParentDir if !absolute && !named => {
                if !target.pop() {
                    return None;
                }
            }
            Component::Normal(name) if name.to_str().is_some_and(plain) => {
                named = true;
                target.push(name);
            }
            _ => return None,
        }
    }
    (named && !cwd.starts_with(&target)).then_some(target)
}

fn plain(name: &str) -> bool {
    !name.is_empty()
        && !name.starts_with(['.', '-'])
        && name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"._-+@".contains(&byte))
}

/// Whether `root` is, in its own canonical spelling, a linked worktree of
/// the repository whose checkout is `cwd`.
fn same_repository_root(root: &Path, cwd: &Path) -> bool {
    root != cwd
        && std::fs::canonicalize(root).is_ok_and(|canonical| canonical == root)
        && super::super::worktree_writes::linked_worktree_dirs(root)
            .zip(session_common(cwd))
            .is_some_and(|((common, _), session)| common == session)
}

/// The shared Git directory of the checkout rooted at `cwd`: its own `.git`
/// directory, or the one a linked worktree there names.
fn session_common(cwd: &Path) -> Option<PathBuf> {
    let marker = cwd.join(".git");
    if marker.symlink_metadata().ok()?.is_dir() {
        return std::fs::canonicalize(marker).ok();
    }
    super::super::worktree_writes::linked_worktree_dirs(cwd).map(|(common, _)| common)
}

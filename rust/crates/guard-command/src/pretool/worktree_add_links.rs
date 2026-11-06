//! `git worktree add <path> <ref> && ln -s <dir> <path>/<sub>/<name>`: sharing
//! a dependency directory such as `node_modules` with the checkout the same
//! command creates.
//!
//! The link path names a directory that does not exist yet, so the ordinary
//! symbolic link screen, which reads the disk, cannot prove it. Right after
//! the add the checkout holds exactly the tree of the commit the worktree
//! proof read, since that proof rules out hooks and filters that could write
//! anything else. The link's parent must be a directory that commit tracks,
//! reached through tracked directories only, and the name must be one the
//! commit does not track there, so `ln` creates a new entry instead of
//! writing through a tracked link or into a tracked directory. If the add
//! fails, the checkout is not there and `ln` fails with it, which is why a
//! stage of the add's own pipeline may stand between them.
//!
//! The target gets the same screen as a link between existing checkouts: an
//! existing, non-hidden directory of a checkout of the same repository, of a
//! related clone, or inside the working directory.
//!
//! A listing later in the chain that names a path through the new link, as in
//! `ls -d <path>/node_modules/.bin/vitest`, reads the target directory, which
//! exists now, so it is screened as the same listing spelled through the
//! target. Every other name in the new checkout is not there yet.

use crate::CommandSegmentV1;
use std::path::{Component, Path, PathBuf};
use std::time::Instant;

#[allow(clippy::too_many_arguments)]
pub(super) fn proven_link(
    segment: &CommandSegmentV1,
    creation: &CommandSegmentV1,
    destination: &Path,
    commit: Option<&str>,
    context: super::super::PathContext<'_>,
    repository: super::super::PathContext<'_>,
    deadline: Option<Instant>,
    execution_environment: Option<&guard_contracts::GuardExecutionEnvironmentV1>,
) -> Option<(PathBuf, PathBuf)> {
    if segment.executable.as_deref() != Some("ln")
        || segment.pipeline_index != 0
        || segment.path_overridden
        || !segment.wrapper_chain.is_empty()
        || !segment.environment_names.is_empty()
        || segment.text.contains([
            '>', '<', '$', '`', '|', '&', ';', '\n', '\r', '*', '?', '[', '{', '~', '\\', '\'', '"',
        ])
    {
        return None;
    }
    let [flag, target, link] = segment.arguments.as_slice() else {
        return None;
    };
    if flag != "-s" || target.is_empty() || target.starts_with('-') || link.starts_with('-') {
        return None;
    }
    let commit = commit?;
    let spec = super::parse(creation)?;
    let cwd = context
        .cwd
        .map(Path::new)
        .filter(|cwd| cwd.is_absolute())
        .and_then(|cwd| std::fs::canonicalize(cwd).ok())?;
    let relative = inside_checkout(link, &cwd, destination)?;
    let (name, parent) = relative.split_last()?;
    let written = parent
        .iter()
        .fold(destination.to_path_buf(), |path, part| path.join(part));
    if !super::super::read_paths::resolved_path_allowed(
        &written.join(name),
        context.home_dir,
        context.cwd,
    ) {
        return None;
    }
    let target = resolved_target(target, &written)?;
    if !target_shares_repository(&target, &cwd, repository, context) {
        return None;
    }
    super::super::git_worktree::tracked_directory_with_free_name(
        creation.executable.as_deref().unwrap_or("git"),
        &spec.leading,
        commit,
        &parent.join("/"),
        name,
        repository,
        deadline,
        execution_environment,
    )
    .filter(|free| *free)
    .map(|_| (written.join(name), target))
}

/// Records a proven link and its target. A second `ln` to the same path
/// would follow the first link and write into the directory it points at, so
/// it fails the proof.
pub(super) fn record_link(links: &mut Vec<(PathBuf, PathBuf)>, link: (PathBuf, PathBuf)) -> bool {
    let key = link.0.to_string_lossy().to_ascii_lowercase();
    let fresh = !links
        .iter()
        .any(|(path, _)| path.to_string_lossy().to_ascii_lowercase() == key);
    links.push(link);
    fresh
}

/// `ls` whose operands below the new checkout all lie through a link an
/// earlier `ln` of the chain proved, each rewritten to the same path below
/// the link's target and screened as a listing there. Operands outside the
/// checkout are screened as written.
pub(super) fn listing_through_links(
    segment: &CommandSegmentV1,
    links: &[(PathBuf, PathBuf)],
    destination: &Path,
    context: super::super::PathContext<'_>,
) -> bool {
    if segment.executable.as_deref() != Some("ls")
        || segment.pipeline_index != 0
        || segment.path_overridden
        || !segment.wrapper_chain.is_empty()
        || !segment.environment_names.is_empty()
        || segment.text.contains([
            '>', '<', '$', '`', '|', '&', ';', '\n', '\r', '*', '?', '[', '{', '~', '\\', '\'', '"',
        ])
    {
        return false;
    }
    let Some(cwd) = context
        .cwd
        .map(Path::new)
        .filter(|cwd| cwd.is_absolute())
        .and_then(|cwd| std::fs::canonicalize(cwd).ok())
    else {
        return false;
    };
    let mut through = false;
    let rewritten = segment
        .arguments
        .iter()
        .map(|argument| {
            if argument.starts_with('-') || !resolved_below(argument, &cwd, destination)? {
                return Some(argument.clone());
            }
            let resolved = resolved_spelling(argument, &cwd)?;
            let (link, target) = links.iter().find(|(link, _)| resolved.starts_with(link))?;
            let rest = resolved.strip_prefix(link).ok()?;
            through = true;
            let rewritten = if rest.as_os_str().is_empty() {
                target.clone()
            } else {
                target.join(rest)
            };
            Some(rewritten.to_str()?.to_owned())
        })
        .collect::<Option<Vec<_>>>();
    rewritten.is_some_and(|arguments| {
        through && super::super::safe_reads::safe_listing_arguments(&arguments, context)
    })
}

/// Whether `value` resolves at or below `destination`, or `None` when it
/// cannot be followed.
fn resolved_below(value: &str, cwd: &Path, destination: &Path) -> Option<bool> {
    resolved_spelling(value, cwd).map(|resolved| resolved.starts_with(destination))
}

/// `value` resolved from `cwd` as the kernel will once the checkout exists:
/// the part that exists now physically, the rest as written.
fn resolved_spelling(value: &str, cwd: &Path) -> Option<PathBuf> {
    if !super::valid_path_text(value) || value.ends_with('/') {
        return None;
    }
    let mut existing = cwd.join(value);
    let mut missing = Vec::new();
    while std::fs::symlink_metadata(&existing).is_err() {
        missing.push(existing.file_name()?.to_owned());
        if !existing.pop() {
            return None;
        }
    }
    let mut resolved = std::fs::canonicalize(&existing).ok()?;
    resolved.extend(missing.iter().rev());
    Some(resolved)
}

/// The names below `destination` that `link` spells, resolved as the kernel
/// will once the checkout exists: the part that exists now physically, the
/// rest as written. Each name is plain ASCII and not hidden.
fn inside_checkout(link: &str, cwd: &Path, destination: &Path) -> Option<Vec<String>> {
    if !super::valid_path_text(link)
        || link.ends_with('/')
        || link.split('/').any(|part| part == ".")
    {
        return None;
    }
    let mut existing = cwd.join(link);
    let mut missing = Vec::new();
    while std::fs::symlink_metadata(&existing).is_err() {
        missing.push(existing.file_name()?.to_str()?.to_owned());
        if !existing.pop() {
            return None;
        }
    }
    let mut resolved = std::fs::canonicalize(&existing).ok()?;
    resolved.extend(missing.iter().rev());
    let relative = resolved.strip_prefix(destination).ok()?;
    let names = relative
        .components()
        .map(|component| match component {
            Component::Normal(part) => part.to_str().filter(|part| plain_name(part)),
            _ => None,
        })
        .map(|part| part.map(str::to_owned))
        .collect::<Option<Vec<_>>>()?;
    (!names.is_empty()).then_some(names)
}

fn plain_name(part: &str) -> bool {
    !part.is_empty()
        && !part.starts_with('.')
        && part.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-' | b'+' | b'@')
        })
}

/// The existing directory the link will point at. A relative target resolves
/// from `written`, the directory holding the link, whose names below the
/// checkout are tracked directories, so `..` there undoes one name.
fn resolved_target(target: &str, written: &Path) -> Option<PathBuf> {
    if !super::valid_path_text(target) {
        return None;
    }
    let supplied = Path::new(target);
    let lexical = if supplied.is_absolute() {
        supplied.to_path_buf()
    } else {
        let mut lexical = written.to_path_buf();
        for component in supplied.components() {
            match component {
                Component::Normal(part) => lexical.push(part),
                Component::ParentDir if lexical.pop() => {}
                Component::CurDir => {}
                _ => return None,
            }
        }
        lexical
    };
    std::fs::canonicalize(lexical)
        .ok()
        .filter(|target| target.is_dir())
}

/// The target is a non-hidden directory below the root of a checkout that
/// shares the repository the worktree is added to, of a related clone of
/// it, or inside the working directory, and no sensitive-path screen
/// refuses it.
fn target_shares_repository(
    target: &Path,
    cwd: &Path,
    repository: super::super::PathContext<'_>,
    context: super::super::PathContext<'_>,
) -> bool {
    if !super::super::read_paths::resolved_path_allowed(target, context.home_dir, context.cwd) {
        return false;
    }
    let Some((workspace, workspace_common)) = repository
        .cwd
        .and_then(|cwd| std::fs::canonicalize(cwd).ok())
        .and_then(|cwd| super::super::worktree_writes::repository_common_directory(&cwd))
    else {
        return false;
    };
    let Some((root, common)) = super::super::worktree_writes::repository_common_directory(target)
    else {
        return false;
    };
    let Ok(relative) = target.strip_prefix(&root) else {
        return false;
    };
    let visible = relative.components().all(|component| {
        matches!(component, Component::Normal(part) if !part.to_string_lossy().starts_with('.'))
    });
    visible
        && !relative.as_os_str().is_empty()
        && (common == workspace_common
            || target.starts_with(cwd)
            || super::super::clone_siblings::related_clones(&root, &workspace))
}

//! `git worktree prune` and a non-forced `git worktree remove` of an
//! unlocked linked worktree registered with the routed checkout. Neither
//! starts a hook; the removal's internal status check is proven
//! execution-free, and Git itself refuses to remove a worktree with local
//! changes unless forced. The removal may also run in a chain that first
//! removes the links placed in the worktree and then reads what is left.

use crate::{CanonicalCommandV1, CommandSegmentV1};
use std::fs;
use std::path::{Path, PathBuf};
use std::time::Instant;

#[path = "worktree_maintenance_chain.rs"]
pub(super) mod chain;

enum Maintenance<'a> {
    Prune,
    Remove(&'a str),
}

pub(super) fn exact_safe_command(
    model: &CanonicalCommandV1,
    context: super::PathContext<'_>,
    deadline: Option<Instant>,
    execution_environment: Option<&guard_contracts::GuardExecutionEnvironmentV1>,
) -> bool {
    if model.segments.len() > 1 {
        return chain::proven(model, context, deadline, execution_environment);
    }
    if model.confidence != "exact"
        || model.path_overridden
        || !model.wrapper_chain.is_empty()
        || model.segments.len() != 1
    {
        return false;
    }
    let segment = &model.segments[0];
    let Some((leading, maintenance)) = parse(segment, context) else {
        return false;
    };
    let Some(executable) = segment.executable.as_deref() else {
        return false;
    };
    let Some(probe) = super::git_session_probe::Probe::new(
        executable,
        leading,
        context,
        deadline,
        execution_environment,
    ) else {
        return false;
    };
    let Some(repository) = routed_directory(leading, &probe.cwd)
        .filter(|directory| fs::symlink_metadata(directory.join(".git")).is_ok_and(|m| m.is_dir()))
    else {
        return false;
    };
    match maintenance {
        Maintenance::Prune => true,
        Maintenance::Remove(target) => {
            let placed = repository.join(target);
            if absent(&placed) {
                // Nothing stands at the named path, so the removal takes away no
                // checkout: Git either refuses outright or drops the
                // administrative entry of a worktree whose files are already
                // gone, which is what the agent asked for. It reaches a real
                // checkout only by reading the argument as the trailing part of
                // a registered worktree's path, so a target any registration
                // ends with keeps its review, and so does a registry this route
                // cannot read.
                let Some(registered) = registered_worktrees(&repository) else {
                    return false;
                };
                return !registered
                    .iter()
                    .any(|path| git_reads_as_suffix(path, target));
            }
            let Ok(worktree) = fs::canonicalize(placed) else {
                return false;
            };
            let Some(admin) = super::git_routes::linked_worktree_admin(&worktree, &repository)
            else {
                return false;
            };
            let worktree_text = worktree.to_string_lossy().into_owned();
            !probe.cwd.starts_with(&worktree)
                && fs::symlink_metadata(admin.join("locked"))
                    .is_err_and(|error| error.kind() == std::io::ErrorKind::NotFound)
                && super::git_config::execution_free(
                    executable,
                    &[
                        "-C".to_owned(),
                        worktree_text,
                        "status".to_owned(),
                        "--porcelain".to_owned(),
                    ],
                    context,
                    deadline,
                    execution_environment,
                    true,
                ) == Some(true)
        }
    }
}

fn parse<'a>(
    segment: &'a CommandSegmentV1,
    context: super::PathContext<'_>,
) -> Option<(&'a [String], Maintenance<'a>)> {
    if segment.executable.as_deref() != Some("git")
        || segment.pipeline_index != 0
        || segment.path_overridden
        || !segment.wrapper_chain.is_empty()
        || !segment.environment_names.is_empty()
        || segment
            .text
            .contains(['>', '<', '$', '`', '|', '&', ';', '\n', '\r'])
        || !super::directory_targets::drive_targets_quoted(segment)
        || !super::directory_targets::home_targets_unquoted(segment)
    {
        return None;
    }
    let arguments = segment.arguments.as_slice();
    let remaining = crate::command_compatibility::git_routed_arguments(arguments, context)?;
    let leading = &arguments[..arguments.len() - remaining.len()];
    if !leading
        .chunks(2)
        .all(|pair| matches!(pair, [flag, _] if flag == "-C"))
    {
        return None;
    }
    let maintenance = match remaining {
        [worktree, prune, flags @ ..] if worktree == "worktree" && prune == "prune" => flags
            .iter()
            .all(|flag| matches!(flag.as_str(), "-n" | "--dry-run" | "-v" | "--verbose"))
            .then_some(Maintenance::Prune)?,
        [worktree, remove, target] if worktree == "worktree" && remove == "remove" => {
            let plain = !target.is_empty()
                && !target.starts_with(['-', '~'])
                && super::safe_directory_target(target);
            plain.then_some(Maintenance::Remove(target.as_str()))?
        }
        _ => return None,
    };
    Some((leading, maintenance))
}

/// Whether nothing stands at the path. Only a proven absence counts: any other
/// error leaves the path unknown, and an unknown path is not a proof.
fn absent(path: &Path) -> bool {
    fs::symlink_metadata(path).is_err_and(|error| error.kind() == std::io::ErrorKind::NotFound)
}

/// How many registrations this route reads before it stops understanding the
/// registry.
const REGISTERED_WORKTREE_LIMIT: usize = 256;

/// Every linked worktree this repository registers, read from its own
/// administrative directory. `None` means the registry could not be read, which
/// is not a proof that it is empty.
fn registered_worktrees(repository: &Path) -> Option<Vec<PathBuf>> {
    let registry = repository.join(".git").join("worktrees");
    let entries = match fs::read_dir(&registry) {
        Ok(entries) => entries,
        // A repository that has never had a linked worktree has no registry.
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Some(Vec::new()),
        Err(_) => return None,
    };
    let mut paths = Vec::new();
    for entry in entries {
        if paths.len() == REGISTERED_WORKTREE_LIMIT {
            return None;
        }
        let pointer = entry.ok()?.path().join("gitdir");
        // A registration too large to be a path is a registry this route does
        // not understand, so it stops reading rather than ignoring the entry,
        // and it stops at the bound rather than after taking the whole file in.
        let gitdir = super::git_routes::bounded_git_metadata(&pointer)?;
        let gitdir = Path::new(gitdir.trim_end());
        // Git 2.48 writes the backlink relative to the registration under
        // `worktree.useRelativePaths`, and resolves it against that directory
        // before it matches a removal's argument. This route compares the
        // registration as it stands, so a relative pointer names a path it
        // cannot compare and leaves the registry unread.
        if !gitdir.is_absolute() {
            return None;
        }
        // The file points at the worktree's own `.git`; the worktree is its
        // parent.
        paths.push(gitdir.parent()?.to_path_buf());
    }
    Some(paths)
}

/// Whether Git would resolve the argument as the trailing part of this
/// registered worktree's path. Git matches at a directory boundary, so `fix`
/// matches `/w/fix` but not `/w/prefix`, and it compares the way the filesystem
/// does, so a target differing only in case still counts.
fn git_reads_as_suffix(registered: &Path, target: &str) -> bool {
    let registered = registered.to_string_lossy();
    let registered = registered.as_bytes();
    let target = target.as_bytes();
    let Some(head) = registered.len().checked_sub(target.len()) else {
        return false;
    };
    registered[head..].eq_ignore_ascii_case(target)
        && (head == 0 || matches!(registered[head - 1], b'/' | b'\\'))
}

/// The directory Git runs in after the leading `-C` routes, canonical.
fn routed_directory(leading: &[String], cwd: &Path) -> Option<PathBuf> {
    let mut directory = cwd.to_path_buf();
    for pair in leading.chunks(2) {
        directory = directory.join(pair.get(1)?);
    }
    fs::canonicalize(directory).ok()
}

#[cfg(test)]
#[path = "worktree_maintenance_absence_tests.rs"]
mod absence_tests;

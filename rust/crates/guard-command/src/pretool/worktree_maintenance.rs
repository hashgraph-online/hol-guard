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
            let Some(worktree) = fs::canonicalize(repository.join(target)).ok() else {
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

/// The directory Git runs in after the leading `-C` routes, canonical.
fn routed_directory(leading: &[String], cwd: &Path) -> Option<PathBuf> {
    let mut directory = cwd.to_path_buf();
    for pair in leading.chunks(2) {
        directory = directory.join(pair.get(1)?);
    }
    fs::canonicalize(directory).ok()
}

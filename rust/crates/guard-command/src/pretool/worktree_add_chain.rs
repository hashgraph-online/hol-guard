//! `git worktree add <path> <ref> && cd <path> && git log ...`: Git reads in
//! the checkout the same command creates.
//!
//! A linked worktree shares its repository's configuration, hooks and object
//! store. The worktree proof already rejects per-worktree configuration
//! (`extensions.*`), every include (so no `includeIf "gitdir:..."` can
//! select other settings for the new path), `core.fsmonitor`, and filters
//! the checked-out tree could select. A read the configuration probe proves
//! helper-free in the repository is therefore helper-free in the new
//! checkout too. Anything else after the `cd` (a write, a push, a path read
//! the repository's own copy could not stand in for) keeps its review.

use crate::{CanonicalCommandV1, CommandSegmentV1};
use std::path::{Component, Path, PathBuf};
use std::time::Instant;

/// Whether the whole command is proven `origin` fetches, one proven
/// `git worktree add`, a `cd` into exactly the checkout it creates, and
/// proven Git reads there with bounded `head`/`tail` stages. The result is
/// memoized so the Git read floor reuses this proof instead of probing again.
pub(in super::super) fn proven(
    model: &CanonicalCommandV1,
    context: super::super::PathContext<'_>,
    deadline: Option<Instant>,
    execution_environment: Option<&guard_contracts::GuardExecutionEnvironmentV1>,
) -> bool {
    if model.confidence != "exact"
        || model.path_overridden
        || !model.wrapper_chain.is_empty()
        || worktree_index(model).is_none()
    {
        return false;
    }
    let key = (
        format!("\0worktree-chain:{}", model.normalized_text),
        Vec::new(),
        context.home_dir.map(str::to_owned),
        context.cwd.map(str::to_owned),
        false,
    );
    super::super::git_probe::memoized(key, || {
        Some(prove(model, context, deadline, execution_environment))
    }) == Some(true)
}

/// The `git worktree add` segment directly followed by a `cd`.
fn worktree_index(model: &CanonicalCommandV1) -> Option<usize> {
    let index = model.segments.iter().position(|segment| {
        segment
            .executable
            .as_deref()
            .is_some_and(|value| super::super::executable_basename(value) == "git")
            && super::parse(segment).is_some()
    })?;
    (model.segments.get(index + 1)?.executable.as_deref() == Some("cd")).then_some(index)
}

fn prove(
    model: &CanonicalCommandV1,
    context: super::super::PathContext<'_>,
    deadline: Option<Instant>,
    execution_environment: Option<&guard_contracts::GuardExecutionEnvironmentV1>,
) -> bool {
    let Some(add) = worktree_index(model) else {
        return false;
    };
    let segments = &model.segments;
    // `git fetch origin main && git worktree add ... origin/main` refreshes
    // the start point first; the worktree proof then admits only the
    // standard LFS filter, since the fetched tree is not the one it read.
    let mut fetch_before = false;
    for segment in &segments[..add] {
        let proven = if segment.pipeline_index == 0 {
            super::super::git_remote_ops::proven_fetch(
                segment,
                context,
                deadline,
                execution_environment,
            )
        } else {
            stdin_stage(segment, context, execution_environment)
        };
        if !proven {
            return false;
        }
        fetch_before = true;
    }
    let creation = &segments[add];
    let cd = &segments[add + 1];
    if creation.pipeline_index != 0
        || cd.pipeline_index != 0
        || super::separator_between(model, add, add + 1)
            .as_deref()
            .map(str::trim)
            != Some("&&")
    {
        return false;
    }
    let Some((destination, chdir)) = super::proven_checkout(
        creation,
        fetch_before,
        context,
        deadline,
        execution_environment,
    ) else {
        return false;
    };
    if cd_target(cd, context).as_ref() != Some(&destination) {
        return false;
    }
    // Reads are proven in the repository the checkout belongs to. If the
    // `cd` fails, a read after `;` runs in the shell's own directory, so `;`
    // is accepted only when that directory is the proven repository.
    let fallback_proven = chdir.is_none() || chdir.as_deref() == context.cwd;
    let repository = super::super::PathContext {
        cwd: chdir.as_deref().or(context.cwd),
        ..context
    };
    (add + 2..segments.len()).all(|index| {
        let joined = super::separator_between(model, index - 1, index);
        if !joined
            .as_deref()
            .is_some_and(|separator| match separator.trim() {
                "&&" | "|" => true,
                ";" => fallback_proven,
                _ => false,
            })
        {
            return false;
        }
        if segments[index].pipeline_index > 0 {
            return stdin_stage(&segments[index], repository, execution_environment);
        }
        unrouted_read(model, index, repository, deadline, execution_environment)
    })
}

/// A Git read with no leading option that could route it to another
/// repository or override configuration, proven by the configuration probe.
/// The path screens run against the repository's directory rather than the
/// new checkout, so only paths that stay inside the checkout are accepted.
fn unrouted_read(
    model: &CanonicalCommandV1,
    index: usize,
    repository: super::super::PathContext<'_>,
    deadline: Option<Instant>,
    execution_environment: Option<&guard_contracts::GuardExecutionEnvironmentV1>,
) -> bool {
    let arguments = &model.segments[index].arguments;
    arguments
        .iter()
        .take_while(|argument| argument.starts_with('-'))
        .all(|argument| {
            matches!(
                argument.as_str(),
                "-P" | "--no-pager" | "--no-optional-locks"
            )
        })
        && arguments.iter().all(|argument| checkout_relative(argument))
        && super::super::git_remote_ops::proven_read(
            model,
            index,
            repository,
            deadline,
            execution_environment,
        )
}

/// An argument that names nothing outside the checkout: no absolute or
/// home-relative path, no parent step, and no `--no-index` comparison of
/// arbitrary files.
fn checkout_relative(argument: &str) -> bool {
    let value = argument
        .split_once('=')
        .filter(|_| argument.starts_with("--"))
        .map_or(argument, |(_, value)| value);
    !value.starts_with('/')
        && !value.starts_with('~')
        && !value.starts_with('\\')
        && argument != "--no-index"
        && !Path::new(value)
            .components()
            .any(|component| component == Component::ParentDir)
}

/// A bounded `head` or `tail` of the previous stage's output.
fn stdin_stage(
    segment: &CommandSegmentV1,
    context: super::super::PathContext<'_>,
    execution_environment: Option<&guard_contracts::GuardExecutionEnvironmentV1>,
) -> bool {
    segment.environment_names.is_empty()
        && segment.wrapper_chain.is_empty()
        && !segment.path_overridden
        && segment.executable.as_deref().is_some_and(|value| {
            matches!(super::super::executable_basename(value), "head" | "tail")
                && super::super::git_worktree::trusted_pipeline_command(
                    value,
                    context,
                    execution_environment,
                )
        })
        && super::super::safe_reads::safe_head_tail_stdin_arguments(&segment.arguments)
}

/// The directory `cd <path>` enters, spelled lexically. A shell `cd`
/// resolves `..` against its logical `$PWD`, while Git created the checkout
/// at a physical path, so the two agree only when the reported cwd has no
/// symlinked component and the lexical target equals the canonical
/// destination, which the caller compares.
fn cd_target(
    segment: &CommandSegmentV1,
    context: super::super::PathContext<'_>,
) -> Option<PathBuf> {
    let [value] = segment.arguments.as_slice() else {
        return None;
    };
    if cfg!(windows)
        || !segment.environment_names.is_empty()
        || !segment.wrapper_chain.is_empty()
        || segment.path_overridden
        || !super::valid_path_text(value)
    {
        return None;
    }
    let declared = Path::new(context.cwd?);
    if !declared.is_absolute() || std::fs::canonicalize(declared).ok()? != declared {
        return None;
    }
    // POSIX `cd` searches CDPATH for a relative operand unless it starts
    // with `.` or `..`.
    let supplied = Path::new(value);
    if !supplied.is_absolute() && !value.starts_with("../") && !context.cdpath_unset {
        return None;
    }
    let mut target = PathBuf::new();
    for component in declared.join(supplied).components() {
        match component {
            Component::ParentDir => {
                if !target.pop() {
                    return None;
                }
            }
            Component::CurDir => {}
            other => target.push(other),
        }
    }
    Some(target)
}

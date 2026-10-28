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
//!
//! `git worktree add <path> <ref> && git -C <path> status` is the same read
//! without the `cd`: each read names the new checkout with `-C`, and only
//! a proven `mkdir` may run between them, in the shell's own directory.

use crate::{CanonicalCommandV1, CommandSegmentV1};
use std::path::Path;
use std::time::Instant;

/// Whether the whole command is proven `origin` fetches, one proven
/// `git worktree add`, a `cd` into exactly the checkout it creates, and
/// proven Git reads there with bounded `head`, `tail` and `wc` stages. The
/// result is memoized so the Git read floor reuses this proof instead of
/// probing again.
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

/// The `git worktree add` segment directly followed by a `cd`, a routed
/// `git -C` read, or a `mkdir`.
fn worktree_index(model: &CanonicalCommandV1) -> Option<usize> {
    let index = model.segments.iter().position(|segment| {
        segment
            .executable
            .as_deref()
            .is_some_and(|value| super::super::executable_basename(value) == "git")
            && super::parse(segment).is_some()
    })?;
    let next = model.segments.get(after_creation(model, index))?;
    (matches!(next.executable.as_deref(), Some("cd" | "mkdir"))
        || super::chain_route::routed_position(next).is_some())
    .then_some(index)
}

/// The segment after the `git worktree add` and the stages of its own
/// pipeline. `git worktree add ... 2>&1 | tail -3` reports what the add
/// printed; the checkout it creates is the same one either way.
fn after_creation(model: &CanonicalCommandV1, add: usize) -> usize {
    let mut index = add + 1;
    while model
        .segments
        .get(index)
        .is_some_and(|segment| segment.pipeline_index > 0)
    {
        index += 1;
    }
    index
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
            super::chain_route::stdin_stage(segment, context, execution_environment)
        };
        if !proven {
            return false;
        }
        fetch_before = true;
    }
    let creation = &segments[add];
    let after = after_creation(model, add);
    let Some(next) = segments.get(after) else {
        return false;
    };
    if creation.pipeline_index != 0 || next.pipeline_index != 0 {
        return false;
    }
    if !segments[add + 1..after]
        .iter()
        .all(|segment| super::chain_route::stdin_stage(segment, context, execution_environment))
    {
        return false;
    }
    let entered = next.executable.as_deref() == Some("cd");
    let boundary = super::separator_between(model, after - 1, after);
    // `&&` straight after the add tests the add's own exit status, so the
    // checkout is there before anything reads it. A stage of the add's own
    // pipeline reports its status instead, and `;` reports none, so those
    // spellings prove the add ran only through the `cd`: the checkout proof
    // read the destination and found nothing there, so entering it succeeds
    // only once the add has created it, and a failed `cd` stops the `&&`
    // that carries the reads.
    if !matches!(
        (
            boundary.as_deref().map(str::trim),
            after == add + 1,
            entered
        ),
        (Some("&&"), true, _) | (Some("&&" | ";"), _, true)
    ) {
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
    if entered && super::chain_route::cd_target(next, context).as_ref() != Some(&destination) {
        return false;
    }
    // Reads are proven in the repository the checkout belongs to. If the
    // `cd` fails, a read after `;` runs in the shell's own directory, so `;`
    // is accepted only when that directory is the proven repository. A
    // routed read has no such fallback: after a failed add, `-C` could enter
    // a directory someone else made in the meantime.
    let fallback_proven = entered && (chdir.is_none() || chdir.as_deref() == context.cwd);
    let repository = super::super::PathContext {
        cwd: chdir.as_deref().or(context.cwd),
        ..context
    };
    let first = if entered { after + 1 } else { after };
    // Without a `cd` the chain must read the new checkout: an add followed
    // only by `mkdir` keeps the review work-tree updates give later writes.
    if !entered
        && !segments[first..]
            .iter()
            .any(|segment| segment.executable.as_deref() == Some("git"))
    {
        return false;
    }
    (first..segments.len()).all(|index| {
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
        let segment = &segments[index];
        if segment.pipeline_index > 0 {
            return super::chain_route::stdin_stage(segment, repository, execution_environment);
        }
        if entered {
            return super::chain_route::unrouted_read(
                model,
                index,
                repository,
                deadline,
                execution_environment,
            );
        }
        if segment.executable.as_deref() == Some("mkdir") {
            return proven_mkdir(segment, &destination, context);
        }
        routed_read(
            model,
            index,
            context,
            repository,
            deadline,
            execution_environment,
        )
    })
}

/// A `mkdir` the write screens admit that creates nothing in or below the
/// new checkout. The screens read the disk before the add runs, so a
/// tracked symlink the checkout brings (`notes -> ~/.ssh`) could otherwise
/// lead `mkdir -p` out of it.
fn proven_mkdir(
    segment: &CommandSegmentV1,
    destination: &Path,
    context: super::super::PathContext<'_>,
) -> bool {
    segment.environment_names.is_empty()
        && segment.wrapper_chain.is_empty()
        && !segment.path_overridden
        && !segment
            .arguments
            .iter()
            .any(|argument| super::super::sensitive_path_argument(argument))
        && super::super::directory_targets::home_targets_unquoted(segment)
        && super::super::safe_reads::safe_file_mutation_arguments(
            "mkdir",
            &segment.arguments,
            context,
        )
        && segment
            .arguments
            .last()
            .is_some_and(|target| created_outside(target, destination, context))
}

/// Whether `target` resolves outside `destination`: through the deepest
/// path that exists now, which must not be a dangling link, and then the
/// names still to be created.
fn created_outside(
    target: &str,
    destination: &Path,
    context: super::super::PathContext<'_>,
) -> bool {
    let expanded = if target.starts_with('~') {
        super::super::read_paths::expand_home_read_path(target, context.home_dir)
    } else {
        Some(target.to_owned())
    };
    let (Some(expanded), Some(cwd)) = (
        expanded,
        context.cwd.and_then(|cwd| std::fs::canonicalize(cwd).ok()),
    ) else {
        return false;
    };
    let mut existing = cwd.join(expanded);
    let mut missing = Vec::new();
    while std::fs::symlink_metadata(&existing).is_err() {
        let Some(name) = existing.file_name().map(ToOwned::to_owned) else {
            return false;
        };
        missing.push(name);
        if !existing.pop() {
            return false;
        }
    }
    let Ok(mut resolved) = std::fs::canonicalize(&existing) else {
        return false;
    };
    resolved.extend(missing.iter().rev());
    !resolved.starts_with(destination)
}

/// `git -C <checkout> <read>`: the read Git runs after entering the new
/// checkout, proven as the same read without `-C` in its repository.
fn routed_read(
    model: &CanonicalCommandV1,
    index: usize,
    context: super::super::PathContext<'_>,
    repository: super::super::PathContext<'_>,
    deadline: Option<Instant>,
    execution_environment: Option<&guard_contracts::GuardExecutionEnvironmentV1>,
) -> bool {
    let Some(position) = new_checkout_route(model, index, context) else {
        return false;
    };
    let mut stripped = model.clone();
    stripped.segments[index]
        .arguments
        .drain(position..position + 2);
    super::chain_route::unrouted_read(
        &stripped,
        index,
        repository,
        deadline,
        execution_environment,
    )
}

/// The position of segment `index`'s `-C` when it routes Git into the
/// checkout an earlier `git worktree add` of the same command creates. The
/// spelling is compared before that directory exists, so no route check
/// that needs an existing directory can stand in for it.
pub(crate) fn new_checkout_route(
    model: &CanonicalCommandV1,
    index: usize,
    context: super::super::PathContext<'_>,
) -> Option<usize> {
    let add = worktree_index(model)?;
    let segment = model.segments.get(index).filter(|_| index > add)?;
    let position = super::chain_route::routed_position(segment)?;
    let (_, destination, _) = super::planned_checkout(&model.segments[add], context)?;
    (super::super::directory_targets::home_targets_unquoted(segment)
        && super::chain_route::dash_c_target(&segment.arguments[position + 1], context)
            == Some(destination))
    .then_some(position)
}

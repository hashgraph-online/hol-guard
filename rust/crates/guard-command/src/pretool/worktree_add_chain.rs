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
    let next = model.segments.get(index + 1)?;
    (matches!(next.executable.as_deref(), Some("cd" | "mkdir")) || routed_position(next).is_some())
        .then_some(index)
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
    let next = &segments[add + 1];
    if creation.pipeline_index != 0
        || next.pipeline_index != 0
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
    let entered = next.executable.as_deref() == Some("cd");
    if entered && cd_target(next, context).as_ref() != Some(&destination) {
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
    let first = if entered { add + 2 } else { add + 1 };
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
            return stdin_stage(segment, repository, execution_environment);
        }
        if entered {
            return unrouted_read(model, index, repository, deadline, execution_environment);
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
    unrouted_read(
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
    let position = routed_position(segment)?;
    let (_, destination, _) = super::planned_checkout(&model.segments[add], context)?;
    (super::super::directory_targets::home_targets_unquoted(segment)
        && dash_c_target(&segment.arguments[position + 1], context) == Some(destination))
    .then_some(position)
}

/// The index of the single `-C` among a Git read's leading options.
fn routed_position(segment: &CommandSegmentV1) -> Option<usize> {
    if segment.executable.as_deref() != Some("git") {
        return None;
    }
    let mut position = None;
    let mut index = 0;
    loop {
        match segment.arguments.get(index).map(String::as_str) {
            Some("-P" | "--no-pager" | "--no-optional-locks") => index += 1,
            Some("-C") if position.is_none() => {
                position = Some(index);
                index += 2;
            }
            _ => return position.filter(|position| *position + 1 < segment.arguments.len()),
        }
    }
}

/// The directory `git -C <path>` enters. Git changes directory physically,
/// so the parent is resolved through any symlink and only the final name,
/// which the add itself creates, is taken as spelled.
fn dash_c_target(value: &str, context: super::super::PathContext<'_>) -> Option<PathBuf> {
    let expanded;
    let value = if value.starts_with("~/") {
        if cfg!(windows) || !context.shell_home_matches {
            return None;
        }
        expanded = super::super::read_paths::expand_home_read_path(value, context.home_dir)?;
        expanded.as_str()
    } else {
        value
    };
    if !super::valid_path_text(value) {
        return None;
    }
    let supplied = Path::new(value);
    let target = if supplied.is_absolute() {
        supplied.to_path_buf()
    } else {
        std::fs::canonicalize(context.cwd?).ok()?.join(supplied)
    };
    let leaf = target.file_name()?;
    Some(std::fs::canonicalize(target.parent()?).ok()?.join(leaf))
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

/// The directory `cd <path>` enters. A shell `cd` resolves `..` against its
/// logical `$PWD`, while Git created the checkout at a physical path, so the
/// two agree only when the reported cwd has no symlinked component. The
/// lexical target's parent is then resolved physically and the result is
/// compared with the canonical destination by the caller.
fn cd_target(
    segment: &CommandSegmentV1,
    context: super::super::PathContext<'_>,
) -> Option<PathBuf> {
    let [value] = segment.arguments.as_slice() else {
        return None;
    };
    if !segment.environment_names.is_empty()
        || !segment.wrapper_chain.is_empty()
        || segment.path_overridden
        || !super::valid_path_text(value)
    {
        return None;
    }
    entered_directory(value, context)
}

/// On Windows only a drive-absolute operand is proved: the shell skips the
/// CDPATH search for it and does not resolve it against its logical
/// directory. Its parent must be spelled exactly as its canonical path, so
/// case, short names, junctions and links all stay reviewed, and a `:` past
/// the drive (an alternate data stream) is refused.
#[cfg(windows)]
fn entered_directory(value: &str, _context: super::super::PathContext<'_>) -> Option<PathBuf> {
    if value.get(2..).is_none_or(|rest| rest.contains(':')) {
        return None;
    }
    let supplied = Path::new(value);
    let parent = supplied.parent()?;
    let leaf = supplied.file_name()?;
    let canonical = std::fs::canonicalize(parent).ok()?;
    (supplied.is_absolute()
        && super::super::directory_targets::exact_drive_spelling(parent.to_str()?, &canonical))
    .then(|| canonical.join(leaf))
}

#[cfg(not(windows))]
fn entered_directory(value: &str, context: super::super::PathContext<'_>) -> Option<PathBuf> {
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
    // The shell then enters the lexical target physically, through any
    // symlinked parent such as `/tmp` on macOS, just as `-C` does. A link
    // someone else could swap before the `cd` runs is never followed.
    let leaf = target.file_name()?;
    let parent = target.parent()?;
    let home = std::fs::canonicalize(context.home_dir?).ok()?;
    if !super::destination::fixed_symlinks(parent, &home) {
        return None;
    }
    Some(std::fs::canonicalize(parent).ok()?.join(leaf))
}

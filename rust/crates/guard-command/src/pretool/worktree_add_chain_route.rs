//! Command-shape helpers for the `git worktree add` chain proof.
//!
//! The chain proof in `worktree_add_chain` decides which stages of a
//! command belong to the checkout it creates; these decide what one stage
//! is: where a Git read is routed, whether its operands stay inside the
//! checkout, whether a pipeline stage only bounds the previous stage's
//! output, and which directory a `cd` enters.

use crate::{CanonicalCommandV1, CommandSegmentV1};
use std::path::{Component, Path, PathBuf};
use std::time::Instant;

/// The index of the single `-C` among a Git read's leading options.
pub(super) fn routed_position(segment: &CommandSegmentV1) -> Option<usize> {
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
pub(super) fn dash_c_target(
    value: &str,
    context: super::super::PathContext<'_>,
) -> Option<PathBuf> {
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
pub(super) fn unrouted_read(
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

/// A bounded `head`, `tail` or `wc` of the previous stage's output. A `wc`
/// reading its standard input prints counts of what it was handed and names
/// no file of its own, so it reveals less than the lines `head` prints.
pub(super) fn stdin_stage(
    segment: &CommandSegmentV1,
    context: super::super::PathContext<'_>,
    execution_environment: Option<&guard_contracts::GuardExecutionEnvironmentV1>,
) -> bool {
    let Some(executable) = segment.executable.as_deref() else {
        return false;
    };
    let bounded = match super::super::executable_basename(executable) {
        "head" | "tail" => {
            super::super::safe_reads::safe_head_tail_stdin_arguments(&segment.arguments)
        }
        "wc" => super::super::safe_reads::safe_word_count_stdin_arguments(&segment.arguments),
        _ => return false,
    };
    segment.environment_names.is_empty()
        && segment.wrapper_chain.is_empty()
        && !segment.path_overridden
        && bounded
        && super::super::git_worktree::trusted_pipeline_command(
            executable,
            context,
            execution_environment,
        )
}

/// The directory `cd <path>` enters. A shell `cd` resolves `..` against its
/// logical `$PWD`, while Git created the checkout at a physical path, so the
/// two agree only when the reported cwd has no symlinked component. The
/// lexical target's parent is then resolved physically and the result is
/// compared with the canonical destination by the caller.
pub(super) fn cd_target(
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

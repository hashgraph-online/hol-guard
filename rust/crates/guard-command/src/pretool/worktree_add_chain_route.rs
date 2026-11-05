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
    checkout_path(&target)
}

/// The physical path of the checkout an add is creating. Git creates the
/// directories leading to it, so a parent that does not exist yet keeps its
/// missing names below the nearest existing ancestor, exactly as the add's
/// own destination proof spells them.
fn checkout_path(target: &Path) -> Option<PathBuf> {
    let leaf = target.file_name()?;
    let parent = target.parent()?;
    let parent = match std::fs::symlink_metadata(parent) {
        Ok(_) => std::fs::canonicalize(parent).ok()?,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            super::super::worktree_writes::canonical_write_target(parent)?
        }
        Err(_) => return None,
    };
    Some(parent.join(leaf))
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
    // An unquoted `~/` expands from the shell's HOME, as the add's
    // destination does, and the absolute result skips the CDPATH search.
    let expanded;
    let value = if value.starts_with("~/") {
        if cfg!(windows)
            || !context.shell_home_matches
            || !super::super::directory_targets::home_targets_unquoted(segment)
        {
            return None;
        }
        expanded = super::super::read_paths::expand_home_read_path(value, context.home_dir)?;
        expanded.as_str()
    } else {
        value.as_str()
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
    // Links are checked through the nearest existing ancestor, since Git
    // creates any missing parent along with the checkout.
    let existing = target
        .ancestors()
        .skip(1)
        .find(|ancestor| std::fs::symlink_metadata(ancestor).is_ok())?;
    let home = std::fs::canonicalize(context.home_dir?).ok()?;
    if !super::destination::fixed_symlinks(existing, &home) {
        return None;
    }
    checkout_path(&target)
}

/// Whether every entry of the search path the command runs with is absolute
/// and lies outside the checkout the add creates. Once the `cd` has entered
/// the new checkout a relative entry names one of its folders, whose
/// contents come from the ref it checks out, so a bare program name after
/// the `cd` could run what that ref supplies. An absolute entry inside the
/// destination says the same thing from the other side: the add refuses an
/// existing destination, so nothing fills that folder but the checkout.
pub(super) fn search_path_outside(
    destination: &Path,
    execution_environment: Option<&guard_contracts::GuardExecutionEnvironmentV1>,
) -> bool {
    screened_search_path(destination, None, execution_environment)
}

/// The same screen for a chain that routes Git into the checkout with `-C`
/// instead of entering it. Those steps look their `git` up on the search
/// path exactly as the steps after a `cd` do, so an entry the new checkout
/// supplies decides what they run either way.
///
/// The shell's own directory does not move here, so a relative entry can be
/// read against it and screened like any other. After a `cd` it would
/// resolve inside the checkout whatever it is spelled, which is why the
/// entered form has no base to offer and refuses one outright.
pub(super) fn routed_search_path_outside(
    destination: &Path,
    base: Option<&Path>,
    execution_environment: Option<&guard_contracts::GuardExecutionEnvironmentV1>,
) -> bool {
    screened_search_path(destination, base, execution_environment)
}

/// Whether every search path entry names a folder outside the new checkout.
/// `base` is the directory a relative entry is read against, and `None`
/// refuses a relative entry because nothing here can say where it lands.
fn screened_search_path(
    destination: &Path,
    base: Option<&Path>,
    execution_environment: Option<&guard_contracts::GuardExecutionEnvironmentV1>,
) -> bool {
    let Some(search_path) = execution_environment
        .map(|environment| std::ffi::OsString::from(&environment.path))
        .or_else(|| std::env::var_os("PATH"))
    else {
        return false;
    };
    std::env::split_paths(&search_path).all(|directory| {
        if directory.is_absolute() {
            return !entry_in_checkout(&directory, destination);
        }
        // An empty entry is the shell's own directory, and `join` on an
        // empty path returns the base, so both read the same way.
        base.is_some_and(|base| !entry_in_checkout(&base.join(&directory), destination))
    })
}

/// Whether one search path entry names a folder of the new checkout. The
/// entry is compared the way the shell will read it, not as it is spelled:
/// an entry the shell cannot be shown to name a folder outside the
/// destination counts as inside it.
fn entry_in_checkout(directory: &Path, destination: &Path) -> bool {
    normalized_entry(directory).is_none_or(|entry| !outside_checkout(&entry, destination))
}

/// Whether the entry can be shown to name a folder the new checkout does
/// not hold. Components are compared one at a time with their letters
/// folded down, so that two spellings of one folder compare equal on a
/// filesystem that ignores case. macOS and Windows both ship one by
/// default, and there `<parent>/APP-FLAT/bin` is a folder of the checkout
/// `git worktree add ../app-flat` creates, however it is written.
///
/// A pair of components that still differ is a difference to rely on only
/// while one of them is ASCII. APFS stores a name in whatever normalization
/// it was written with and reads every normalization of it as the same
/// folder, so `cafe` followed by U+0301 and `caf` plus U+00E9 name one
/// directory while comparing unequal, and folding case does not bring them
/// together. Where both components carry a character outside ASCII, the
/// difference therefore proves nothing and the entry reads as inside the
/// checkout, which withholds the proof and leaves the chain reviewed. An
/// ASCII name is its own canonical form in every normalization, so a
/// difference from one is a real difference whatever the other holds.
///
/// An entry that stops above the destination is outside it too: the add
/// creates the destination and nothing above it, so the ref it checks out
/// does not fill an ancestor.
fn outside_checkout(entry: &Path, destination: &Path) -> bool {
    let mut components = entry.components();
    for expected in destination.components() {
        let Some(actual) = components.next() else {
            return true;
        };
        if actual == expected {
            continue;
        }
        let actual = actual.as_os_str().to_string_lossy();
        let expected = expected.as_os_str().to_string_lossy();
        if actual.to_lowercase() == expected.to_lowercase() {
            continue;
        }
        return actual.is_ascii() || expected.is_ascii();
    }
    false
}

/// A search path entry resolved the way the kernel will resolve it once the
/// add has run: the deepest ancestor that exists now is canonicalized,
/// which follows every symbolic link above the entry and every `..` in it,
/// and the names still to be created are applied to the result.
///
/// The destination does not exist until the add runs, so an entry inside it
/// cannot be resolved on disk and a component-wise comparison of the raw
/// entry reads a spelling the shell never uses: `<repository>/../app-flat/bin`
/// and `<link-to-parent>/app-flat/bin` both name a folder of the checkout
/// while sharing no component with it. An entry that cannot be resolved at
/// all -- a dangling link, a name whose tail still holds `..`, a path with
/// no existing ancestor -- returns `None` and is treated as inside the
/// checkout, because nothing here can say where the shell would land.
fn normalized_entry(directory: &Path) -> Option<PathBuf> {
    let mut existing = directory.to_path_buf();
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

/// A relative path after the `cd` names a file of the new checkout, which
/// the ref supplies. A bare name uses the search path, which
/// [`search_path_outside`] screens. The add refuses an existing
/// destination, so an absolute path that resolves now names a program
/// outside it; one that does not resolve could only come from the checkout.
pub(super) fn resolved_outside(later: &CommandSegmentV1, destination: &Path) -> bool {
    later.executable.as_deref().is_some_and(|value| {
        !value.contains(['/', '\\'])
            || (Path::new(value).is_absolute()
                && std::fs::canonicalize(value)
                    .is_ok_and(|resolved| !resolved.starts_with(destination)))
    })
}

/// A step that only reads and prints writes no configuration, ref or hook a
/// later Git read in the checkout could pick up, so it leaves the
/// destination proof standing. `cd`, `pushd` and `popd` would move those
/// reads out of the checkout the proof answers for, and `rg` runs a
/// caller-chosen program through `--pre`. A bare name resolves on the
/// search path, which [`search_path_outside`] screens, never inside the new
/// checkout.
pub(super) fn inert_step(later: &CommandSegmentV1) -> bool {
    later.executable.as_deref().is_some_and(|value| {
        super::super::executable_basename(value) == value
            && !matches!(value, "cd" | "pushd" | "popd" | "rg")
    }) && later.environment_names.is_empty()
        && later.wrapper_chain.is_empty()
        && !later.path_overridden
        && !super::super::control_flow_flatten::command_word_changes_shell_state(&later.text)
        && super::super::search::grep::creates_nothing(later)
}

/// `git checkout -b <name>`, or `git switch -c <name>`, naming no start
/// point. The chain's add proved this commit's `post-checkout` and
/// `reference-transaction` hooks inert, and the new worktree shares the
/// repository those hooks come from. With no start point the step stays on
/// that commit: it writes one new ref, points `HEAD` at it, and changes no
/// file of the working tree, so no filter or textconv runs over a tree the
/// add never read. A start point would name another commit, whose hooks and
/// tree the add never proved, so a second operand is refused.
pub(super) fn new_branch_step(segment: &CommandSegmentV1) -> bool {
    if segment.executable.as_deref() != Some("git")
        || !segment.environment_names.is_empty()
        || !segment.wrapper_chain.is_empty()
        || segment.path_overridden
    {
        return false;
    }
    let mut arguments = segment.arguments.iter().map(String::as_str);
    let mut word = arguments.next();
    while matches!(word, Some("-P" | "--no-pager" | "--no-optional-locks")) {
        word = arguments.next();
    }
    let flag = match word {
        Some("checkout") => "-b",
        Some("switch") => "-c",
        _ => return false,
    };
    arguments.next() == Some(flag)
        && arguments.next().is_some_and(new_branch_name)
        && arguments.next().is_none()
}

/// A branch name Git reads as a name rather than an option or a path out of
/// the repository: no leading dash, no absolute or home spelling, and no
/// parent step.
fn new_branch_name(name: &str) -> bool {
    !name.is_empty()
        && !name.starts_with('-')
        && !name.starts_with('/')
        && !name.starts_with('~')
        && !name.starts_with('\\')
        && super::valid_path_text(name)
        && !Path::new(name)
            .components()
            .any(|component| component == Component::ParentDir)
}

/// A `mkdir` the write screens admit that creates nothing in or below the
/// new checkout. The screens read the disk before the add runs, so a
/// tracked symlink the checkout brings (`notes -> ~/.ssh`) could otherwise
/// lead `mkdir -p` out of it.
pub(super) fn proven_mkdir(
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

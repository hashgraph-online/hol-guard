//! Exact command sequences joined with `;` or `||` that the single-chain
//! proofs do not cover.
//!
//! * `cd <dir> && ls src; ls tests`: the shell groups this as
//!   `(cd <dir> && ls src); ls tests`. Segments chained to the `cd` with
//!   `&&` or `|` run only in the new directory; every segment after the
//!   first `;` or `||` runs there when the `cd` succeeded and in the
//!   original directory when it failed, so each is proven against both.
//!   `cd <dir> && ls src || echo none && ls tests` splits the same way: a
//!   failed `cd` runs the `||` alternative and everything after it in the
//!   original directory. Git reads follow the same split in the Git
//!   execution-context floor.
//! * `cd <dir>; ls src`: nothing is chained to the `cd`, so every later
//!   segment runs in `<dir>` when the `cd` succeeded and in the original
//!   directory when it failed. Each is proven against both. A Git read is
//!   admitted only without helper context; the Git execution-context floor
//!   inspects its configuration in both directories.
//! * `touch <f> && echo ok || echo fail; rm -f <f>`: a write probe that
//!   creates one new file and removes it again. The file must not exist
//!   before the command runs, so the trailing `rm` can only remove what the
//!   same command created.

use crate::pretool::segment_proof::{cwd_read_executable, exact_safe_segment_with_context};
use crate::pretool::{executable_basename, sensitive_command, PathContext};
use crate::{CanonicalCommandV1, CommandSegmentV1};

const MAX_SEGMENTS: usize = 12;

fn separators(model: &CanonicalCommandV1) -> Option<Vec<String>> {
    model
        .segments
        .windows(2)
        .map(|pair| {
            // Parser spans count Unicode characters, not UTF-8 byte offsets.
            let length = pair[1].span.start.checked_sub(pair[0].span.end)?;
            let separator: String = model
                .normalized_text
                .chars()
                .skip(pair[0].span.end)
                .take(length)
                .collect();
            Some(separator.trim().to_owned())
        })
        .collect()
}

/// A separator after which a segment can run whether or not the leading
/// `cd` succeeded.
fn forks(separator: &str) -> bool {
    matches!(separator, ";" | "||")
}

/// A GitHub CLI read names its repository, so the directory it runs in
/// selects nothing and no Git command runs to resolve a remote.
fn selects_repository(segment: &CommandSegmentV1) -> bool {
    segment
        .arguments
        .iter()
        .enumerate()
        .any(|(index, argument)| {
            (matches!(argument.as_str(), "--repo" | "-R")
                && segment
                    .arguments
                    .get(index + 1)
                    .is_some_and(|value| !value.is_empty() && !value.starts_with('-')))
                || argument
                    .strip_prefix("--repo=")
                    .is_some_and(|value| !value.is_empty())
        })
}

fn plain_segment(segment: &CommandSegmentV1) -> bool {
    segment.environment_names.is_empty()
        && segment.wrapper_chain.is_empty()
        && !segment.path_overridden
}

fn exact_model(model: &CanonicalCommandV1) -> bool {
    model.confidence == "exact"
        && !model.path_overridden
        && model.wrapper_chain.is_empty()
        && (2..=MAX_SEGMENTS).contains(&model.segments.len())
}

pub(in crate::pretool) fn exact_safe_sequence(
    model: &CanonicalCommandV1,
    allow_git_helper_context: bool,
    context: PathContext<'_>,
) -> bool {
    exact_model(model)
        && (cd_then_read_sequence(model, allow_git_helper_context, context)
            || created_file_probe(model, context))
}

/// The verified directory a leading plain `cd <dir>` moves to.
fn leading_cd_target(model: &CanonicalCommandV1, context: PathContext<'_>) -> Option<String> {
    let first = model.segments.first()?;
    if first.executable.as_deref() != Some("cd")
        || !plain_segment(first)
        || first.pipeline_index != 0
        || sensitive_command(&first.text)
        || !crate::pretool::directory_targets::drive_targets_quoted(first)
        || !crate::pretool::directory_targets::home_targets_unquoted(first)
    {
        return None;
    }
    let [target] = first.arguments.as_slice() else {
        return None;
    };
    crate::pretool::safe_reads::verified_cwd_target(target, context)
}

fn changes_directory(segment: &CommandSegmentV1) -> bool {
    segment
        .executable
        .as_deref()
        .is_none_or(|name| matches!(executable_basename(name), "cd" | "pushd" | "popd"))
}

/// `cd <dir>; <rest>` with no other directory change: `<rest>` runs in the
/// returned directory when the `cd` succeeded and in the original directory
/// when it failed. The rest keeps the original text and spans.
pub(in crate::pretool) fn leading_semicolon_cd(
    model: &CanonicalCommandV1,
    context: PathContext<'_>,
) -> Option<(String, CanonicalCommandV1)> {
    if !exact_model(model)
        || separators(model)?.first().map(String::as_str) != Some(";")
        || model.segments[1..].iter().any(changes_directory)
    {
        return None;
    }
    let cwd = leading_cd_target(model, context)?;
    let mut rest = model.clone();
    rest.segments = model.segments[1..].to_vec();
    Some((cwd, rest))
}

/// `cd <dir> && <head>; <tail>` or `cd <dir> && <head> || <tail>` with the
/// head joined by `&&` or `|` and no other directory change. The shell
/// groups it as `(cd <dir> && <head>); <tail>`: the head runs only in
/// `<dir>`, and the tail runs there after the head or in the original
/// directory when the `cd` failed. Returns the
/// directory, every segment after the `cd`, and the tail on its own; both
/// keep the original text and spans.
pub(in crate::pretool) fn leading_and_cd(
    model: &CanonicalCommandV1,
    context: PathContext<'_>,
) -> Option<(String, CanonicalCommandV1, CanonicalCommandV1)> {
    if !exact_model(model) || model.segments[1..].iter().any(changes_directory) {
        return None;
    }
    let separators = separators(model)?;
    let tail = separators.iter().position(|separator| forks(separator))? + 1;
    if separators.first().map(String::as_str) != Some("&&")
        || !separators[..tail - 1]
            .iter()
            .all(|separator| matches!(separator.as_str(), "&&" | "|"))
    {
        return None;
    }
    let cwd = leading_cd_target(model, context)?;
    let mut rest = model.clone();
    rest.segments = model.segments[1..].to_vec();
    let mut after = model.clone();
    after.segments = model.segments[tail..].to_vec();
    Some((cwd, rest, after))
}

fn cd_then_read_sequence(
    model: &CanonicalCommandV1,
    allow_git_helper_context: bool,
    context: PathContext<'_>,
) -> bool {
    let Some(separators) = separators(model) else {
        return false;
    };
    let leading_semicolon = separators.first().map(String::as_str) == Some(";");
    if !(leading_semicolon
        || (separators.first().map(String::as_str) == Some("&&")
            && separators.iter().any(|separator| forks(separator))))
        || !separators
            .iter()
            .all(|separator| matches!(separator.as_str(), "&&" | "|" | ";" | "||"))
    {
        return false;
    }
    let Some(cwd) = leading_cd_target(model, context) else {
        return false;
    };
    let moved = PathContext {
        cwd: Some(&cwd),
        ..context
    };
    // The Git floor splits both forms and inspects each Git read in every
    // directory it can run in. A read that needs the helper probe stays
    // reviewed, because that probe runs in one directory only.
    let git = model.segments[1..]
        .iter()
        .any(|segment| segment.executable.as_deref().map(executable_basename) == Some("git"));
    let allow_git_helper_context = allow_git_helper_context && !leading_semicolon && !git;
    let mut after_fork = false;
    model.segments[1..]
        .iter()
        .zip(&separators)
        .all(|(segment, separator)| {
            after_fork |= forks(separator);
            let executable = segment.executable.as_deref().map(executable_basename);
            plain_segment(segment)
                && !changes_directory(segment)
                && (cwd_read_executable(segment.executable.as_deref())
                    || crate::pretool::version_probes::lone_probe_segment(segment))
                && executable.is_some_and(|name| name != "gh" || selects_repository(segment))
                && exact_safe_segment_with_context(model, segment, allow_git_helper_context, moved)
                && (!after_fork
                    || exact_safe_segment_with_context(
                        model,
                        segment,
                        allow_git_helper_context,
                        context,
                    ))
        })
}

/// The trailing `rm` of a write probe that the native proof accepts: it
/// removes only the file or directory the same command creates, and that path does not
/// exist yet. The compatibility layer does not treat it as a destructive
/// delete.
pub(crate) fn proven_created_file_removal(
    model: &CanonicalCommandV1,
    segment: &CommandSegmentV1,
    context: PathContext<'_>,
) -> bool {
    segment.executable.as_deref() == Some("rm")
        && model
            .segments
            .last()
            .is_some_and(|last| std::ptr::eq(last, segment))
        && exact_model(model)
        && created_file_probe(model, context)
}

fn created_file_probe(model: &CanonicalCommandV1, context: PathContext<'_>) -> bool {
    let (Some(first), Some(last)) = (model.segments.first(), model.segments.last()) else {
        return false;
    };
    let Some(separators) = separators(model) else {
        return false;
    };
    if last.executable.as_deref() != Some("rm")
        || !model
            .segments
            .iter()
            .all(|segment| plain_segment(segment) && segment.pipeline_index == 0)
        || !separators
            .iter()
            .all(|separator| matches!(separator.as_str(), "&&" | "||" | ";"))
    {
        return false;
    }
    let Some((created, directory)) = created_target(first) else {
        return false;
    };
    let Some(removed) = removed_target(&last.arguments, directory) else {
        return false;
    };
    // The absence proof expands `~` to home; a quoted `~` stays a relative path
    // that may name something that already exists.
    if removed != created
        || sensitive_command(&last.text)
        || !crate::pretool::directory_targets::home_targets_unquoted(first)
        || !crate::pretool::directory_targets::home_targets_unquoted(last)
        || !absent_target(created, context)
    {
        return false;
    }
    let mut creation = model.clone();
    creation.segments = vec![first.clone()];
    exact_safe_segment_with_context(&creation, &creation.segments[0], false, context)
        && model.segments[1..model.segments.len() - 1]
            .iter()
            .all(|segment| {
                matches!(
                    segment.executable.as_deref(),
                    Some("echo" | "printf" | "true")
                ) && exact_safe_segment_with_context(model, segment, false, context)
            })
}

/// The path a `touch` or `mkdir` segment creates, and whether it is a
/// directory. A directory path must name only new components: `mkdir -p`
/// creates every missing parent, so `new/../kept` would make `kept` look absent.
fn created_target(segment: &CommandSegmentV1) -> Option<(&String, bool)> {
    let arguments = segment.arguments.as_slice();
    match segment.executable.as_deref() {
        Some("touch") => match arguments {
            [target] => Some((target, false)),
            [separator, target] if separator == "--" => Some((target, false)),
            _ => None,
        },
        Some("mkdir") => {
            let target = match arguments {
                [target] => target,
                [flag, target] if matches!(flag.as_str(), "-p" | "--") => target,
                [parents, separator, target] if parents == "-p" && separator == "--" => target,
                _ => return None,
            };
            plain_directory_path(target).then_some((target, true))
        }
        _ => None,
    }
}

/// The path an `rm` segment removes: a file without `-r`, a directory only with it.
fn removed_target(arguments: &[String], directory: bool) -> Option<&String> {
    let recursive = |flag: &str| matches!(flag, "-r" | "-R" | "-rf" | "-fr" | "-Rf" | "-fR");
    match (arguments, directory) {
        ([target], false) => Some(target),
        ([flag, target], false) if matches!(flag.as_str(), "-f" | "--") => Some(target),
        ([force, separator, target], false) if force == "-f" && separator == "--" => Some(target),
        ([flag, target], true) if recursive(flag) => Some(target),
        ([flag, separator, target], true) if recursive(flag) && separator == "--" => Some(target),
        _ => None,
    }
}

fn plain_directory_path(value: &str) -> bool {
    !value.is_empty()
        && !value.starts_with('-')
        && !value.contains(['*', '?', '[', ']', '{', '}', '$', '`', '\\', '\n'])
        && std::path::Path::new(value).components().all(|component| {
            matches!(
                component,
                std::path::Component::Normal(_) | std::path::Component::RootDir
            )
        })
}

fn absent_target(value: &str, context: PathContext<'_>) -> bool {
    let expanded = crate::pretool::read_paths::expand_home_read_path(value, context.home_dir)
        .unwrap_or_else(|| value.to_owned());
    let path = std::path::Path::new(&expanded);
    let path = if path.is_absolute() {
        path.to_path_buf()
    } else if let Some(cwd) = context
        .cwd
        .filter(|cwd| std::path::Path::new(cwd).is_absolute())
    {
        std::path::Path::new(cwd).join(path)
    } else {
        return false;
    };
    std::fs::symlink_metadata(path).is_err_and(|error| error.kind() == std::io::ErrorKind::NotFound)
}

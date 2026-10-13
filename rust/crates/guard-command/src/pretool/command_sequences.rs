//! Exact command sequences joined with `;` or `||` that the single-chain
//! proofs do not cover.
//!
//! * `cd <dir> && ls src; ls tests`: the shell groups this as
//!   `(cd <dir> && ls src); ls tests`. Segments chained to the `cd` with
//!   `&&` or `|` run only in the new directory; every segment after a `;`
//!   runs there when the `cd` succeeded and in the original directory when
//!   it failed, so each is proven against both.
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

fn cd_then_read_sequence(
    model: &CanonicalCommandV1,
    allow_git_helper_context: bool,
    context: PathContext<'_>,
) -> bool {
    let first = &model.segments[0];
    let Some(separators) = separators(model) else {
        return false;
    };
    if first.executable.as_deref() != Some("cd")
        || !plain_segment(first)
        || first.pipeline_index != 0
        || sensitive_command(&first.text)
        || !crate::pretool::directory_targets::drive_targets_quoted(first)
        || !crate::pretool::directory_targets::home_targets_unquoted(first)
        || separators.first().map(String::as_str) != Some("&&")
        || !separators.iter().any(|separator| separator == ";")
        || !separators
            .iter()
            .all(|separator| matches!(separator.as_str(), "&&" | "|" | ";"))
    {
        return false;
    }
    let [target] = first.arguments.as_slice() else {
        return false;
    };
    let Some(cwd) = crate::pretool::safe_reads::verified_cwd_target(target, context) else {
        return false;
    };
    let moved = PathContext {
        cwd: Some(&cwd),
        ..context
    };
    let mut after_semicolon = false;
    model.segments[1..]
        .iter()
        .zip(&separators)
        .all(|(segment, separator)| {
            after_semicolon |= separator == ";";
            let executable = segment.executable.as_deref();
            plain_segment(segment)
                && (cwd_read_executable(executable)
                    || crate::pretool::version_probes::lone_probe_segment(segment))
                && executable.is_some_and(|name| !matches!(executable_basename(name), "git" | "gh"))
                && exact_safe_segment_with_context(model, segment, allow_git_helper_context, moved)
                && (!after_semicolon
                    || exact_safe_segment_with_context(
                        model,
                        segment,
                        allow_git_helper_context,
                        context,
                    ))
        })
}

/// The trailing `rm` of a write probe that the native proof accepts: it
/// removes only the file the same command creates, and that file does not
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
    if first.executable.as_deref() != Some("touch")
        || last.executable.as_deref() != Some("rm")
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
    let created = match first.arguments.as_slice() {
        [target] => target,
        [separator, target] if separator == "--" => target,
        _ => return false,
    };
    let removed = match last.arguments.as_slice() {
        [target] => target,
        [flag, target] if matches!(flag.as_str(), "-f" | "--") => target,
        [force, separator, target] if force == "-f" && separator == "--" => target,
        _ => return false,
    };
    if removed != created || sensitive_command(&last.text) || !absent_target(created, context) {
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

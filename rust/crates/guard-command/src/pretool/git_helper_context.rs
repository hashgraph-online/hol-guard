use super::{exact_safe_command_with_context, executable_basename, git_config, PathContext};
use crate::CanonicalCommandV1;

pub(super) fn git_helper_context_required(
    model: &CanonicalCommandV1,
    context: PathContext<'_>,
) -> bool {
    if !exact_safe_command_with_context(model, true, context) {
        return false;
    }
    // A relative `-C` after a verified `cd` resolves against the destination.
    let destination = super::segment_proof::verified_cwd_compound_context(model, context);
    let context = PathContext {
        cwd: destination.as_deref().or(context.cwd),
        ..context
    };
    model.segments.iter().any(|segment| {
        segment.executable.as_deref().is_some_and(|executable| {
            executable_basename(executable) == "git"
                    // Leading `-C`/`-P` options precede the subcommand.
                    && crate::command_compatibility::git_inspection_arguments(
                        &segment.arguments,
                        context,
                    )
                    .is_some_and(|arguments| {
                        let option_end = arguments
                            .iter()
                            .position(|argument| argument == "--")
                            .unwrap_or(arguments.len());
                        let active_options = &arguments[1..option_end];
                        matches!(arguments[0].as_str(), "diff" | "log" | "show")
                            && !(active_options
                                .iter()
                                .any(|argument| argument == "--no-ext-diff")
                                && active_options
                                    .iter()
                                    .any(|argument| argument == "--no-textconv"))
                    })
        })
    })
}

/// Only a harness-stamped execution environment can prove which configuration
/// the agent's own Git process will read.
pub(super) fn git_helpers_proven_inert(
    model: &CanonicalCommandV1,
    context: PathContext<'_>,
    deadline: Option<std::time::Instant>,
    execution_environment: Option<&guard_contracts::GuardExecutionEnvironmentV1>,
) -> bool {
    let Some(environment) = execution_environment else {
        return false;
    };
    // After a verified `cd`, the Git process reads configuration from the new
    // directory, so the probe must run there rather than in the reported cwd.
    let destination = super::segment_proof::verified_cwd_compound_context(model, context);
    let context = PathContext {
        cwd: destination.as_deref().or(context.cwd),
        ..context
    };
    model.segments.iter().enumerate().all(|(index, segment)| {
        segment.executable.as_deref().is_none_or(|executable| {
            executable_basename(executable) != "git"
                || (segment.environment_names.is_empty()
                    && super::directory_targets::drive_targets_quoted(segment)
                    && git_config::execution_free(
                        executable,
                        &segment.arguments,
                        context,
                        deadline,
                        Some(environment),
                        stdout_piped(model, index),
                    ) == Some(true))
        })
    })
}

/// Git starts a pager only when its standard output is a terminal. The parser
/// rejects stdout redirection, so a following pipeline stage proves a pipe.
pub(super) fn stdout_piped(model: &CanonicalCommandV1, index: usize) -> bool {
    match (model.segments.get(index), model.segments.get(index + 1)) {
        (Some(segment), Some(next)) => next.pipeline_index == segment.pipeline_index + 1,
        _ => false,
    }
}

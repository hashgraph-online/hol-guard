use super::{exact_safe_command, executable_basename, git_config, PathContext};
use crate::CanonicalCommandV1;

pub(super) fn git_helper_context_required(model: &CanonicalCommandV1) -> bool {
    exact_safe_command(model, true)
        && model.segments.iter().any(|segment| {
            segment.executable.as_deref().is_some_and(|executable| {
                executable_basename(executable) == "git"
                    && segment.arguments.first().is_some_and(|subcommand| {
                        let option_end = segment
                            .arguments
                            .iter()
                            .position(|argument| argument == "--")
                            .unwrap_or(segment.arguments.len());
                        let active_options = &segment.arguments[1..option_end];
                        matches!(subcommand.as_str(), "diff" | "log" | "show")
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
    model.segments.iter().all(|segment| {
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
                    ) == Some(true))
        })
    })
}

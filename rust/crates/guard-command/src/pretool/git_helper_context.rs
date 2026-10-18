use super::{exact_safe_command_with_context, executable_basename, git_config, PathContext};
use crate::CanonicalCommandV1;

pub(super) fn git_helper_context_required(
    model: &CanonicalCommandV1,
    context: PathContext<'_>,
) -> bool {
    if !exact_safe_command_with_context(model, true, context) {
        return false;
    }
    // A proven read prefix holds no Git segment; judge from its `cd` onward.
    let rest = super::segment_proof::after_read_prefix(model, context);
    let model = rest.as_ref().unwrap_or(model);
    // A relative `-C` after a verified `cd` resolves against the destination.
    let destination = super::segment_proof::verified_cwd_compound_context(model, context);
    let context = PathContext {
        cwd: destination.as_deref().or(context.cwd),
        ..context
    };
    (0..model.segments.len()).any(|index| {
        let child = super::fanout_reads::git_xargs_child(model, index);
        segment_runs_helpers(child.as_ref().unwrap_or(&model.segments[index]), context)
    })
}

/// Whether a Git segment's operation can start a configured helper.
fn segment_runs_helpers(original: &crate::CommandSegmentV1, context: PathContext<'_>) -> bool {
    let stripped = super::segment_proof::without_stderr_merge(original);
    let segment = stripped.as_ref().unwrap_or(original);
    segment.executable.as_deref().is_some_and(|executable| {
        executable_basename(executable) == "git"
            // Leading `-C`/`-P` options precede the subcommand.
            && crate::command_compatibility::git_inspection_arguments(&segment.arguments, context)
                .is_some_and(|arguments| {
                    let option_end = arguments
                        .iter()
                        .position(|argument| argument == "--")
                        .unwrap_or(arguments.len());
                    let active_options = &arguments[1..option_end];
                    match arguments[0].as_str() {
                        "diff" | "log" | "show" => !(active_options
                            .iter()
                            .any(|argument| argument == "--no-ext-diff")
                            && active_options
                                .iter()
                                .any(|argument| argument == "--no-textconv")),
                        // A clean filter is the only helper hash-object runs.
                        "hash-object" => {
                            !super::git_hash_object::filters_disabled(&arguments[1..])
                        }
                        // The probe screens the printed entries for credentials.
                        "config" => super::git_config_reads::read_form(&arguments[1..]).is_some(),
                        // These do not page by default, but pager.<name> can, and
                        // an object read can fetch from a partial clone's promisor.
                        "merge-base" | "ls-tree" | "cat-file" | "show-ref" | "for-each-ref"
                        | "rev-list" => true,
                        // blame and reflog page by default; describe honors
                        // pager.describe when it is set.
                        "blame" | "describe" | "reflog" => true,
                        // grep pages by default through pager.grep or core.pager.
                        "grep" => true,
                        // A shortlog pages under pager.shortlog, and both
                        // listings read the repository's configuration.
                        "shortlog" | "check-ignore" => true,
                        // Finding the untracked paths refreshes the index,
                        // which starts a configured core.fsmonitor.
                        "clean" => true,
                        // Reading the files the patch names refreshes the
                        // index, which starts a configured core.fsmonitor.
                        "apply" => true,
                        _ => false,
                    }
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
    let rest = super::segment_proof::after_read_prefix(model, context);
    let model = rest.as_ref().unwrap_or(model);
    // After a verified `cd`, the Git process reads configuration from the new
    // directory, so the probe must run there rather than in the reported cwd.
    let destination = super::segment_proof::verified_cwd_compound_context(model, context);
    let context = PathContext {
        cwd: destination.as_deref().or(context.cwd),
        ..context
    };
    model.segments.iter().enumerate().all(|(index, original)| {
        // `git merge-base ... | xargs git log` runs its Git read as the child.
        let child = super::fanout_reads::git_xargs_child(model, index);
        let original = child.as_ref().unwrap_or(original);
        // A trailing `2>&1` is a redirect, not a Git argument.
        let stripped = super::segment_proof::without_stderr_merge(original);
        let segment = stripped.as_ref().unwrap_or(original);
        segment.executable.as_deref().is_none_or(|executable| {
            executable_basename(executable) != "git"
                // The exact-safe proof already cleared Git reads that start no
                // helper, such as `rev-parse`, so only helper reads need the probe.
                || !segment_runs_helpers(segment, context)
                || (segment.environment_names.is_empty()
                    && super::directory_targets::drive_targets_quoted(segment)
                    && super::directory_targets::home_targets_unquoted(segment)
                    && match git_config::execution_free(
                        executable,
                        &segment.arguments,
                        context,
                        deadline,
                        Some(environment),
                        stdout_piped(model, index),
                    ) {
                        Some(proven) => proven,
                        // Operations the probe does not cover (rev-parse,
                        // ls-files, remote -v, worktree list) run no
                        // configured helper; the exact-safe proof already
                        // admitted them, so they join a proven sequence.
                        None => {
                            crate::command_compatibility::git_inspection_arguments(
                                &segment.arguments,
                                context,
                            )
                            .is_some()
                                && !segment_runs_helpers(segment, context)
                        }
                    })
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

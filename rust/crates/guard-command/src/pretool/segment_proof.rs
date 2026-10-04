use super::{
    executable_basename, pure_expression, safe_directory_target, safe_gh_arguments,
    safe_git_arguments, safe_reads, search, sensitive_command, sensitive_path_argument,
};
use crate::CanonicalCommandV1;

pub(super) fn verified_cwd_compound_context(
    model: &CanonicalCommandV1,
    context: super::PathContext<'_>,
) -> Option<String> {
    let first = model.segments.first()?;
    if model.segments.len() < 2
        || first.executable.as_deref() != Some("cd")
        || !first.environment_names.is_empty()
        || first.pipeline_index != 0
        || model.segments[1..]
            .iter()
            .any(|segment| segment.executable.as_deref() == Some("cd"))
    {
        return None;
    }
    let [target] = first.arguments.as_slice() else {
        return None;
    };
    let cwd = safe_reads::verified_cwd_target(target, context)?;
    for (index, pair) in model.segments.windows(2).enumerate() {
        // Parser spans count Unicode characters, not UTF-8 byte offsets.
        let length = pair[1].span.start.checked_sub(pair[0].span.end)?;
        let separator: String = model
            .normalized_text
            .chars()
            .skip(pair[0].span.end)
            .take(length)
            .collect();
        if (index == 0 && separator.trim() != "&&") || !matches!(separator.trim(), "&&" | "|") {
            return None;
        }
    }
    Some(cwd)
}

pub(super) fn exact_safe_cwd_compound(
    model: &CanonicalCommandV1,
    context: super::PathContext<'_>,
) -> bool {
    let Some(cwd) = verified_cwd_compound_context(model, context) else {
        return false;
    };
    if model.segments.len() == 2
        && matches!(
            model.segments[1].executable.as_deref(),
            Some("cp" | "mkdir" | "touch" | "mv")
        )
    {
        // A verified successful cd has no filesystem side effects. Reuse the
        // standalone mutation proof without admitting a later write chain.
        let mut operation = model.clone();
        operation.segments = vec![model.segments[1].clone()];
        return exact_safe_segment_with_context(
            &operation,
            &operation.segments[0],
            false,
            crate::pretool::PathContext {
                home_dir: context.home_dir,
                cwd: Some(&cwd),
            },
        );
    }
    model.segments[1..].iter().all(|segment| {
        matches!(
            segment.executable.as_deref(),
            Some(
                "pwd"
                    | "true"
                    | "echo"
                    | "printf"
                    | "which"
                    | "whoami"
                    | "uname"
                    | "date"
                    | "sleep"
                    | "ls"
                    | "cat"
                    | "stat"
                    | "test"
                    | "find"
                    | "head"
                    | "tail"
                    | "git"
                    | "gh"
                    | "jq"
                    | "wc"
                    | "rg"
                    | "grep"
                    | "sed"
                    | "sort"
                    | "uniq"
                    | "cut"
            )
        ) && exact_safe_segment_with_context(
            model,
            segment,
            false,
            crate::pretool::PathContext {
                home_dir: context.home_dir,
                cwd: Some(&cwd),
            },
        )
    })
}

pub(crate) fn benign_command_segments(
    model: &CanonicalCommandV1,
    context: super::PathContext<'_>,
) -> Vec<usize> {
    let cwd = verified_cwd_compound_context(model, context);
    if model.confidence != "exact"
        || model.path_overridden
        || !model.wrapper_chain.is_empty()
        // A cwd transition changes the meaning of subsequent relative operands.
        || (cwd.is_none()
            && model
                .segments
                .iter()
                .any(|segment| segment.executable.as_deref() == Some("cd")))
    {
        return Vec::new();
    }
    let proof_context = crate::pretool::PathContext {
        home_dir: context.home_dir,
        cwd: cwd.as_deref().or(context.cwd),
    };
    let segment_benign: Vec<bool> = model
        .segments
        .iter()
        .enumerate()
        .map(|(index, segment)| {
            (index == 0 && cwd.is_some())
                || exact_safe_segment_with_context(model, segment, false, proof_context)
        })
        .collect();
    let mut all_previous_benign = true;
    model
        .segments
        .iter()
        .enumerate()
        .filter_map(|(index, segment)| {
            let benign = segment_benign[index];
            let basename = executable_basename(segment.executable.as_deref().unwrap_or(""));
            let stdin_filter = segment.pipeline_index > 0
                && ((matches!(basename, "head" | "tail")
                    && safe_reads::safe_head_tail_stdin_arguments(&segment.arguments))
                    || (basename == "jq"
                        && safe_reads::safe_jq_stdin_arguments(&segment.arguments))
                    || (basename == "wc"
                        && safe_reads::safe_word_count_stdin_arguments(&segment.arguments))
                    || (basename == "grep"
                        && search::safe_grep_stdin_arguments(&segment.arguments))
                    || (basename == "rg" && search::safe_rg_stdin_arguments(&segment.arguments))
                    || (basename == "sed"
                        && safe_reads::safe_sed_stdin_arguments(&segment.arguments))
                    || super::stdin_filters::safe_arguments(basename, &segment.arguments));
            let path_free = matches!(
                basename,
                "pwd"
                    | "true"
                    | "echo"
                    | "printf"
                    | "which"
                    | "whoami"
                    | "uname"
                    | "date"
                    | "sleep"
            ) || segment.arguments.is_empty()
                || stdin_filter;
            // Context-free public wrappers cannot prove that a file operand or
            // implicit cwd is not a sensitive target. Keep extension consent
            // from upgrading those lexical-only proofs; callers with verified
            // home/cwd context retain the bounded path proof below.
            let requires_path_context = !path_free
                && matches!(
                    basename,
                    "ls" | "cat"
                        | "cp"
                        | "mkdir"
                        | "touch"
                        | "mv"
                        | "head"
                        | "tail"
                        | "rg"
                        | "grep"
                        | "sed"
                        | "wc"
                        | "stat"
                        | "test"
                        | "find"
                );
            let ls_has_explicit_target = basename != "ls" || {
                let mut skip_next = false;
                let mut found = false;
                for argument in &segment.arguments {
                    if skip_next {
                        skip_next = false;
                        continue;
                    }
                    if matches!(
                        argument.as_str(),
                        "-I" | "--ignore"
                            | "--hide"
                            | "-w"
                            | "--width"
                            | "-T"
                            | "--tabsize"
                            | "--color"
                            | "--sort"
                            | "--format"
                            | "--time"
                            | "--time-style"
                            | "--block-size"
                            | "--quoting-style"
                            | "--indicator-style"
                    ) {
                        skip_next = true;
                        continue;
                    }
                    if !argument.starts_with('-') {
                        found = true;
                        break;
                    }
                }
                found
            };
            // Earlier extension-approved segments may rewrite the tree (checkout/pull);
            // a pre-execution path proof only holds while every predecessor is benign.
            let covered = benign
                && ls_has_explicit_target
                && (!requires_path_context
                    || safe_reads::verified_path_context(
                        proof_context.home_dir,
                        proof_context.cwd,
                    ))
                && (path_free || all_previous_benign);
            all_previous_benign = all_previous_benign && benign;
            covered.then_some(index)
        })
        .collect()
}

pub(super) fn exact_safe_segment_with_context(
    model: &CanonicalCommandV1,
    segment: &crate::CommandSegmentV1,
    allow_git_helper_context: bool,
    context: super::PathContext<'_>,
) -> bool {
    let Some(executable) = segment.executable.as_deref() else {
        return false;
    };
    let basename = executable_basename(executable);
    let inert_search = matches!(basename, "rg" | "grep")
        && search::safe_search_arguments_with_context(basename, &segment.arguments, context);
    if (!inert_search && sensitive_command(&segment.text))
        || (!matches!(basename, "rg" | "grep")
            && segment
                .arguments
                .iter()
                .any(|argument| sensitive_path_argument(argument)))
        || !segment.environment_names.is_empty()
        || executable.contains(['/', '\\'])
    {
        return false;
    }
    match basename {
        "cd" => {
            model.segments.len() == 1
                && matches!(segment.arguments.as_slice(), [target] if safe_directory_target(target))
        }
        "pwd" | "true" | "echo" | "printf" | "which" | "whoami" | "uname" => true,
        "date" => safe_reads::safe_date_arguments(&segment.arguments),
        "sleep" => safe_reads::safe_sleep_arguments(&segment.arguments),
        "ls" => safe_reads::safe_listing_arguments(&segment.arguments, context),
        "test" => safe_reads::safe_file_predicate_arguments(&segment.arguments, context),
        "find" => safe_reads::safe_find_listing_arguments(&segment.arguments, context),
        "cat" => safe_reads::safe_plain_file_arguments(&segment.arguments, context),
        "stat" => matches!(segment.arguments.as_slice(), [target]
            if !target.starts_with('-')
                && safe_reads::bounded_read_target(target, context.home_dir, context.cwd, false)),
        "cp" => {
            model.segments.len() == 1
                && safe_reads::safe_copy_arguments(&segment.arguments, context)
        }
        "mkdir" | "touch" | "mv" => {
            model.segments.len() == 1
                && safe_reads::safe_file_mutation_arguments(basename, &segment.arguments, context)
        }
        // Admit stdin only when every producer in the pipeline is also proven safe.
        "head" | "tail" => safe_reads::safe_head_tail_arguments(
            &segment.arguments,
            segment.pipeline_index > 0,
            context,
        ),
        "git" => safe_git_arguments(&segment.arguments, allow_git_helper_context, context),
        "gh" => safe_gh_arguments(&segment.arguments),
        "jq" => {
            segment.pipeline_index > 0 && safe_reads::safe_jq_stdin_arguments(&segment.arguments)
        }
        "wc" => safe_reads::safe_word_count_arguments(
            &segment.arguments,
            segment.pipeline_index > 0,
            context,
        ),
        "sort" | "uniq" | "cut" => {
            segment.pipeline_index > 0
                && super::stdin_filters::safe_arguments(basename, &segment.arguments)
        }
        "rg" | "grep" => {
            search::safe_search_arguments_with_context(basename, &segment.arguments, context)
        }
        "sed" => {
            safe_reads::safe_sed_arguments(&segment.arguments, segment.pipeline_index > 0, context)
        }
        "python" | "python3" | "node" | "nodejs" => {
            pure_expression::safe_inline_expression(basename, &segment.arguments)
        }
        _ => false,
    }
}

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
        || !super::directory_targets::drive_targets_quoted(first)
        || !super::directory_targets::home_targets_unquoted(first)
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
    allow_git_helper_context: bool,
    context: super::PathContext<'_>,
) -> bool {
    let Some(cwd) = verified_cwd_compound_context(model, context) else {
        return false;
    };
    if model.segments.len() == 2
        && matches!(
            model.segments[1].executable.as_deref(),
            Some("cp" | "mkdir" | "touch" | "mv" | "ln" | "rm")
        )
    {
        // `rm` and `ln` delete or publish a path. Re-anchoring them is safe
        // only inside the original workspace or a linked worktree of it.
        // `cd ~` and `cd /tmp` must not become the new write boundary.
        if matches!(model.segments[1].executable.as_deref(), Some("ln" | "rm"))
            && !mutation_directory_stays_in_workspace(&cwd, context)
        {
            return false;
        }
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
                cdpath_unset: context.cdpath_unset,
                rustup_override_absent: context.rustup_override_absent,
                npm_config_inert: context.npm_config_inert,
                shell_home_matches: context.shell_home_matches,
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
                    | "uptime"
                    | "pgrep"
                    | "ls"
                    | "cat"
                    | "base64"
                    | "stat"
                    | "test"
                    | "find"
                    | "head"
                    | "tail"
                    | "git"
                    | "gh"
                    | "jq"
                    | "wc"
                    | "od"
                    | "rg"
                    | "grep"
                    | "sed"
                    | "sort"
                    | "uniq"
                    | "cut"
                    | "du"
                    | "df"
                    | "diff"
            )
        ) && exact_safe_segment_with_context(
            model,
            segment,
            allow_git_helper_context,
            crate::pretool::PathContext {
                home_dir: context.home_dir,
                cdpath_unset: context.cdpath_unset,
                rustup_override_absent: context.rustup_override_absent,
                npm_config_inert: context.npm_config_inert,
                shell_home_matches: context.shell_home_matches,
                cwd: Some(&cwd),
            },
        )
    })
}

/// `ln` and `rm` may follow `cd` only when the new directory is the original
/// workspace, a directory inside it, or a linked worktree of the same
/// repository. A session whose directory is the home, or a directory that
/// contains the home, has no workspace boundary. `cd ~` and `cd /tmp` must
/// not become the new write boundary.
fn mutation_directory_stays_in_workspace(cwd: &str, context: super::PathContext<'_>) -> bool {
    let Some(original) = context
        .cwd
        .and_then(|root| std::fs::canonicalize(root).ok())
    else {
        return false;
    };
    let target = std::path::Path::new(cwd);
    let home = context
        .home_dir
        .and_then(|home| std::fs::canonicalize(home).ok());
    let Some(home) = home else {
        return false;
    };
    if home.starts_with(target) || home.starts_with(&original) {
        return false;
    }
    target.starts_with(&original)
        || super::worktree_writes::same_repository_worktree(&original, target)
}

pub(crate) fn benign_command_segments(
    model: &CanonicalCommandV1,
    context: super::PathContext<'_>,
) -> Vec<usize> {
    let cwd = verified_cwd_compound_context(model, context);
    if model.confidence != "exact"
        || model.path_overridden
        || !model.wrapper_chain.is_empty()
        // Per-segment sleep proofs must not add up past the whole-command bound.
        || !super::safe_scalar::bounded_total_sleep(model)
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
        cdpath_unset: context.cdpath_unset,
        rustup_override_absent: context.rustup_override_absent,
        npm_config_inert: context.npm_config_inert,
        shell_home_matches: context.shell_home_matches,
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
        .filter_map(|(index, original)| {
            // Coverage checks must see the same arguments the proof does. A
            // trailing `2>&1` is not an ls target.
            let stripped = without_stderr_merge(original);
            let segment = stripped.as_ref().unwrap_or(original);
            let benign = segment_benign[index];
            let basename = executable_basename(segment.executable.as_deref().unwrap_or(""));
            let stdin_filter = stdin_filter_segment(segment);
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
                    | "uptime"
                    | "pgrep"
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
                        | "base64"
                        | "cp"
                        | "mkdir"
                        | "touch"
                        | "mv"
                        | "ln"
                        | "rm"
                        | "head"
                        | "tail"
                        | "rg"
                        | "grep"
                        | "sed"
                        | "wc"
                        | "od"
                        | "stat"
                        | "test"
                        | "find"
                        | "du"
                        | "diff"
                        | "npm"
                        | "jq"
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

/// A later pipeline stage that only filters its standard input.
pub(super) fn stdin_filter_segment(segment: &crate::CommandSegmentV1) -> bool {
    let basename = executable_basename(segment.executable.as_deref().unwrap_or(""));
    segment.pipeline_index > 0
        && ((matches!(basename, "head" | "tail")
            && safe_reads::safe_head_tail_stdin_arguments(&segment.arguments))
            || (basename == "jq" && safe_reads::safe_jq_stdin_arguments(&segment.arguments))
            || (basename == "wc"
                && safe_reads::safe_word_count_stdin_arguments(&segment.arguments))
            || (basename == "od" && safe_reads::safe_byte_dump_stdin_arguments(&segment.arguments))
            || (basename == "grep" && search::safe_grep_stdin_arguments(&segment.arguments))
            || (basename == "rg" && search::safe_rg_stdin_arguments(&segment.arguments))
            || (basename == "sed" && safe_reads::safe_sed_stdin_arguments(&segment.arguments))
            || super::stdin_filters::safe_arguments(basename, &segment.arguments))
}

pub(super) fn exact_safe_segment_with_context(
    model: &CanonicalCommandV1,
    segment: &crate::CommandSegmentV1,
    allow_git_helper_context: bool,
    context: super::PathContext<'_>,
) -> bool {
    let stripped = without_stderr_merge(segment);
    let segment = stripped.as_ref().unwrap_or(segment);
    let Some(executable) = segment.executable.as_deref() else {
        return false;
    };
    let basename = executable_basename(executable);
    let inert_search = matches!(basename, "rg" | "grep" | "fd")
        && search::safe_search_arguments_with_context(basename, &segment.arguments, context);
    if (!inert_search
        && !super::source_file_read_segment(segment)
        && sensitive_command(&segment.text))
        || (!matches!(basename, "rg" | "grep" | "fd")
            && segment
                .arguments
                .iter()
                .any(|argument| sensitive_path_argument(argument)))
        || !segment.environment_names.is_empty()
        || executable.contains(['/', '\\'])
    {
        return false;
    }
    if super::version_probes::safe_version_probe(basename, &segment.arguments) {
        return true;
    }
    match basename {
        "cd" => {
            model.segments.len() == 1
                && matches!(segment.arguments.as_slice(), [target] if safe_directory_target(target))
                && super::directory_targets::drive_targets_quoted(segment)
        }
        "pwd" | "true" | "echo" | "printf" | "which" | "whoami" | "uname" => true,
        "type" | "command" => {
            super::lookup_reads::safe_lookup_arguments(basename, &segment.arguments)
        }
        "cargo" | "rustc" => super::rust_toolchain::safe_version_probe(&segment.arguments, context),
        "date" => safe_reads::safe_date_arguments(&segment.arguments),
        "sleep" => safe_reads::safe_sleep_arguments(&segment.arguments),
        "uptime" => segment.arguments.is_empty(),
        "pgrep" => super::safe_scalar::safe_pgrep_arguments(&segment.arguments),
        "ls" => {
            super::listing_reads::safe_listing_segment(&segment.text, &segment.arguments, context)
        }
        "test" => safe_reads::safe_file_predicate_arguments(&segment.arguments, context),
        "find" => super::find_reads::safe_find_listing_arguments(&segment.arguments, context),
        // Operand-free `cat` after a pipe only copies the proven producer's output.
        "cat" => {
            (segment.pipeline_index > 0 && segment.arguments.is_empty())
                || safe_reads::safe_plain_file_arguments(&segment.arguments, context)
        }
        "base64" => super::base64_reads::safe_base64_arguments(&segment.arguments, context),
        "du" => super::metadata_reads::safe_du_arguments(&segment.arguments, context),
        "df" => super::metadata_reads::safe_df_arguments(&segment.arguments),
        "diff" => super::metadata_reads::safe_diff_arguments(&segment.arguments, context),
        "stat" => matches!(segment.arguments.as_slice(), [target]
            if !target.starts_with('-')
                && safe_reads::bounded_read_target(target, context.home_dir, context.cwd, false)),
        "cp" => {
            model.segments.len() == 1
                && super::directory_targets::drive_targets_quoted(segment)
                && (safe_reads::safe_copy_arguments(&segment.arguments, context)
                    || super::recursive_copy::safe_recursive_copy_arguments(
                        &segment.arguments,
                        context,
                    ))
        }
        "mktemp" | "mkdir" | "touch" | "mv" | "ln" | "rm" => {
            model.segments.len() == 1
                && (basename != "ln" && basename != "rm"
                    || super::directory_targets::home_targets_unquoted(segment))
                && (safe_reads::safe_file_mutation_arguments(basename, &segment.arguments, context)
                    // A session run from the directory above its checkouts can
                    // still share a dependency directory between two of them.
                    || (basename == "ln"
                        && super::symlink_writes::safe_symlink_arguments(segment, context)))
        }
        // Admit stdin only when every producer in the pipeline is also proven safe.
        "head" | "tail" => safe_reads::safe_head_tail_arguments(
            &segment.arguments,
            segment.pipeline_index > 0,
            context,
        ),
        "git" => {
            safe_git_arguments(&segment.arguments, allow_git_helper_context, context)
                && super::directory_targets::drive_targets_quoted(segment)
                && super::directory_targets::home_targets_unquoted(segment)
        }
        "gh" => safe_gh_arguments(&segment.arguments, &segment.text),
        "wrangler" => super::wrangler_reads::safe_wrangler_arguments(&segment.arguments),
        "npm" => {
            super::npm_reads::read_only_neighbors(model)
                && super::npm_reads::safe_npm_read(&segment.arguments, context)
        }
        "hol-guard" => super::guard_diagnostics::safe_hol_guard_segment(
            &segment.arguments,
            context.cwd,
            segment.pipeline_index,
        ),
        "jq" => {
            (segment.pipeline_index > 0 && safe_reads::safe_jq_stdin_arguments(&segment.arguments))
                || (segment.pipeline_index == 0
                    && safe_reads::safe_jq_file_arguments(&segment.arguments, context))
        }
        "wc" => safe_reads::safe_word_count_arguments(
            &segment.arguments,
            segment.pipeline_index > 0,
            context,
        ),
        "od" => safe_reads::safe_byte_dump_arguments(
            &segment.arguments,
            segment.pipeline_index > 0,
            context,
        ),
        "sort" | "uniq" | "cut" => {
            segment.pipeline_index > 0
                && super::stdin_filters::safe_arguments(basename, &segment.arguments)
        }
        "rg" | "grep" | "fd" => {
            search::safe_search_arguments_with_context(basename, &segment.arguments, context)
                && super::directory_targets::search_home_targets_safe(
                    segment,
                    context.cwd,
                    context.home_dir,
                )
        }
        "sed" => {
            safe_reads::safe_sed_arguments(&segment.arguments, segment.pipeline_index > 0, context)
        }
        "python" | "python3" | "node" | "nodejs" => {
            super::safe_scalar::version_probe_arguments(basename, &segment.arguments)
                || pure_expression::safe_inline_expression(basename, &segment.arguments)
        }
        _ => false,
    }
}

/// Trailing `2>&1` redirects only join stderr to the segment's own stdout, so
/// the proof applies to the command without them. Every eligible redirect is
/// removed in one copy. The parser admits that redirect only at a token
/// boundary; a quoted or escaped `2>&1` operand is still the last argument but
/// leaves a quote or backslash in the text, so it stays.
fn stderr_merge_tail(segment: &crate::CommandSegmentV1) -> bool {
    segment.arguments.last().map(String::as_str) == Some("2>&1")
        && segment.tokens.last().map(String::as_str) == Some("2>&1")
}

pub(super) fn without_stderr_merge(
    segment: &crate::CommandSegmentV1,
) -> Option<crate::CommandSegmentV1> {
    if !stderr_merge_tail(segment) {
        return None;
    }
    let mut merged = segment.clone();
    while stderr_merge_tail(&merged) {
        let Some(text) = merged.text.strip_suffix("2>&1") else {
            break;
        };
        let command = text.trim_end();
        if command.len() == text.len() || command.ends_with('\\') {
            break;
        }
        merged.arguments.pop();
        merged.tokens.pop();
        merged.text = command.to_owned();
    }
    Some(merged)
}

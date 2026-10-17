use super::{
    executable_basename, pure_expression, safe_directory_target, safe_gh_arguments,
    safe_git_arguments, safe_reads, search, sensitive_path_argument,
};
use crate::CanonicalCommandV1;

pub(crate) use super::stderr_merge::without_stderr_merge;

#[path = "segment_proof_cwd.rs"]
mod cwd;
pub(super) use cwd::{
    after_read_prefix, cwd_read_executable, exact_safe_cwd_compound, verified_cwd_compound_context,
    verified_cwd_list_context,
};

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
        ripgrep_config_absent: context.ripgrep_config_absent,
        psql_environment: context.psql_environment,
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
                    | "ps"
                    | "lsof"
                    | "pg_isready"
                    | "psql"
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
                        | "file"
                        | "npm"
                        | "jq"
                        | "pkill"
                )
                // A file operand prints a source line on a syntax error, so it
                // gets the same session proof as `cat`.
                || (matches!(basename, "node" | "nodejs")
                    && segment.arguments.len() == 2
                    && matches!(segment.arguments[0].as_str(), "--check" | "-c"));
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
    let jq_filter = (basename == "jq")
        .then(|| safe_reads::jq_filter_position(&segment.arguments, segment.pipeline_index > 0))
        .flatten();
    // The same proof the admission arm runs below, so a search segment that
    // arm refuses cannot shed its sensitive-text screen here.
    let inert_search = match basename {
        "grep" => search::grep::safe_grep_segment(model, segment, context),
        "rg" => search::safe_rg_segment(model, segment, context),
        "fd" => search::safe_search_arguments_with_context(basename, &segment.arguments, context),
        _ => false,
    };
    let search_text = if basename == "git" {
        super::git_search_text::pattern_positions(&segment.arguments)
    } else {
        Vec::new()
    };
    if (!inert_search
        && !super::source_file_read_segment(segment)
        && super::git_search_text::sensitive_beyond_patterns(
            &segment.text,
            super::git_search_text::segment_without_patterns(segment),
        ))
        || (!matches!(basename, "rg" | "grep" | "fd")
            && segment
                .arguments
                .iter()
                .enumerate()
                .any(|(index, argument)| {
                    Some(index) != jq_filter
                        && !search_text.contains(&index)
                        && sensitive_path_argument(argument)
                }))
        || !(segment.environment_names.is_empty()
            || (basename == "kubectl"
                && super::kubectl_reads::trusted_kubeconfig_prefix(segment, context)))
        || (executable.contains(['/', '\\'])
            && !super::postgres_reads::trusted_pg_ctl_path(executable, context))
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
        "printenv" => super::safe_scalar::safe_printenv_arguments(&segment.arguments),
        "pgrep" => super::safe_scalar::safe_pgrep_arguments(&segment.arguments),
        "ps" => super::safe_scalar::safe_ps_arguments(&segment.arguments),
        "lsof" => super::safe_scalar::safe_lsof_arguments(&segment.arguments),
        "pkill" => super::process_stops::safe_pkill_arguments(&segment.arguments, context),
        "pg_isready" => super::safe_scalar::safe_pg_isready_arguments(&segment.arguments),
        "ls" => {
            super::listing_reads::safe_listing_segment(&segment.text, &segment.arguments, context)
        }
        "test" => safe_reads::safe_file_predicate_arguments(&segment.arguments, context),
        "[" => segment
            .arguments
            .split_last()
            .is_some_and(|(last, predicate)| {
                last == "]" && safe_reads::safe_file_predicate_arguments(predicate, context)
            }),
        "find" => {
            super::find_reads::safe_find_listing_arguments(&segment.arguments, context)
                || super::fanout_reads::safe_find_exec(model, segment, context)
        }
        "xargs" => {
            super::fanout_reads::safe_xargs(model, segment, context)
                || super::fanout_reads::safe_git_xargs(model, segment, context)
        }
        // Operand-free `cat` after a pipe only copies the proven producer's output.
        "cat" => {
            (segment.pipeline_index > 0 && segment.arguments.is_empty())
                || safe_reads::safe_plain_file_arguments(&segment.arguments, context)
        }
        "base64" => {
            super::base64_reads::safe_base64_arguments(&segment.arguments, context)
                || (segment.pipeline_index > 0
                    && super::stdin_filters::safe_arguments(basename, &segment.arguments))
        }
        "du" => super::metadata_reads::safe_du_arguments(&segment.arguments, context),
        "df" => super::metadata_reads::safe_df_arguments(&segment.arguments),
        "diff" => super::metadata_reads::safe_diff_arguments(&segment.arguments, context),
        "file" => super::metadata_reads::safe_file_arguments(&segment.arguments, context),
        "stat" => matches!(segment.arguments.as_slice(), [target]
            if !target.starts_with('-')
                && safe_reads::bounded_read_target(target, context.home_dir, context.cwd, false)),
        "cp" => {
            super::chain_temporary::copy_segments_allowed(model, segment, context)
                && super::directory_targets::drive_targets_quoted(segment)
                && (safe_reads::safe_copy_arguments(&segment.arguments, context)
                    || super::recursive_copy::safe_recursive_copy_arguments(
                        &segment.arguments,
                        context,
                    ))
        }
        "mktemp" | "mkdir" | "touch" | "mv" | "ln" | "rm" => {
            let alone = basename != "ln" || model.segments.len() == 1;
            (model.segments.len() == 1
                || (basename == "mkdir" && super::chain_temporary::mkdir_chain(model))
                || (basename == "ln" && super::symlink_writes::link_chain(model)))
                && (basename != "ln" && basename != "rm"
                    || super::directory_targets::home_targets_unquoted(segment))
                // In a chain the link must join two checkouts of one
                // repository; a link to any readable source is proven alone.
                && ((alone
                    && safe_reads::safe_file_mutation_arguments(basename, &segment.arguments, context))
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
        "curl" => super::curl_reads::safe_curl_segment(model, segment, context),
        "kubectl" => super::kubectl_reads::safe_kubectl_segment(model, segment, context),
        "export" => super::kubectl_reads::safe_export_segment(model, segment, context),
        "wrangler" => super::wrangler_reads::safe_wrangler_arguments(&segment.arguments),
        "doctl" => super::doctl_reads::safe_doctl_arguments(&segment.arguments),
        "docker" => super::docker_reads::safe_docker_segment(model, segment),
        "nc" | "netcat" => super::port_probes::safe_nc_segment(model, segment),
        "brew" => super::brew_reads::safe_brew_segment(model, segment),
        "pg_ctl" => super::postgres_reads::safe_pg_ctl_arguments(&segment.arguments),
        "psql" => super::postgres_reads::safe_psql_arguments(&segment.arguments, context),
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
        "sort" | "uniq" | "cut" | "tr" => {
            segment.pipeline_index > 0
                && super::stdin_filters::safe_arguments(basename, &segment.arguments)
        }
        "rg" | "grep" | "fd" => {
            (match basename {
                "grep" => search::grep::safe_grep_segment(model, segment, context),
                "rg" => search::safe_rg_segment(model, segment, context),
                _ => search::safe_search_arguments_with_context(
                    basename,
                    &segment.arguments,
                    context,
                ),
            }) && super::directory_targets::search_home_targets_safe(
                segment,
                context.cwd,
                context.home_dir,
            )
        }
        "sed" => {
            safe_reads::safe_sed_arguments(&segment.arguments, segment.pipeline_index > 0, context)
                || super::sed_edits::safe_in_place_segment(model, segment, context)
        }
        // A proof admits a file writer only as the whole command.
        "rustfmt" => {
            model.segments.len() == 1
                && super::rustfmt_writes::safe_rustfmt_arguments(&segment.arguments, context)
        }
        "awk" => super::awk_reads::safe_awk_arguments(
            &segment.arguments,
            segment.pipeline_index > 0,
            context,
        ),
        "python" | "python3" | "node" | "nodejs" => {
            super::safe_scalar::version_probe_arguments(basename, &segment.arguments)
                || pure_expression::safe_inline_expression(basename, &segment.arguments)
                || (matches!(basename, "node" | "nodejs")
                    && super::safe_scalar::node_syntax_check_arguments(
                        &segment.arguments,
                        segment.pipeline_index > 0,
                        context,
                    ))
        }
        _ => false,
    }
}

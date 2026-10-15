//! Single-command read-only source search / view / filter review for Codex
//! tool-output (`commands_support_codex_reads` search and view halves).

use crate::codex_output_args::{
    cat_targets, git_grep_search_args, nl_targets, parse_head_tail_args, parse_sed_args,
    sed_script_is_bounded_print, wc_targets, yq_expression_and_targets, READ_ONLY_PIPE_FILTERS,
    READ_ONLY_SEARCH_COMMANDS, READ_ONLY_SEARCH_WRAPPERS, READ_ONLY_VIEW_COMMANDS,
};
use crate::codex_output_git_diff::git_diff_targets_are_source_like;
use crate::codex_output_py::{py_strip, shlex_split, PyPath};
use crate::codex_output_search::{
    fd_exec_is_bounded_read_only, fd_targets, fd_targets_are_source_like,
    git_grep_uses_external_execution, has_unquoted_shell_control, search_targets,
    search_targets_are_source_like, sed_args_are_bounded_filter, shell_wrapper_script_index,
    target_is_external_source_like, target_is_source_like, Scope,
};
use crate::codex_output_splitters::{split_chain, split_pipeline, uses_untrusted_search_binary};
use crate::codex_output_wrappers::unwrapped_command_parts;

fn executable_of(token: &str) -> String {
    PyPath::new(token).name().to_owned()
}

/// `_codex_source_inspection_target_tokens`.
pub(crate) fn source_inspection_target_tokens(parts: &[String]) -> Vec<String> {
    let command_parts = unwrapped_command_parts(parts);
    let Some(first) = command_parts.first() else {
        return Vec::new();
    };
    let executable = executable_of(first);
    let args = &command_parts[1..];
    if READ_ONLY_VIEW_COMMANDS.contains(&executable.as_str()) {
        return match executable.as_str() {
            "sed" => parse_sed_args(args)
                .map(|parsed| parsed.targets)
                .unwrap_or_default(),
            "head" | "tail" => {
                let (targets, valid, skip_next) = parse_head_tail_args(args);
                if valid && !skip_next {
                    targets
                } else {
                    Vec::new()
                }
            }
            "nl" => nl_targets(args).unwrap_or_default(),
            "wc" => wc_targets(args).unwrap_or_default(),
            "yq" => yq_expression_and_targets(args)
                .map(|(_, targets)| targets)
                .unwrap_or_default(),
            _ => cat_targets(args),
        };
    }
    if READ_ONLY_SEARCH_COMMANDS.contains(&executable.as_str()) {
        if executable == "fd" {
            return fd_targets(args);
        }
        return search_targets(args, &executable);
    }
    if executable == "git" {
        if let Some(git_grep_args) = git_grep_search_args(args) {
            return search_targets(&git_grep_args, &executable);
        }
    }
    let script_index = if READ_ONLY_SEARCH_WRAPPERS.contains(&executable.as_str()) {
        shell_wrapper_script_index(&command_parts)
    } else {
        None
    };
    if let Some(index) = script_index.filter(|index| *index < command_parts.len()) {
        let Some(nested) = shlex_split(&command_parts[index]) else {
            return Vec::new();
        };
        return source_inspection_target_tokens(&nested);
    }
    Vec::new()
}

/// `_codex_command_has_external_source_search_target`.
pub(crate) fn has_external_source_search_target(command_text: &str, scope: Scope) -> bool {
    if let Some(segments) = split_chain(command_text) {
        return segments
            .iter()
            .any(|segment| has_external_source_search_target(segment, scope));
    }
    if let Some(segments) = split_pipeline(command_text).filter(|segments| !segments.is_empty()) {
        return segments
            .iter()
            .any(|segment| has_external_source_search_target(segment, scope));
    }
    let Some(parts) = shlex_split(command_text) else {
        return false;
    };
    source_inspection_target_tokens(&parts)
        .iter()
        .any(|target| target_is_external_source_like(target, scope))
}

fn all_source_like(targets: &[String], scope: Scope) -> bool {
    targets
        .iter()
        .all(|target| target_is_source_like(target, scope, false))
}

fn cat_targets_are_source_like(args: &[String], scope: Scope) -> bool {
    let mut targets: Vec<String> = Vec::new();
    let mut after_terminator = false;
    for arg in args {
        if after_terminator {
            targets.push(arg.clone());
            continue;
        }
        if arg == "--" {
            after_terminator = true;
            continue;
        }
        if arg == "-" {
            return false;
        }
        if arg.starts_with('-') {
            continue;
        }
        targets.push(arg.clone());
    }
    !targets.is_empty() && all_source_like(&targets, scope)
}

fn head_tail_targets_are_source_like(args: &[String], scope: Scope) -> bool {
    let (targets, valid, skip_next) = parse_head_tail_args(args);
    valid && !skip_next && !targets.is_empty() && all_source_like(&targets, scope)
}

fn head_tail_args_are_bounded_filter(args: &[String]) -> bool {
    let (targets, valid, skip_next) = parse_head_tail_args(args);
    valid && !skip_next && targets.is_empty()
}

fn sed_targets_are_read_only_source_like(args: &[String], scope: Scope) -> bool {
    let Some(parsed) = parse_sed_args(args) else {
        return false;
    };
    !parsed.targets.is_empty()
        && parsed.saw_print_suppression
        && parsed
            .scripts
            .iter()
            .all(|script| sed_script_is_bounded_print(script))
        && all_source_like(&parsed.targets, scope)
}

/// `_codex_command_is_bounded_read_only_filter`.
pub(crate) fn is_bounded_read_only_filter(command_text: &str) -> bool {
    let Some(parts) = shlex_split(command_text) else {
        return false;
    };
    let Some(first) = parts.first() else {
        return false;
    };
    if uses_untrusted_search_binary(first) {
        return false;
    }
    let executable = executable_of(first);
    if !READ_ONLY_PIPE_FILTERS.contains(&executable.as_str()) {
        return false;
    }
    let args = &parts[1..];
    match executable.as_str() {
        "cat" => cat_targets(args).is_empty(),
        "sed" => sed_args_are_bounded_filter(args),
        "nl" => nl_targets(args).is_some_and(|targets| targets.is_empty()),
        "wc" => wc_targets(args).is_some_and(|targets| targets.is_empty()),
        _ => head_tail_args_are_bounded_filter(args),
    }
}

/// `_codex_command_is_read_only_source_view`.
pub(crate) fn is_read_only_source_view(command_text: &str, scope: Scope) -> bool {
    let command = py_strip(command_text);
    if command.is_empty() || has_unquoted_shell_control(command) {
        return false;
    }
    let Some(parts) = shlex_split(command) else {
        return false;
    };
    let Some(first) = parts.first() else {
        return false;
    };
    if uses_untrusted_search_binary(first) {
        return false;
    }
    let executable = executable_of(first);
    let args = &parts[1..];
    if !READ_ONLY_VIEW_COMMANDS.contains(&executable.as_str()) {
        return executable == "git" && git_diff_targets_are_source_like(args, scope);
    }
    match executable.as_str() {
        "sed" => sed_targets_are_read_only_source_like(args, scope),
        "head" | "tail" => head_tail_targets_are_source_like(args, scope),
        "nl" => nl_targets(args)
            .is_some_and(|targets| !targets.is_empty() && all_source_like(&targets, scope)),
        "wc" => wc_targets(args)
            .is_some_and(|targets| !targets.is_empty() && all_source_like(&targets, scope)),
        "yq" => yq_expression_and_targets(args)
            .is_some_and(|(_, targets)| all_source_like(&targets, scope)),
        _ => cat_targets_are_source_like(args, scope),
    }
}

/// `_codex_command_is_read_only_source_search`.
pub(crate) fn is_read_only_source_search(command_text: &str, scope: Scope) -> bool {
    let command = py_strip(command_text);
    if command.is_empty() || has_unquoted_shell_control(command) {
        return false;
    }
    let Some(parts) = shlex_split(command) else {
        return false;
    };
    let Some(first) = parts.first() else {
        return false;
    };
    if uses_untrusted_search_binary(first) {
        return false;
    }
    let executable = executable_of(first);
    let args = &parts[1..];
    if READ_ONLY_SEARCH_COMMANDS.contains(&executable.as_str()) {
        if executable == "fd" {
            return fd_targets_are_source_like(args, scope) && fd_exec_is_bounded_read_only(args);
        }
        let ripgrep_config = scope
            .ctx
            .host
            .env("RIPGREP_CONFIG_PATH")
            .is_some_and(|value| !value.is_empty());
        if executable == "rg" && !parts.iter().any(|part| part == "--no-config") && ripgrep_config {
            return false;
        }
        return search_targets_are_source_like(args, scope, &executable);
    }
    if executable == "git" {
        if let Some(git_grep_args) = git_grep_search_args(args) {
            if git_grep_uses_external_execution(&git_grep_args) {
                return false;
            }
            return search_targets_are_source_like(&git_grep_args, scope, &executable);
        }
    }
    let script_index = if READ_ONLY_SEARCH_WRAPPERS.contains(&executable.as_str()) {
        shell_wrapper_script_index(&parts)
    } else {
        None
    };
    match script_index.filter(|index| *index < parts.len()) {
        Some(index) => is_read_only_source_search(&parts[index], scope),
        None => false,
    }
}

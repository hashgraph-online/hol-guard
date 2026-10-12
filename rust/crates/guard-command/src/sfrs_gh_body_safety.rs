//! Static GitHub pull-request body and sensitive-read checks
//! (`github_pr_body_safety.py`). `shell_heredoc_payloads` lives in
//! `sfrs_interpreter_heredoc`; the body-file validation itself in
//! `sfrs_gh_body_file_check`.

// Consumed by the later classifier slices.
#![allow(dead_code)]

use std::path::Path;

use crate::codex_output_env::Ctx;
use crate::codex_output_py::{strip_quotes, PyPath};
use crate::github_command_capabilities::static_markdown_pr_body_file_operand;
use crate::sfrs_constants::FIND_EXEC_TERMINATOR_TOKENS;
use crate::sfrs_constants::{FIND_EXEC_ACTION_FLAGS, FIND_EXEC_PLACEHOLDER_TARGET};
use crate::sfrs_developer_inspection::find_exec_sed_args_are_read_only;
use crate::sfrs_gh_body_file::static_markdown_pr_edit_body_file_operand;
use crate::sfrs_gh_body_file_check::github_pr_body_file_is_safe;
use crate::sfrs_gh_pr_expansion::{
    gh_pr_create_body_args_start_index, shell_token_has_active_expansion,
};
use crate::sfrs_gh_pyshim::decimal_digits_value;
use crate::sfrs_patterns::{FIND_PATH_VALUE_PREDICATES, SHELL_LOCAL_READ_COMMANDS};
use crate::sfrs_pytest_target::shell_token_has_active_glob;
use crate::sfrs_quote_tokens::{
    shell_token_segments, shell_tokens_preserving_quote_context, QuotedToken,
};
use crate::sfrs_request_data::{
    SECRET_EXFILTRATION_DESTINATION_PATTERN, SECRET_EXFILTRATION_NETWORK_PATTERN,
    SECRET_EXFILTRATION_SECRET_PATTERN,
};
use crate::sfrs_requests::classify_sensitive_path;
use crate::sfrs_shell_tokens::{
    shell_command_token_without_attached_redirection, shell_segment_primary_command,
};
use crate::sfrs_substitution::shell_command_substitution_payloads;
use crate::shell_secret_read_support::shell_segment_file_operand_tokens;

const SENSITIVE_MARKERS: &[&str] = &[
    ".aws/",
    ".docker/",
    ".kube/",
    ".ssh/",
    ".env",
    ".git-credentials",
    ".netrc",
    ".npmrc",
    ".pypirc",
    "id_rsa",
];

/// `_path_text_looks_sensitive`.
pub(crate) fn path_text_looks_sensitive(path_text: &str) -> bool {
    let lowered = path_text.to_lowercase();
    SENSITIVE_MARKERS
        .iter()
        .any(|marker| lowered.contains(marker))
}

/// `_text_contains_credential_exfiltration`: a matcher failure is a hit.
pub(crate) fn text_contains_credential_exfiltration(text: &str) -> bool {
    [
        &SECRET_EXFILTRATION_SECRET_PATTERN,
        &SECRET_EXFILTRATION_NETWORK_PATTERN,
        &SECRET_EXFILTRATION_DESTINATION_PATTERN,
    ]
    .iter()
    .all(|pattern| pattern.is_match(text).unwrap_or(true))
}

/// `_bounded_output_consumer`: `head`/`tail` bounded to 1..=1000 lines.
pub(crate) fn bounded_output_consumer(tokens: &[String]) -> bool {
    let count = match tokens {
        [command, count] if command == "head" || command == "tail" => {
            let Some(digits) = count.strip_prefix('-') else {
                return false;
            };
            digits
        }
        [command, flag, count] if (command == "head" || command == "tail") && flag == "-n" => count,
        _ => return false,
    };
    decimal_digits_value(count).is_some_and(|value| (1..=1000).contains(&value))
}

const PIPELINE_SEPARATORS: &[&str] = &["&&", "||", ";", "&", "|", "|&"];

/// `_gh_pr_create_segment_with_bounded_output`.
pub(crate) fn gh_pr_create_segment_with_bounded_output(
    command_text: &str,
) -> Option<Vec<QuotedToken>> {
    let tokens = shell_tokens_preserving_quote_context(command_text);
    let separators: Vec<usize> = tokens
        .iter()
        .enumerate()
        .filter(|(_, token)| PIPELINE_SEPARATORS.contains(&token.plain.as_str()))
        .map(|(index, _)| index)
        .collect();
    if separators.is_empty() {
        return Some(tokens);
    }
    if separators.len() != 1 || tokens[separators[0]].plain != "|" {
        return None;
    }
    let pipe_index = separators[0];
    let mut producer = &tokens[..pipe_index];
    if producer.last().is_some_and(|token| token.plain == "2>&1") {
        producer = &producer[..producer.len() - 1];
    }
    if producer.iter().any(|token| {
        shell_token_has_active_expansion(&token.raw)
            || shell_token_has_active_glob(&token.raw)
            || token.raw.contains('<')
            || token.raw.contains('>')
    }) {
        return None;
    }
    let consumer: Vec<String> = tokens[pipe_index + 1..]
        .iter()
        .map(|token| token.plain.clone())
        .collect();
    bounded_output_consumer(&consumer).then(|| producer.to_vec())
}

fn home_relative_operand_is_unexpanded(operand: &str, args: &[QuotedToken]) -> bool {
    operand.starts_with("~/")
        && !args
            .iter()
            .any(|token| token.plain == operand && token.raw.starts_with("~/"))
}

fn body_file_is_safe(
    operand: &str,
    cwd: Option<&Path>,
    home_dir: Option<&Path>,
    ctx: &Ctx,
) -> bool {
    github_pr_body_file_is_safe(operand, cwd, home_dir, ctx)
}

/// `_gh_pr_create_uses_safe_static_body_file`.
pub(crate) fn gh_pr_create_uses_safe_static_body_file(
    command_text: &str,
    cwd: Option<&Path>,
    home_dir: Option<&Path>,
    ctx: &Ctx,
) -> bool {
    if !shell_command_substitution_payloads(command_text).is_empty() {
        return false;
    }
    let Some(segment) = gh_pr_create_segment_with_bounded_output(command_text) else {
        return false;
    };
    let Some(start) = gh_pr_create_body_args_start_index(&segment) else {
        return false;
    };
    let args = &segment[start..];
    let plain: Vec<String> = args.iter().map(|token| token.plain.clone()).collect();
    let Some(operand) = static_markdown_pr_body_file_operand(&plain) else {
        return false;
    };
    !home_relative_operand_is_unexpanded(&operand, args)
        && body_file_is_safe(&operand, cwd, home_dir, ctx)
}

/// `_gh_pr_edit_uses_safe_static_body_file`.
pub(crate) fn gh_pr_edit_uses_safe_static_body_file(
    command_text: &str,
    cwd: Option<&Path>,
    home_dir: Option<&Path>,
    ctx: &Ctx,
) -> bool {
    if !shell_command_substitution_payloads(command_text).is_empty() {
        return false;
    }
    let segments = shell_token_segments(&shell_tokens_preserving_quote_context(command_text));
    let [segment] = segments.as_slice() else {
        return false;
    };
    let head = ["gh", "pr", "edit"];
    if segment.len() < 4
        || !segment[..3]
            .iter()
            .zip(head)
            .all(|(token, want)| token.raw == want && token.plain == want)
        || segment
            .iter()
            .any(|token| shell_token_has_active_expansion(&token.raw))
    {
        return false;
    }
    let args = &segment[3..];
    let plain: Vec<String> = args.iter().map(|token| token.plain.clone()).collect();
    let Some(operand) = static_markdown_pr_edit_body_file_operand(&plain) else {
        return false;
    };
    !home_relative_operand_is_unexpanded(&operand, args)
        && body_file_is_safe(&operand, cwd, home_dir, ctx)
}

/// `_shell_segment_reads_sensitive_path`.
pub(crate) fn shell_segment_reads_sensitive_path(
    segment: &[String],
    cwd: Option<&Path>,
    home_dir: Option<&Path>,
) -> bool {
    let (Some(command_name), Some(command_index)) = shell_segment_primary_command(segment) else {
        return false;
    };
    let command_segment = &segment[command_index..];
    if command_name == "find" {
        return find_segment_reads_sensitive_path(command_segment, cwd, home_dir);
    }
    if !SHELL_LOCAL_READ_COMMANDS.contains(&command_name.as_str())
        || !shell_read_segment_can_emit_stdout(command_segment)
    {
        return false;
    }
    shell_segment_file_operand_tokens(command_segment)
        .iter()
        .any(|token| {
            let normalized = shell_command_token_without_attached_redirection(token);
            let normalized = strip_quotes(&normalized);
            !normalized.is_empty() && classify_sensitive_path(normalized, cwd, home_dir).is_some()
        })
}

/// `_find_segment_reads_sensitive_path`.
pub(crate) fn find_segment_reads_sensitive_path(
    command_segment: &[String],
    cwd: Option<&Path>,
    home_dir: Option<&Path>,
) -> bool {
    let args = command_segment.get(1..).unwrap_or_default();
    find_exec_reads_file_content(args)
        && find_target_candidates(args)
            .iter()
            .any(|candidate| find_target_candidate_is_sensitive(candidate, cwd, home_dir))
}

/// `_find_exec_reads_file_content`.
pub(crate) fn find_exec_reads_file_content(args: &[String]) -> bool {
    let mut index = 0;
    while index < args.len() {
        if !FIND_EXEC_ACTION_FLAGS.contains(&args[index].as_str()) {
            index += 1;
            continue;
        }
        if index + 1 >= args.len() {
            return false;
        }
        let command_name = PyPath::new(&args[index + 1]).name().to_lowercase();
        let mut exec_index = index + 2;
        let mut exec_args: Vec<String> = Vec::new();
        while exec_index < args.len()
            && !FIND_EXEC_TERMINATOR_TOKENS.contains(&args[exec_index].as_str())
        {
            exec_args.push(args[exec_index].clone());
            exec_index += 1;
        }
        let next = if exec_index < args.len() {
            exec_index + 1
        } else {
            exec_index
        };
        if SHELL_LOCAL_READ_COMMANDS.contains(&command_name.as_str()) {
            if command_name == "sed" && !find_exec_sed_args_are_read_only(&exec_args) {
                index = next;
                continue;
            }
            return true;
        }
        index = next;
    }
    false
}

/// `_find_target_candidates`.
pub(crate) fn find_target_candidates(args: &[String]) -> Vec<String> {
    let mut candidates = Vec::new();
    let mut index = 0;
    while index < args.len() {
        let arg = args[index].as_str();
        if FIND_EXEC_ACTION_FLAGS.contains(&arg) {
            index += 1;
            while index < args.len() && !FIND_EXEC_TERMINATOR_TOKENS.contains(&args[index].as_str())
            {
                index += 1;
            }
            if index < args.len() {
                index += 1;
            }
            continue;
        }
        if FIND_PATH_VALUE_PREDICATES.contains(&arg) && index + 1 < args.len() {
            candidates.push(args[index + 1].clone());
            index += 2;
            continue;
        }
        if !arg.starts_with('-') {
            candidates.push(arg.to_owned());
        }
        index += 1;
    }
    candidates
}

/// `_find_target_candidate_is_sensitive`.
pub(crate) fn find_target_candidate_is_sensitive(
    candidate: &str,
    cwd: Option<&Path>,
    home_dir: Option<&Path>,
) -> bool {
    let normalized = shell_command_token_without_attached_redirection(candidate);
    let normalized = strip_quotes(&normalized);
    if matches!(normalized, "" | "-" | "{}") || normalized == FIND_EXEC_PLACEHOLDER_TARGET {
        return false;
    }
    classify_sensitive_path(normalized, cwd, home_dir).is_some()
        || path_text_looks_sensitive(normalized)
}

/// `_shell_read_segment_can_emit_stdout`.
pub(crate) fn shell_read_segment_can_emit_stdout(segment: &[String]) -> bool {
    let Some(first) = segment.first() else {
        return false;
    };
    let command_name = PyPath::new(first).name().to_lowercase();
    if matches!(command_name.as_str(), "grep" | "egrep" | "fgrep" | "rg") {
        return !search_args_use_quiet_mode(&segment[1..]);
    }
    true
}

/// `_search_args_use_quiet_mode`.
pub(crate) fn search_args_use_quiet_mode(args: &[String]) -> bool {
    let mut skip_next = false;
    for arg in args {
        if skip_next {
            skip_next = false;
            continue;
        }
        let arg = arg.as_str();
        if arg == "--" {
            return false;
        }
        if matches!(arg, "-e" | "--regexp" | "-f" | "--file") {
            skip_next = true;
            continue;
        }
        if arg.starts_with("--regexp=") || arg.starts_with("--file=") {
            continue;
        }
        if (arg.starts_with("-e") || arg.starts_with("-f")) && arg.chars().count() > 2 {
            continue;
        }
        if matches!(arg, "-q" | "--quiet" | "--silent")
            || arg.starts_with("--quiet=")
            || arg.starts_with("--silent=")
        {
            return true;
        }
        if arg.starts_with('-') && !arg.starts_with("--") && arg[1..].contains('q') {
            return true;
        }
    }
    false
}

//! Portable static GitHub PR body checks shared by every host.

use crate::codex_output_env::Ctx;
use crate::github_command_capabilities::static_markdown_pr_body_file_operand;
use crate::sfrs_gh_body_file::static_markdown_pr_edit_body_file_operand;
use crate::sfrs_gh_body_file_check::github_pr_body_file_is_safe;
use crate::sfrs_gh_pr_expansion::{
    gh_pr_create_body_args_start_index, shell_token_has_active_expansion,
};
use crate::sfrs_gh_pyshim::decimal_digits_value;
use crate::sfrs_pytest_target::shell_token_has_active_glob;
use crate::sfrs_quote_tokens::{
    shell_token_segments, shell_tokens_preserving_quote_context, QuotedToken,
};
use crate::sfrs_substitution::shell_command_substitution_payloads;
use std::path::Path;

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

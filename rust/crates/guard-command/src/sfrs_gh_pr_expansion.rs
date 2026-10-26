//! GitHub pull-request argument expansion checks
//! (`secret_file_request_services/github_pr_expansion.py`, the shell-token
//! parts; the Python-AST helpers move with the pytest entrypoint slice).

// Consumed by the later classifier slices.
#![allow(dead_code)]

use std::sync::LazyLock;

use regex::Regex;

use crate::codex_output_py::py_strip;
use crate::env_wrapper::parse_env_wrapper;
use crate::sfrs_constants::{
    SHELL_CONTROL_PREFIX_TOKENS, SUDO_OPTION_VALUE_FLAGS, SUDO_OPTION_VALUE_LONG_FLAGS,
};
use crate::sfrs_gh_environment::command_builtin_options_are_lookup_only;
use crate::sfrs_patterns::SHELL_ASSIGNMENT_PATTERN;
use crate::sfrs_quote_parsing::{
    gh_pr_env_split_string_payloads_with_substitution, skip_generic_shell_wrapper_options,
    skip_gh_pr_options,
};
use crate::sfrs_quote_tokens::{
    shell_token_segments, shell_tokens_preserving_quote_context, QuotedToken,
};
use crate::sfrs_shell_tokens::{
    leading_shell_redirection_tokens_consumed, normalized_shell_command_name,
    shell_command_token_without_attached_redirection,
};
use crate::sfrs_substitution::{shell_command_substitution_payloads, shell_segment_env_index};

const PARAMETER_PREFIXES: &str =
    "{(_0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz*?@#$!-";

static PYTHON_INTERPRETER: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\Apythonw?(?:\d+(?:\.\d+)*)?(?:\.exe)?\z").expect("interpreter pattern")
});

fn plain_tokens(segment: &[QuotedToken]) -> Vec<String> {
    segment.iter().map(|token| token.plain.clone()).collect()
}

/// `_gh_pr_create_body_has_shell_command_substitution`.
pub(crate) fn gh_pr_create_body_has_shell_command_substitution(
    command_text: &str,
    depth: isize,
) -> bool {
    if depth > 2 || shell_command_substitution_payloads(command_text).is_empty() {
        return false;
    }
    let tokens = shell_tokens_preserving_quote_context(command_text);
    for segment in shell_token_segments(&tokens) {
        for payload in gh_pr_env_split_string_payloads_with_substitution(&segment) {
            if gh_pr_create_body_has_shell_command_substitution(&payload, depth + 1) {
                return true;
            }
        }
        let Some(start) = gh_pr_create_body_args_start_index(&segment) else {
            continue;
        };
        if gh_pr_create_body_args_have_substitution(&segment[start..]) {
            return true;
        }
    }
    false
}

/// `_gh_pr_edit_has_shell_command_substitution`.
pub(crate) fn gh_pr_edit_has_shell_command_substitution(command_text: &str) -> bool {
    if shell_command_substitution_payloads(command_text).is_empty() {
        return false;
    }
    let tokens = shell_tokens_preserving_quote_context(command_text);
    shell_token_segments(&tokens).iter().any(|segment| {
        let plain = plain_tokens(segment);
        plain.windows(3).any(|w| w == ["gh", "pr", "edit"])
    })
}

/// `_gh_pr_create_has_active_shell_expansion`.
pub(crate) fn gh_pr_create_has_active_shell_expansion(command_text: &str, depth: isize) -> bool {
    if depth > 2 || (!command_text.contains('$') && !command_text.contains('`')) {
        return false;
    }
    let tokens = shell_tokens_preserving_quote_context(command_text);
    for segment in shell_token_segments(&tokens) {
        for payload in gh_pr_env_split_string_payloads_with_active_expansion(&segment) {
            if gh_pr_create_has_active_shell_expansion(&payload, depth + 1) {
                return true;
            }
        }
        let Some(start) = gh_pr_create_body_args_start_index(&segment) else {
            continue;
        };
        let plain = plain_tokens(&segment);
        let mut index = start;
        while index < segment.len() {
            let consumed = leading_shell_redirection_tokens_consumed(&plain, index);
            if consumed > 0 {
                index += consumed;
                continue;
            }
            if shell_token_has_active_expansion(&segment[index].raw) {
                return true;
            }
            index += 1;
        }
    }
    false
}

/// `_gh_pr_env_split_string_payloads_with_active_expansion`.
pub(crate) fn gh_pr_env_split_string_payloads_with_active_expansion(
    segment: &[QuotedToken],
) -> Vec<String> {
    let plain = plain_tokens(segment);
    let Some(env_index) = shell_segment_env_index(&plain) else {
        return Vec::new();
    };
    let parsed = parse_env_wrapper(&plain[env_index + 1..], None, None);
    parsed
        .split_expansions
        .iter()
        .filter_map(|expansion| {
            let source = env_index + 1 + expansion.source_index;
            (source < segment.len() && shell_token_has_active_expansion(&segment[source].raw))
                .then(|| py_strip(&expansion.payload).to_owned())
        })
        .filter(|payload| !payload.is_empty())
        .collect()
}

/// `_shell_token_has_active_expansion`.
pub(crate) fn shell_token_has_active_expansion(raw_token: &str) -> bool {
    let chars: Vec<char> = raw_token.chars().collect();
    let (mut index, mut single, mut double) = (0, false, false);
    while index < chars.len() {
        let character = chars[index];
        if single {
            single = character != '\'';
            index += 1;
            continue;
        }
        match character {
            '\\' => {
                index += 2;
                continue;
            }
            '\'' if !double => single = true,
            '"' => double = !double,
            '`' => return true,
            '$' if chars
                .get(index + 1)
                .is_some_and(|next| PARAMETER_PREFIXES.contains(*next)) =>
            {
                return true;
            }
            _ => {}
        }
        index += 1;
    }
    false
}

/// `_gh_pr_create_body_args_start_index`.
pub(crate) fn gh_pr_create_body_args_start_index(segment: &[QuotedToken]) -> Option<usize> {
    gh_pr_body_args_start_index(segment, &["create", "new"])
}

/// `_gh_pr_body_args_start_index`.
pub(crate) fn gh_pr_body_args_start_index(
    segment: &[QuotedToken],
    operations: &[&str],
) -> Option<usize> {
    let plain = plain_tokens(segment);
    let mut index = 0;
    while index < segment.len() {
        let consumed = leading_shell_redirection_tokens_consumed(&plain, index);
        if consumed > 0 {
            index += consumed;
            continue;
        }
        let token = &segment[index];
        let stripped = shell_command_token_without_attached_redirection(&token.plain);
        let name = normalized_shell_command_name(&stripped);
        match name.as_str() {
            "gh" => {
                if index + 1 >= segment.len() || segment[index + 1].plain != "pr" {
                    return None;
                }
                let command_index = skip_gh_pr_options(segment, index + 2);
                if command_index >= segment.len() {
                    return None;
                }
                return operations
                    .contains(&segment[command_index].plain.as_str())
                    .then_some(command_index + 1);
            }
            _ if SHELL_ASSIGNMENT_PATTERN
                .is_match(&stripped)
                .unwrap_or(false) =>
            {
                index += 1
            }
            "command" => {
                if command_builtin_options_are_lookup_only(&plain, index + 1) {
                    return None;
                }
                index = skip_command_builtin_options(segment, index + 1);
            }
            "time" | "nice" | "nohup" | "stdbuf" => {
                index = skip_generic_shell_wrapper_options(&name, segment, index + 1);
            }
            "env" => index = skip_env_wrapper_options(segment, index + 1),
            "sudo" => index = skip_sudo_wrapper_options(segment, index + 1),
            "case" => index = skip_shell_case_header(segment, index + 1),
            "select" => index = skip_shell_select_header(segment, index + 1),
            _ if SHELL_CONTROL_PREFIX_TOKENS.contains(&token.plain.as_str())
                || SHELL_CONTROL_PREFIX_TOKENS.contains(&name.as_str()) =>
            {
                index += 1;
            }
            _ => return None,
        }
    }
    None
}

/// `_skip_command_builtin_options`.
pub(crate) fn skip_command_builtin_options(segment: &[QuotedToken], mut index: usize) -> usize {
    while index < segment.len() {
        let plain = segment[index].plain.as_str();
        if plain == "--" {
            return index + 1;
        }
        if !plain.starts_with('-') {
            break;
        }
        index += 1;
    }
    index
}

/// `_skip_shell_case_header`.
pub(crate) fn skip_shell_case_header(segment: &[QuotedToken], mut index: usize) -> usize {
    while index < segment.len() {
        if segment[index].plain.ends_with(')') {
            return index + 1;
        }
        index += 1;
    }
    index
}

/// `_skip_shell_select_header`.
pub(crate) fn skip_shell_select_header(segment: &[QuotedToken], mut index: usize) -> usize {
    while index < segment.len() && segment[index].plain != "do" {
        index += 1;
    }
    index
}

/// `_skip_env_wrapper_options`.
pub(crate) fn skip_env_wrapper_options(segment: &[QuotedToken], index: usize) -> usize {
    let parsed = parse_env_wrapper(
        &plain_tokens(&segment[index.min(segment.len())..]),
        None,
        None,
    );
    match parsed.command_index {
        Some(command_index) if parsed.complete && parsed.split_expansions.is_empty() => {
            index + command_index
        }
        _ => segment.len(),
    }
}

/// `_skip_sudo_wrapper_options`.
pub(crate) fn skip_sudo_wrapper_options(segment: &[QuotedToken], mut index: usize) -> usize {
    while index < segment.len() {
        let plain = segment[index].plain.as_str();
        if SUDO_OPTION_VALUE_FLAGS.contains(&plain) || SUDO_OPTION_VALUE_LONG_FLAGS.contains(&plain)
        {
            index += 2;
            continue;
        }
        let long_valued = SUDO_OPTION_VALUE_LONG_FLAGS
            .iter()
            .any(|flag| plain.starts_with(&format!("{flag}=")));
        if long_valued || plain.starts_with('-') {
            index += 1;
            continue;
        }
        break;
    }
    index
}

/// `_gh_pr_create_body_args_have_substitution`.
pub(crate) fn gh_pr_create_body_args_have_substitution(args: &[QuotedToken]) -> bool {
    let mut index = 0;
    while index < args.len() {
        let arg = &args[index];
        let plain = arg.plain.as_str();
        let substituted = || !shell_command_substitution_payloads(&arg.raw).is_empty();
        if matches!(plain, "--body" | "-b" | "--body-file" | "-F") {
            if index + 1 >= args.len() {
                return false;
            }
            if !shell_command_substitution_payloads(&args[index + 1].raw).is_empty() {
                return true;
            }
            index += 2;
            continue;
        }
        let attached = (plain.starts_with("-F") && plain.len() > 2)
            || (plain.starts_with("-b") && plain.len() > 2)
            || plain.starts_with("--body-file=")
            || plain.starts_with("--body=");
        if attached && substituted() {
            return true;
        }
        index += 1;
    }
    false
}

/// `_is_pytest_python_interpreter_command`.
pub(crate) fn is_pytest_python_interpreter_command(command_name: &str) -> bool {
    PYTHON_INTERPRETER.is_match(command_name)
}

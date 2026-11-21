//! Command-substitution, expansion and nested-script extraction used by the
//! GitHub shell checks (`secret_file_request_services/github_shell_capabilities.py`).

// Consumed by the later classifier slices.
#![allow(dead_code)]

use crate::env_wrapper::parse_env_wrapper;
use crate::hook_adapter_pytext::py_strip;
use crate::sfrs_constants::SHELL_COMMAND_STRING_INTERPRETERS;
use crate::sfrs_patterns::{
    SHELL_ASSIGNMENT_PATTERN, SHELL_COMMAND_SEPARATORS, SHELL_COMMAND_WRAPPERS,
};
use crate::sfrs_selectors::github_pr_head_oid_endpoint_matches;
use crate::sfrs_shell_tokens::{
    iter_shell_command_segments, normalized_shell_command_name, shell_segment_primary_command,
    split_shell_parts, wrapper_option_tokens_consumed,
};
use crate::shell_secret_read_support::shell_interpreter_command_payload;

fn followed_by_open_paren(chars: &[char], index: usize) -> bool {
    chars.get(index + 1) == Some(&'(')
}

fn push_payload(payloads: &mut Vec<String>, payload: String) {
    if !py_strip(&payload).is_empty() {
        payloads.push(payload);
    }
}

/// `_shell_command_substitution_payloads`.
pub(crate) fn shell_command_substitution_payloads(command_text: &str) -> Vec<String> {
    let chars: Vec<char> = command_text.chars().collect();
    let mut payloads = Vec::new();
    let mut index = 0;
    let mut single_quoted = false;
    let mut double_quoted = false;
    while index < chars.len() {
        let c = chars[index];
        if single_quoted {
            if c == '\'' {
                single_quoted = false;
            }
            index += 1;
            continue;
        }
        if double_quoted {
            if c == '\\' && index + 1 < chars.len() {
                index += 2;
                continue;
            }
            if c == '"' {
                double_quoted = false;
                index += 1;
                continue;
            }
            if c == '$' && followed_by_open_paren(&chars, index) {
                let (payload, next) = read_command_substitution(&chars, index + 2);
                push_payload(&mut payloads, payload);
                index = next;
                continue;
            }
            if c == '`' {
                let (payload, next) = read_backtick_command_substitution(&chars, index + 1);
                push_payload(&mut payloads, payload);
                index = next;
                continue;
            }
            index += 1;
            continue;
        }
        if c == '\\' && index + 1 < chars.len() {
            index += 2;
            continue;
        }
        if c == '\'' {
            single_quoted = true;
            index += 1;
            continue;
        }
        if c == '"' {
            double_quoted = true;
            index += 1;
            continue;
        }
        if (c == '$' || c == '<' || c == '>') && followed_by_open_paren(&chars, index) {
            let (payload, next) = read_command_substitution(&chars, index + 2);
            push_payload(&mut payloads, payload);
            index = next;
            continue;
        }
        if c == '`' {
            let (payload, next) = read_backtick_command_substitution(&chars, index + 1);
            push_payload(&mut payloads, payload);
            index = next;
            continue;
        }
        index += 1;
    }
    payloads
}

/// `_read_command_substitution`.
pub(crate) fn read_command_substitution(chars: &[char], start: usize) -> (String, usize) {
    let mut index = start;
    let mut depth = 1usize;
    let mut payload = String::new();
    let mut single_quoted = false;
    let mut double_quoted = false;
    while index < chars.len() {
        let c = chars[index];
        if single_quoted {
            payload.push(c);
            if c == '\'' {
                single_quoted = false;
            }
            index += 1;
            continue;
        }
        if double_quoted {
            payload.push(c);
            if c == '\\' && index + 1 < chars.len() {
                payload.push(chars[index + 1]);
                index += 2;
                continue;
            }
            if c == '"' {
                double_quoted = false;
            }
            index += 1;
            continue;
        }
        if c == '\'' {
            single_quoted = true;
            payload.push(c);
            index += 1;
            continue;
        }
        if c == '"' {
            double_quoted = true;
            payload.push(c);
            index += 1;
            continue;
        }
        if c == '$' && followed_by_open_paren(chars, index) {
            let (nested, next) = read_command_substitution(chars, index + 2);
            payload.push_str(&format!("$({nested})"));
            index = next;
            continue;
        }
        if c == '(' {
            depth += 1;
            payload.push(c);
            index += 1;
            continue;
        }
        if c == ')' {
            depth -= 1;
            if depth == 0 {
                return (payload, index + 1);
            }
            payload.push(c);
            index += 1;
            continue;
        }
        payload.push(c);
        index += 1;
    }
    (payload, index)
}

/// `_read_backtick_command_substitution`.
pub(crate) fn read_backtick_command_substitution(chars: &[char], start: usize) -> (String, usize) {
    let mut index = start;
    let mut payload = String::new();
    while index < chars.len() {
        let c = chars[index];
        if c == '\\' && index + 1 < chars.len() {
            payload.push(c);
            payload.push(chars[index + 1]);
            index += 2;
            continue;
        }
        if c == '$' && followed_by_open_paren(chars, index) {
            let (nested, next) = read_command_substitution(chars, index + 2);
            payload.push_str(&format!("$({nested})"));
            index = next;
            continue;
        }
        if c == '`' {
            return (payload, index + 1);
        }
        payload.push(c);
        index += 1;
    }
    (payload, index)
}

/// `_shell_token_has_expansion`.
pub(crate) fn shell_token_has_expansion(token: &str) -> bool {
    let chars: Vec<char> = token.chars().collect();
    let mut single_quoted = false;
    let mut double_quoted = false;
    let mut escaped = false;
    let mut index = 0;
    while index < chars.len() {
        let c = chars[index];
        if escaped {
            escaped = false;
            index += 1;
            continue;
        }
        if c == '\\' && !single_quoted {
            escaped = true;
            index += 1;
            continue;
        }
        if !single_quoted && !double_quoted && c == '$' && chars.get(index + 1) == Some(&'\'') {
            index += 2;
            while index < chars.len() {
                if chars[index] == '\\' && index + 1 < chars.len() {
                    index += 2;
                    continue;
                }
                if chars[index] == '\'' {
                    index += 1;
                    break;
                }
                index += 1;
            }
            continue;
        }
        if c == '\'' && !double_quoted {
            single_quoted = !single_quoted;
            index += 1;
            continue;
        }
        if c == '"' && !single_quoted {
            double_quoted = !double_quoted;
            index += 1;
            continue;
        }
        if !single_quoted && (c == '$' || c == '`') {
            return true;
        }
        index += 1;
    }
    false
}

/// `github_argument_token_has_untrusted_expansion`.
pub(crate) fn github_argument_token_has_untrusted_expansion(token: &str) -> bool {
    let chars: Vec<char> = token.chars().collect();
    let quoted = chars.len() >= 2
        && chars[0] == chars[chars.len() - 1]
        && (chars[0] == '\'' || chars[0] == '"');
    let unquoted: String = if quoted {
        chars[1..chars.len() - 1].iter().collect()
    } else {
        token.to_owned()
    };
    if github_pr_head_oid_endpoint_matches(&unquoted) {
        return false;
    }
    shell_token_has_expansion(token)
}

/// `_iter_shell_pipelines`.
pub(crate) fn iter_shell_pipelines(parts: &[String]) -> Vec<Vec<Vec<String>>> {
    let mut pipelines: Vec<Vec<Vec<String>>> = Vec::new();
    let mut pipeline: Vec<Vec<String>> = Vec::new();
    let mut segment: Vec<String> = Vec::new();
    for part in parts {
        let token = py_strip(part);
        if token.is_empty() {
            continue;
        }
        if token == "|" || token == "|&" {
            if !segment.is_empty() {
                pipeline.push(std::mem::take(&mut segment));
            }
            continue;
        }
        if SHELL_COMMAND_SEPARATORS.contains(&token) {
            if !segment.is_empty() {
                pipeline.push(std::mem::take(&mut segment));
            }
            if !pipeline.is_empty() {
                pipelines.push(std::mem::take(&mut pipeline));
            }
            continue;
        }
        segment.push(token.to_owned());
    }
    if !segment.is_empty() {
        pipeline.push(segment);
    }
    if !pipeline.is_empty() {
        pipelines.push(pipeline);
    }
    pipelines
}

/// `_shell_segment_env_index`.
pub(crate) fn shell_segment_env_index(segment: &[String]) -> Option<usize> {
    let mut index = 0;
    while index < segment.len() {
        let normalized = segment[index]
            .trim_start_matches('(')
            .trim_end_matches(')')
            .to_owned();
        if SHELL_ASSIGNMENT_PATTERN
            .is_match(&normalized)
            .unwrap_or(false)
        {
            index += 1;
            continue;
        }
        let command_name = normalized_shell_command_name(&normalized);
        if command_name == "env" {
            return Some(index);
        }
        if SHELL_COMMAND_WRAPPERS.contains(&command_name.as_str()) {
            index += 1;
            while index < segment.len() {
                let token = &segment[index];
                if !token.starts_with('-') {
                    break;
                }
                index += wrapper_option_tokens_consumed(&command_name, token);
            }
            continue;
        }
        return None;
    }
    None
}

/// `_env_split_string_payloads`.
pub(crate) fn env_split_string_payloads(parts: &[String]) -> Vec<String> {
    let mut payloads = Vec::new();
    for segment in iter_shell_command_segments(parts) {
        let Some(env_index) = shell_segment_env_index(&segment) else {
            continue;
        };
        let parsed = parse_env_wrapper(&segment[env_index + 1..], None, None);
        for expansion in parsed.split_expansions {
            if !py_strip(&expansion.payload).is_empty() {
                payloads.push(expansion.payload);
            }
        }
    }
    payloads
}

/// `_shell_command_scripts`.
pub(crate) fn shell_command_scripts(parts: &[String]) -> Vec<String> {
    let mut scripts = Vec::new();
    for segment in iter_shell_command_segments(parts) {
        let (name, index) = shell_segment_primary_command(&segment);
        let (Some(name), Some(index)) = (name, index) else {
            continue;
        };
        if !SHELL_COMMAND_STRING_INTERPRETERS.contains(&name.as_str()) {
            continue;
        }
        if let Some(payload) = shell_interpreter_command_payload(&segment, index) {
            scripts.push(payload.script_text);
        }
    }
    scripts
}

/// Convenience for callers holding raw command text.
pub(crate) fn split_parts(command_text: &str) -> Vec<String> {
    split_shell_parts(command_text)
}

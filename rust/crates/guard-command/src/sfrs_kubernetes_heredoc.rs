//! Kubernetes heredoc command detection helpers
//! (`runtime/kubernetes_heredoc_support.py`).

#![allow(dead_code)]

use crate::data_flow::{extract_command_segments, extract_input_redirects, split_top_level_pipes};
use crate::env_wrapper::parse_env_wrapper;
use crate::hook_adapter_pytext::{is_py_space, py_strip};
use crate::sfrs_kubernetes_heredoc_scan::{
    heredoc_body_and_end, is_background_separator, looks_like_heredoc_operator, parse_heredoc,
    skip_command_whitespace, starts_command_separator, wrapper_option_tokens_consumed,
};
use crate::sfrs_kubernetes_support::{
    exec_remote_tokens_after_resource, is_assignment, is_inline_interpreter_command,
    is_output_redirect_target, is_secret_volume_path, path_name_lower, py_split_whitespace,
    script_reads_sensitive_env, secret_volume_argument_value, shell_command_script,
    skip_kubectl_options, OUTPUT_REDIRECT_TOKENS, SHELL_EXECUTABLES, WRAPPER_COMMANDS,
    WRITE_ONLY_COMMANDS,
};
use crate::shell_structure::extract_command_substitutions;

const ENV_CONTROL_TOKENS: &[&str] = &["&&", "||", ";", "|", "|&", "&"];

/// One recorded heredoc: the text before the operator, the rest of the
/// operator line after the tag, and the body.
pub(crate) type Heredoc = (String, String, String);

/// `kubernetes_heredoc_secret_source`.
pub(crate) fn kubernetes_heredoc_secret_source(command: &str) -> Option<&'static str> {
    for (before, after, body) in iter_kubernetes_heredocs(command) {
        let Some(kind) = kubernetes_heredoc_remote_kind(&before, &after) else {
            continue;
        };
        if kind == "interpreter" {
            if script_reads_sensitive_env(&body) {
                return Some("Kubernetes pod environment");
            }
            continue;
        }
        if script_body_reads_secret_volume(&body) {
            return Some("Kubernetes secret volume");
        }
        if script_reads_sensitive_env(&body) {
            return Some("Kubernetes pod environment");
        }
    }
    None
}

/// `_interpreter_reads_stdin`.
pub(crate) fn interpreter_reads_stdin(args: &[String]) -> bool {
    for token in args {
        if token == "--" {
            continue;
        }
        if token == "-c"
            || token == "-e"
            || ((token.starts_with("-c") || token.starts_with("-e")) && token.chars().count() > 2)
        {
            return false;
        }
        if token == "-" {
            return true;
        }
        if token.starts_with('-') {
            continue;
        }
        return false;
    }
    false
}

pub(crate) fn slice(chars: &[char], start: usize, end: usize) -> String {
    let end = end.min(chars.len());
    if start >= end {
        return String::new();
    }
    chars[start..end].iter().collect()
}

pub(crate) fn starts_with_at(chars: &[char], index: usize, needle: &str) -> bool {
    let mut cursor = index;
    for expected in needle.chars() {
        if chars.get(cursor) != Some(&expected) {
            return false;
        }
        cursor += 1;
    }
    true
}

/// `_iter_kubernetes_heredocs`.
pub(crate) fn iter_kubernetes_heredocs(command: &str) -> Vec<Heredoc> {
    let chars: Vec<char> = command.chars().collect();
    let mut heredocs: Vec<Heredoc> = Vec::new();
    let mut command_start = 0usize;
    let mut index = 0usize;
    let mut quote: Option<char> = None;
    let mut in_backtick = false;
    let mut subshell_depth = 0usize;
    while index < chars.len() {
        let ch = chars[index];
        if ch == '\\' {
            index += 2;
            continue;
        }
        if ch == '`' && quote != Some('\'') {
            in_backtick = !in_backtick;
            index += 1;
            continue;
        }
        if in_backtick {
            index += 1;
            continue;
        }
        if quote == Some('\'') {
            if ch == '\'' {
                quote = None;
            }
            index += 1;
            continue;
        }
        if ch == '\'' && quote.is_none() {
            quote = Some('\'');
            index += 1;
            continue;
        }
        if ch == '"' {
            if quote == Some('"') {
                quote = None;
            } else if quote.is_none() {
                quote = Some('"');
            }
            index += 1;
            continue;
        }
        if quote != Some('\'') && starts_with_at(&chars, index, "$(") {
            subshell_depth += 1;
            index += 2;
            continue;
        }
        if quote.is_none() && ch == '(' && subshell_depth > 0 {
            subshell_depth += 1;
            index += 1;
            continue;
        }
        if quote.is_none() && ch == ')' && subshell_depth > 0 {
            subshell_depth -= 1;
            index += 1;
            continue;
        }
        if quote.is_none() && subshell_depth == 0 {
            if starts_command_separator(&chars, index) {
                index += 2;
                command_start = skip_command_whitespace(&chars, index);
                continue;
            }
            if ch == ';' || ch == '\n' || is_background_separator(&chars, index) {
                index += 1;
                command_start = skip_command_whitespace(&chars, index);
                continue;
            }
            if looks_like_heredoc_operator(&chars, index) {
                if let Some((tag, after_tag_start, body_start, line_end)) =
                    parse_heredoc(&chars, index)
                {
                    if let Some((body, next_index)) = heredoc_body_and_end(&chars, &tag, body_start)
                    {
                        let before = slice(&chars, command_start, index);
                        let after = slice(&chars, after_tag_start, line_end);
                        heredocs.push((
                            py_strip(&before).to_owned(),
                            py_strip(&after).to_owned(),
                            body,
                        ));
                        command_start = skip_command_whitespace(&chars, next_index);
                        index = command_start;
                        continue;
                    }
                }
            }
        }
        index += 1;
    }
    heredocs
}

/// `_kubernetes_heredoc_remote_kind`.
pub(crate) fn kubernetes_heredoc_remote_kind(before: &str, after: &str) -> Option<&'static str> {
    if let Some(kind) = kubernetes_remote_kind_from_command(&last_pipe_segment(before)) {
        return Some(kind);
    }
    let trimmed = after.trim_start_matches(is_py_space);
    let rest = trimmed.strip_prefix('|')?;
    pipe_segments(rest)
        .iter()
        .find_map(|segment| kubernetes_remote_kind_from_command(segment))
}

/// `_kubernetes_remote_kind_from_command`.
pub(crate) fn kubernetes_remote_kind_from_command(command: &str) -> Option<&'static str> {
    let (name, kube_tokens) = unwrap_heredoc_remote_command(&shell_tokens(command));
    if !matches!(name.as_deref(), Some("kubectl" | "oc")) || kube_tokens.is_empty() {
        return None;
    }
    let remote = kubernetes_exec_remote_tokens(&kube_tokens);
    if remote.is_empty() {
        return None;
    }
    let (name, args) = unwrap_heredoc_remote_command(&remote);
    let name = name?;
    if SHELL_EXECUTABLES.contains(&name.as_str()) && shell_reads_stdin(&args) {
        return Some("shell");
    }
    if is_inline_interpreter_command(&name) && interpreter_reads_stdin(&args) {
        return Some("interpreter");
    }
    None
}

/// `_kubernetes_exec_remote_tokens`.
pub(crate) fn kubernetes_exec_remote_tokens(tokens: &[String]) -> Vec<String> {
    let subcommand_index = skip_kubectl_options(tokens, 0);
    if subcommand_index >= tokens.len() {
        return Vec::new();
    }
    let verb = tokens[subcommand_index].to_lowercase();
    if verb != "exec" && verb != "rsh" {
        return Vec::new();
    }
    exec_remote_tokens_after_resource(&tokens[subcommand_index + 1..])
}

/// `_script_body_reads_secret_volume`.
pub(crate) fn script_body_reads_secret_volume(body: &str) -> bool {
    if extract_input_redirects(body)
        .iter()
        .any(|target| is_secret_volume_path(target))
    {
        return true;
    }
    if extract_command_substitutions(body)
        .iter()
        .any(|substitution| script_body_reads_secret_volume(substitution))
    {
        return true;
    }
    extract_command_segments(body)
        .iter()
        .any(|segment| segment_reads_secret_volume(&shell_tokens(segment)))
}

/// `_segment_reads_secret_volume`.
pub(crate) fn segment_reads_secret_volume(tokens: &[String]) -> bool {
    let Some(first) = tokens.first() else {
        return false;
    };
    let name = path_name_lower(first);
    if SHELL_EXECUTABLES.contains(&name.as_str()) {
        return shell_command_script(&tokens[1..])
            .is_some_and(|script| !script.is_empty() && script_body_reads_secret_volume(&script));
    }
    if WRITE_ONLY_COMMANDS.contains(&name.as_str()) {
        return false;
    }
    let mut previous: Option<&str> = None;
    for token in &tokens[1..] {
        if OUTPUT_REDIRECT_TOKENS.contains(&token.as_str()) {
            previous = Some(token);
            continue;
        }
        let normalized = secret_volume_argument_value(token);
        if token.starts_with('-') && !token.contains('=') {
            previous = Some(token);
            continue;
        }
        if !is_secret_volume_path(&normalized) {
            previous = Some(token);
            continue;
        }
        if is_output_redirect_target(token, previous) {
            previous = Some(token);
            continue;
        }
        return true;
    }
    false
}

/// `_shell_reads_stdin`.
pub(crate) fn shell_reads_stdin(args: &[String]) -> bool {
    for token in args {
        if token == "--" {
            continue;
        }
        if token == "-s" {
            return true;
        }
        if token == "-c" || (token.starts_with('-') && token[1..].contains('c')) {
            return false;
        }
        if token.starts_with('-') {
            continue;
        }
        return token == "-";
    }
    true
}

/// `_shell_tokens` (`shlex.split`, falling back to `str.split`).
pub(crate) fn shell_tokens(command: &str) -> Vec<String> {
    crate::codex_output_py::shlex_split(command).unwrap_or_else(|| py_split_whitespace(command))
}

/// `_unwrap_heredoc_remote_command`.
pub(crate) fn unwrap_heredoc_remote_command(tokens: &[String]) -> (Option<String>, Vec<String>) {
    let mut index = 0;
    while index < tokens.len() {
        let token = tokens[index].as_str();
        if is_assignment(token) {
            index += 1;
            continue;
        }
        let name = path_name_lower(token);
        if !WRAPPER_COMMANDS.contains(&name.as_str()) {
            return (Some(name), tokens[index + 1..].to_vec());
        }
        if name == "env" {
            let parsed = parse_env_wrapper(&tokens[index + 1..], None, None);
            let control_or_empty = parsed
                .executable_argv
                .first()
                .is_none_or(|first| ENV_CONTROL_TOKENS.contains(&first.as_str()));
            if parsed.complete && control_or_empty {
                return (Some(name), tokens[index + 1..].to_vec());
            }
            if !parsed.complete {
                return (None, Vec::new());
            }
            if !parsed.split_expansions.is_empty() {
                return unwrap_heredoc_remote_command(&parsed.executable_argv);
            }
            let Some(command_index) = parsed.command_index else {
                return (None, Vec::new());
            };
            index += command_index + 1;
            continue;
        }
        index += 1;
        while index < tokens.len() {
            let current = tokens[index].as_str();
            if current == "--" {
                index += 1;
                break;
            }
            if is_assignment(current) {
                index += 1;
                continue;
            }
            if !current.starts_with('-') {
                break;
            }
            index += wrapper_option_tokens_consumed(&name, current);
        }
    }
    (None, Vec::new())
}

/// `_last_pipe_segment`.
pub(crate) fn last_pipe_segment(command: &str) -> String {
    pipe_segments(command)
        .pop()
        .unwrap_or_else(|| py_strip(command).to_owned())
}

/// `_pipe_segments`.
pub(crate) fn pipe_segments(command: &str) -> Vec<String> {
    let stripped = py_strip(command);
    if stripped.is_empty() {
        return Vec::new();
    }
    let segments: Vec<String> = split_top_level_pipes(stripped)
        .iter()
        .map(|segment| py_strip(segment).to_owned())
        .filter(|segment| !segment.is_empty())
        .collect();
    if segments.is_empty() {
        vec![stripped.to_owned()]
    } else {
        segments
    }
}

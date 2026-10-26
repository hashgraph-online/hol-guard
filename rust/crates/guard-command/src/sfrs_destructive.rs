//! Port of `secret_file_request_services.destructive_shell_detection`:
//! destructive shell, Git and redirection detection, and recursive credential
//! exfiltration over nested shell payloads.

// Consumed by the dispatcher slice.
#![allow(dead_code)]

use std::path::{Path, PathBuf};

use crate::codex_output_py::{is_py_space, py_strip};
use crate::sfrs_constants::{DESTRUCTIVE_SHELL_COMMANDS, SAFE_SHELL_REDIRECT_TARGETS};
use crate::sfrs_credential_exfil::{
    local_shell_script_payloads, shell_segments_contain_credential_exfiltration,
    text_contains_credential_exfiltration,
};
use crate::sfrs_interpreter_heredoc::{normalized_redirect_target, shell_heredoc_payloads};
use crate::sfrs_patterns::{DESTRUCTIVE_GIT_SUBCOMMANDS, GIT_GLOBAL_OPTIONS_WITH_VALUE};
use crate::sfrs_read_only_filters::split_attached_redirection_token;
use crate::sfrs_sensitive_pipeline::shell_pipeline_reads_sensitive_path_to_network;
use crate::sfrs_shell_tokens::{
    iter_shell_command_segments, normalized_shell_command_name, shell_segment_primary_command,
    split_shell_parts,
};
use crate::sfrs_substitution::{
    env_split_string_payloads, shell_command_scripts, shell_command_substitution_payloads,
};

const FIND_VALUE_TAKING_PREDICATES: &[&str] = &[
    "-name",
    "-iname",
    "-path",
    "-ipath",
    "-wholename",
    "-iwholename",
    "-regex",
    "-iregex",
    "-lname",
    "-ilname",
];
const BARE_REDIRECT_OPERATORS: &[&str] = &[">", ">>", ">|", "1>", "1>>", "1>|", "2>", "2>>", "2>|"];

/// `_contains_shell_credential_exfiltration` (start with `depth = 0` and no
/// visited script paths).
pub(crate) fn contains_shell_credential_exfiltration(
    command_text: &str,
    cwd: Option<&Path>,
    home_dir: Option<&Path>,
    allowed_roots: Option<&[PathBuf]>,
    depth: usize,
    visited_script_paths: &[String],
) -> bool {
    if depth > 4 {
        return false;
    }
    let normalized = py_strip(command_text);
    if normalized.is_empty() {
        return false;
    }
    let parts = split_shell_parts(normalized);
    if parts.is_empty() {
        return false;
    }
    if shell_pipeline_reads_sensitive_path_to_network(&parts, cwd, home_dir)
        || shell_segments_contain_credential_exfiltration(&parts)
        || shell_heredoc_payloads(normalized)
            .iter()
            .any(|payload| text_contains_credential_exfiltration(payload))
    {
        return true;
    }
    let nested = |text: &str| {
        contains_shell_credential_exfiltration(
            text,
            cwd,
            home_dir,
            allowed_roots,
            depth + 1,
            visited_script_paths,
        )
    };
    if env_split_string_payloads(&parts)
        .iter()
        .any(|text| nested(text))
        || shell_command_substitution_payloads(normalized)
            .iter()
            .any(|text| nested(text))
        || shell_command_scripts(&parts)
            .iter()
            .any(|text| nested(text))
    {
        return true;
    }
    local_shell_script_payloads(&parts, cwd, home_dir, allowed_roots, visited_script_paths)
        .into_iter()
        .any(|(script_text, script_cwd, script_path)| {
            let mut visited = visited_script_paths.to_vec();
            if !visited.contains(&script_path) {
                visited.push(script_path);
            }
            contains_shell_credential_exfiltration(
                &script_text,
                script_cwd.as_deref(),
                home_dir,
                allowed_roots,
                depth + 1,
                &visited,
            )
        })
}

/// `_find_command_uses_delete`.
pub(crate) fn find_command_uses_delete(parts: &[String]) -> bool {
    iter_shell_command_segments(parts).iter().any(|segment| {
        match shell_segment_primary_command(segment) {
            (Some(name), Some(index)) if name == "find" => {
                find_segment_uses_delete(&segment[index + 1..])
            }
            _ => false,
        }
    })
}

/// `_find_segment_uses_delete`.
pub(crate) fn find_segment_uses_delete(segment_args: &[String]) -> bool {
    let mut index = 0;
    while index < segment_args.len() {
        let token = segment_args[index].as_str();
        if matches!(token, "-exec" | "-execdir" | "-ok" | "-okdir") {
            index += 1;
            if index < segment_args.len()
                && DESTRUCTIVE_SHELL_COMMANDS
                    .contains(&normalized_shell_command_name(&segment_args[index]).as_str())
            {
                return true;
            }
            while index < segment_args.len() && !matches!(segment_args[index].as_str(), ";" | "+") {
                index += 1;
            }
            if index < segment_args.len() {
                index += 1;
            }
            continue;
        }
        if FIND_VALUE_TAKING_PREDICATES.contains(&token) && index + 1 < segment_args.len() {
            index += 2;
            continue;
        }
        if token == "-delete" {
            return true;
        }
        index += 1;
    }
    false
}

/// `_contains_destructive_git_command`.
pub(crate) fn contains_destructive_git_command(parts: &[String]) -> bool {
    iter_shell_command_segments(parts).iter().any(|segment| {
        match shell_segment_primary_command(segment) {
            (Some(name), Some(index)) if name == "git" => {
                segment_uses_destructive_git_command(&segment[index + 1..])
            }
            _ => false,
        }
    })
}

/// `_segment_uses_destructive_git_command`.
pub(crate) fn segment_uses_destructive_git_command(segment_args: &[String]) -> bool {
    let mut index = 0;
    while index < segment_args.len() {
        let token = segment_args[index].as_str();
        if token == "--" {
            index += 1;
            continue;
        }
        if matches!(token, "-h" | "--help" | "--version") {
            return false;
        }
        if GIT_GLOBAL_OPTIONS_WITH_VALUE.contains(&token) && index + 1 < segment_args.len() {
            index += 2;
            continue;
        }
        if GIT_GLOBAL_OPTIONS_WITH_VALUE
            .iter()
            .filter(|option| option.starts_with("--"))
            .any(|option| {
                token
                    .strip_prefix(option)
                    .is_some_and(|rest| rest.starts_with('='))
            })
        {
            index += 1;
            continue;
        }
        if token.starts_with('-') {
            index += 1;
            continue;
        }
        let normalized = py_strip(token).to_lowercase();
        if normalized == "help" {
            return false;
        }
        if normalized == "clean" {
            return !git_clean_is_preview(&segment_args[index + 1..]);
        }
        return DESTRUCTIVE_GIT_SUBCOMMANDS.contains(&normalized.as_str());
    }
    false
}

/// `_git_clean_is_preview`.
pub(crate) fn git_clean_is_preview(arguments: &[String]) -> bool {
    let mut index = 0;
    while index < arguments.len() {
        let normalized = py_strip(&arguments[index]).to_lowercase();
        let option_name = normalized.split('=').next().unwrap_or_default();
        if matches!(option_name, "-e" | "--exclude") && !normalized.contains('=') {
            index += 2;
            continue;
        }
        if normalized == "--dry-run" {
            return true;
        }
        if let Some(cluster) = normalized
            .strip_prefix('-')
            .filter(|_| !normalized.starts_with("--"))
        {
            for flag in cluster.chars() {
                if flag == 'e' {
                    break;
                }
                if flag == 'n' {
                    return true;
                }
            }
        }
        index += 1;
    }
    false
}

/// `_contains_mutating_shell_redirection`.
pub(crate) fn contains_mutating_shell_redirection(parts: &[String]) -> bool {
    let mut index = 0;
    while index < parts.len() {
        let token = py_strip(&parts[index]);
        if token.is_empty() {
            index += 1;
            continue;
        }
        // The stderr-only safe-target case is subsumed by the general one.
        let mut target: Option<String> = None;
        if BARE_REDIRECT_OPERATORS.contains(&token) {
            if token.ends_with('>') && index + 2 < parts.len() && parts[index + 1] == "|" {
                target = Some(parts[index + 2].clone());
                index += 3;
            } else if index + 1 < parts.len() {
                target = Some(parts[index + 1].clone());
                index += 2;
            } else {
                index += 1;
            }
        } else {
            let Some((prefix, _fd, _op, attached_target)) = split_attached_redirection_token(token)
            else {
                index += 1;
                continue;
            };
            if prefix.ends_with('=') {
                index += 1;
                continue;
            }
            if !attached_target.is_empty() {
                target = Some(attached_target);
                index += 1;
            } else if index + 1 < parts.len() {
                target = Some(parts[index + 1].clone());
                index += 2;
            } else {
                index += 1;
            }
        }
        let Some(target) = target else {
            continue;
        };
        let normalized_target = normalized_redirect_target(&target).to_lowercase();
        if SAFE_SHELL_REDIRECT_TARGETS.contains(&normalized_target.as_str())
            || normalized_target.starts_with('&')
        {
            continue;
        }
        return true;
    }
    false
}

/// `_shell_command_names`.
pub(crate) fn shell_command_names(command_text: &str) -> Vec<String> {
    shell_command_names_from_parts(&split_shell_parts(command_text))
}

/// `_shell_command_names_from_parts`.
pub(crate) fn shell_command_names_from_parts(parts: &[String]) -> Vec<String> {
    iter_shell_command_segments(parts)
        .iter()
        .filter_map(|segment| shell_segment_primary_command(segment).0)
        .collect()
}

/// `_redacted_shell_text_for_command_names`: every complete quoted run
/// becomes `Q`.
pub(crate) fn redacted_shell_text_for_command_names(command_text: &str) -> String {
    let mut result = String::with_capacity(command_text.len());
    let mut rest = command_text;
    while let Some(start) = rest.find(['\'', '"']) {
        let quote = rest[start..].chars().next().unwrap_or('\'');
        let after = &rest[start + 1..];
        match after.find(quote) {
            Some(end) => {
                result.push_str(&rest[..start]);
                result.push('Q');
                rest = &after[end + 1..];
            }
            None => {
                result.push_str(&rest[..=start]);
                rest = after;
            }
        }
    }
    result.push_str(rest);
    result
}

/// `_shell_text_for_redirection_scan`: hide quoted arguments while retaining
/// quoted redirect targets.
pub(crate) fn shell_text_for_redirection_scan(command_text: &str) -> String {
    let chars: Vec<char> = command_text.chars().collect();
    let mut result = String::with_capacity(command_text.len());
    let mut index = 0;
    while index < chars.len() {
        let quote = chars[index];
        if !matches!(quote, '\'' | '"') {
            result.push(quote);
            index += 1;
            continue;
        }
        let preserve = chars[..index]
            .iter()
            .rev()
            .find(|c| !is_py_space(**c))
            .is_some_and(|c| *c == '>');
        result.push(if preserve { quote } else { 'Q' });
        index += 1;
        while index < chars.len() {
            let character = chars[index];
            if quote == '"' && character == '\\' && index + 1 < chars.len() {
                if preserve {
                    result.push(character);
                    result.push(chars[index + 1]);
                }
                index += 2;
                continue;
            }
            if character == quote {
                if preserve {
                    result.push(character);
                }
                index += 1;
                break;
            }
            if preserve {
                result.push(character);
            }
            index += 1;
        }
    }
    result
}

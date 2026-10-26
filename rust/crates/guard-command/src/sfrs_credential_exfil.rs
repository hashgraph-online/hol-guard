//! Credential exfiltration and local script inspection
//! (`credential_exfiltration.py`).

// Consumed by the later classifier slices.
#![allow(dead_code)]

use std::path::{Path, PathBuf};

use crate::codex_output_py::py_strip;
use crate::runtime_read_paths::{
    read_small_runtime_text_file, resolved_runtime_path, runtime_read_roots,
};
use crate::sfrs_constants::SHELL_SCRIPT_INTERPRETER_COMMANDS;
use crate::sfrs_patterns::{
    BROAD_CREDENTIAL_EXFILTRATION_SKIP_COMMANDS, CURL_AT_FILE_FLAGS_WITH_VALUE,
    CURL_CONFIG_FLAGS_WITH_VALUE, CURL_CREDENTIAL_EXFILTRATION_FLAGS_WITH_VALUE,
    CURL_DATA_URLENCODE_FLAGS_WITH_VALUE, CURL_DIRECT_FILE_FLAGS_WITH_VALUE,
    CURL_FORM_FLAGS_WITH_VALUE, CURL_VARIABLE_FLAGS_WITH_VALUE, SHELL_ASSIGNMENT_PATTERN,
    WGET_CREDENTIAL_EXFILTRATION_FLAGS_WITH_VALUE,
};
use crate::sfrs_request_data::{
    SECRET_EXFILTRATION_DESTINATION_PATTERN, SECRET_EXFILTRATION_NETWORK_PATTERN,
    SECRET_EXFILTRATION_SECRET_PATTERN,
};
use crate::sfrs_shell_tokens::{
    iter_shell_command_segments, shell_command_token_without_attached_redirection,
    shell_segment_primary_command,
};
use crate::sfrs_upload_arguments::short_flag_takes_value;

/// `(script_text, script_cwd, normalized_script_path)`.
pub(crate) type ScriptPayload = (String, Option<PathBuf>, String);

/// `Path.parent`: the root's parent is itself.
pub(crate) fn py_parent(path: &Path) -> PathBuf {
    path.parent()
        .map_or_else(|| path.to_path_buf(), Path::to_path_buf)
}

/// `allowed_roots or _runtime_read_roots(cwd, home_dir)`.
pub(crate) fn effective_read_roots(
    allowed_roots: Option<&[PathBuf]>,
    cwd: Option<&Path>,
    home_dir: Option<&Path>,
) -> Vec<PathBuf> {
    match allowed_roots {
        Some(roots) if !roots.is_empty() => roots.to_vec(),
        _ => runtime_read_roots(cwd, home_dir),
    }
}

fn is_assignment(token: &str) -> bool {
    SHELL_ASSIGNMENT_PATTERN.is_match(token).unwrap_or(false)
}

fn destination_hit(token: &str) -> bool {
    SECRET_EXFILTRATION_DESTINATION_PATTERN
        .is_match(token)
        .unwrap_or(false)
}

/// `_text_contains_credential_exfiltration` (`github_pr_body_safety.py`).
pub(crate) fn text_contains_credential_exfiltration(text: &str) -> bool {
    SECRET_EXFILTRATION_SECRET_PATTERN
        .is_match(text)
        .unwrap_or(false)
        && SECRET_EXFILTRATION_NETWORK_PATTERN
            .is_match(text)
            .unwrap_or(false)
        && destination_hit(text)
}

/// `_shell_segments_contain_credential_exfiltration`.
pub(crate) fn shell_segments_contain_credential_exfiltration(parts: &[String]) -> bool {
    for segment in iter_shell_command_segments(parts) {
        let (Some(command_name), Some(command_index)) = shell_segment_primary_command(&segment)
        else {
            continue;
        };
        if BROAD_CREDENTIAL_EXFILTRATION_SKIP_COMMANDS.contains(&command_name.as_str())
            && command_name != "curl"
            && command_name != "wget"
        {
            continue;
        }
        let segment_text =
            shell_segment_credential_exfiltration_text(&segment, &command_name, command_index);
        if !segment_text.is_empty() && text_contains_credential_exfiltration(&segment_text) {
            return true;
        }
    }
    false
}

/// `_shell_segment_credential_exfiltration_text`.
pub(crate) fn shell_segment_credential_exfiltration_text(
    segment: &[String],
    command_name: &str,
    command_index: usize,
) -> String {
    match command_name {
        "curl" => curl_segment_credential_exfiltration_text(segment, command_index),
        "wget" => wget_segment_credential_exfiltration_text(segment, command_index),
        _ => segment[command_index..].join(" "),
    }
}

fn leading_surface_tokens(segment: &[String], command_index: usize) -> Vec<String> {
    let mut surface: Vec<String> = segment[..command_index]
        .iter()
        .filter(|token| is_assignment(&shell_command_token_without_attached_redirection(token)))
        .cloned()
        .collect();
    surface.push(segment[command_index].clone());
    surface
}

fn push_flag_and_value(surface: &mut Vec<String>, segment: &[String], index: usize) {
    surface.push(segment[index].clone());
    if let Some(value) = segment.get(index + 1) {
        surface.push(value.clone());
    }
}

/// `_curl_segment_credential_exfiltration_text`.
pub(crate) fn curl_segment_credential_exfiltration_text(
    segment: &[String],
    command_index: usize,
) -> String {
    let mut surface = leading_surface_tokens(segment, command_index);
    let mut index = command_index + 1;
    while index < segment.len() {
        let token = segment[index].as_str();
        if token == "--" {
            surface.extend(network_destination_tokens(&segment[index + 1..]));
            break;
        }
        let consumed = curl_clustered_short_flag_tokens_consumed(segment, index);
        if consumed > 1 {
            push_flag_and_value(&mut surface, segment, index);
            index += consumed;
            continue;
        }
        let mut token_chars = token.chars();
        if let (Some('-'), Some(flag), None) =
            (token_chars.next(), token_chars.next(), token_chars.next())
        {
            if short_flag_takes_value(flag) {
                push_flag_and_value(&mut surface, segment, index);
                index += 2;
                continue;
            }
        }
        if token.starts_with("--") && token.contains('=') {
            surface.push(token.to_owned());
            index += 1;
            continue;
        }
        let takes_value = [
            CURL_CONFIG_FLAGS_WITH_VALUE,
            CURL_AT_FILE_FLAGS_WITH_VALUE,
            CURL_DATA_URLENCODE_FLAGS_WITH_VALUE,
            CURL_FORM_FLAGS_WITH_VALUE,
            CURL_DIRECT_FILE_FLAGS_WITH_VALUE,
            CURL_VARIABLE_FLAGS_WITH_VALUE,
            CURL_CREDENTIAL_EXFILTRATION_FLAGS_WITH_VALUE,
        ]
        .iter()
        .any(|flags| flags.contains(&token))
            || token == "-H"
            || token == "-X";
        if takes_value {
            push_flag_and_value(&mut surface, segment, index);
            index += 2;
            continue;
        }
        if !token.starts_with('-') {
            if destination_hit(token) {
                surface.push(token.to_owned());
            }
            index += 1;
            continue;
        }
        surface.push(token.to_owned());
        index += 1;
    }
    surface.join(" ")
}

/// `_wget_segment_credential_exfiltration_text`.
pub(crate) fn wget_segment_credential_exfiltration_text(
    segment: &[String],
    command_index: usize,
) -> String {
    let mut surface = leading_surface_tokens(segment, command_index);
    let mut index = command_index + 1;
    while index < segment.len() {
        let token = segment[index].as_str();
        if token == "--" {
            surface.extend(network_destination_tokens(&segment[index + 1..]));
            break;
        }
        if WGET_CREDENTIAL_EXFILTRATION_FLAGS_WITH_VALUE.contains(&token) {
            push_flag_and_value(&mut surface, segment, index);
            index += 2;
            continue;
        }
        if WGET_CREDENTIAL_EXFILTRATION_FLAGS_WITH_VALUE
            .iter()
            .filter(|flag| flag.starts_with("--"))
            .any(|flag| {
                token
                    .strip_prefix(*flag)
                    .is_some_and(|rest| rest.starts_with('='))
            })
        {
            surface.push(token.to_owned());
            index += 1;
            continue;
        }
        if !token.starts_with('-') {
            if destination_hit(token) {
                surface.push(token.to_owned());
            }
            index += 1;
            continue;
        }
        surface.push(token.to_owned());
        index += 1;
    }
    surface.join(" ")
}

/// `_network_destination_tokens`.
pub(crate) fn network_destination_tokens(tokens: &[String]) -> Vec<String> {
    tokens
        .iter()
        .filter(|token| destination_hit(token))
        .cloned()
        .collect()
}

/// `_curl_clustered_short_flag_tokens_consumed`.
pub(crate) fn curl_clustered_short_flag_tokens_consumed(
    segment_args: &[String],
    index: usize,
) -> usize {
    let token = segment_args[index].as_str();
    if !token.starts_with('-') || token.starts_with("--") || token.chars().count() <= 2 {
        return 1;
    }
    let cluster: Vec<char> = token.chars().skip(1).collect();
    for (flag_index, flag) in cluster.iter().enumerate() {
        if !short_flag_takes_value(*flag) {
            continue;
        }
        if flag_index + 1 < cluster.len() {
            return 1;
        }
        return if index + 1 < segment_args.len() { 2 } else { 1 };
    }
    1
}

/// `_local_shell_script_payloads`.
pub(crate) fn local_shell_script_payloads(
    parts: &[String],
    cwd: Option<&Path>,
    home_dir: Option<&Path>,
    allowed_roots: Option<&[PathBuf]>,
    visited_script_paths: &[String],
) -> Vec<ScriptPayload> {
    let mut payloads: Vec<ScriptPayload> = Vec::new();
    let read_roots = effective_read_roots(allowed_roots, cwd, home_dir);
    for segment in iter_shell_command_segments(parts) {
        let (command_name, command_index) = shell_segment_primary_command(&segment);
        let Some(command_index) = command_index else {
            continue;
        };
        let Some(script_path) =
            shell_script_path_for_segment(&segment, command_name.as_deref(), command_index)
        else {
            continue;
        };
        let Some(script_file) =
            resolved_runtime_path(&script_path, cwd, home_dir, Some(&read_roots))
        else {
            continue;
        };
        let normalized = script_file.to_string_lossy().into_owned();
        if visited_script_paths.contains(&normalized) {
            continue;
        }
        let Some(script_text) = read_small_runtime_text_file(&script_file, &read_roots) else {
            continue;
        };
        payloads.push((script_text, Some(py_parent(&script_file)), normalized));
    }
    payloads
}

/// `_shell_script_path_for_segment`.
pub(crate) fn shell_script_path_for_segment(
    segment: &[String],
    command_name: Option<&str>,
    command_index: usize,
) -> Option<String> {
    if command_name.is_some_and(|name| SHELL_SCRIPT_INTERPRETER_COMMANDS.contains(&name)) {
        return shell_script_path_from_segment(&segment[command_index + 1..]);
    }
    let command_token = py_strip(&segment[command_index]);
    if command_token.is_empty() || command_token.starts_with('-') || is_assignment(command_token) {
        return None;
    }
    if !is_explicit_shell_script_path_token(command_token) {
        return None;
    }
    Some(command_token.to_owned())
}

/// `_shell_script_path_from_segment`.
pub(crate) fn shell_script_path_from_segment(segment_args: &[String]) -> Option<String> {
    let mut index = 0;
    while index < segment_args.len() {
        let token = py_strip(&segment_args[index]);
        if token.is_empty() {
            index += 1;
            continue;
        }
        if token == "--" {
            index += 1;
            break;
        }
        if is_assignment(token) {
            index += 1;
            continue;
        }
        if token == "-s" {
            return None;
        }
        if token.starts_with('-') && !token.starts_with("--") && token[1..].contains('c') {
            return None;
        }
        if !token.starts_with('-') && !token.starts_with('+') {
            return Some(token.to_owned());
        }
        if token == "-c" || token == "--command" || token.starts_with("-c") {
            return None;
        }
        if token.starts_with("--command=") {
            return None;
        }
        if matches!(
            token,
            "-O" | "-o" | "+O" | "+o" | "--rcfile" | "--init-file"
        ) {
            index += 2;
            continue;
        }
        if token.starts_with("--rcfile=") || token.starts_with("--init-file=") {
            index += 1;
            continue;
        }
        index += 1;
    }
    while index < segment_args.len() {
        let token = py_strip(&segment_args[index]);
        if !token.is_empty() {
            return Some(token.to_owned());
        }
        index += 1;
    }
    None
}

/// `_is_explicit_shell_script_path_token`.
pub(crate) fn is_explicit_shell_script_path_token(token: &str) -> bool {
    let normalized = py_strip(token);
    if normalized.is_empty() {
        return false;
    }
    normalized.starts_with(['.', '/', '~']) || normalized.contains('/')
}

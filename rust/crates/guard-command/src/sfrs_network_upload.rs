//! Network upload and stdin source detection (`network_upload_detection.py`).

// Consumed by the later classifier slices.
#![allow(dead_code)]

use std::path::{Path, PathBuf};

use crate::runtime_read_paths::{
    read_small_runtime_text_file, resolved_runtime_path, MAX_DECODED_PAYLOAD_BYTES,
};
use crate::sfrs_constants::SAFE_SHELL_REDIRECT_TARGETS;
use crate::sfrs_credential_exfil::{
    curl_clustered_short_flag_tokens_consumed, effective_read_roots, py_parent,
};
use crate::sfrs_patterns::{
    CURL_AT_FILE_FLAGS_WITH_VALUE, CURL_CONFIG_FLAGS_WITH_VALUE,
    CURL_DATA_URLENCODE_FLAGS_WITH_VALUE, CURL_DIRECT_FILE_FLAGS_WITH_VALUE,
    CURL_EXPAND_FLAGS_WITH_VALUE, CURL_FORM_FLAGS_WITH_VALUE, CURL_VARIABLE_FLAGS_WITH_VALUE,
};
use crate::sfrs_shell_tokens::{
    iter_shell_command_segments, shell_command_token_without_attached_redirection,
    shell_segment_primary_command, split_shell_parts, token_is_heredoc_operator,
};
use crate::sfrs_upload_arguments::{
    curl_clustered_short_flag_value, curl_config_arguments, curl_upload_value_uses_local_file,
    curl_variable_value_uses_local_file, strip_cli_value, wget_segment_uses_file_upload,
};

/// A stdin config payload: its text and the directory its relative paths use.
pub(crate) type StdinPayload = (String, Option<PathBuf>);

/// The keyword context `_curl_segment_uses_file_upload` threads through.
#[derive(Clone, Copy)]
pub(crate) struct UploadScan<'a> {
    pub(crate) cwd: Option<&'a Path>,
    pub(crate) home_dir: Option<&'a Path>,
    pub(crate) allowed_roots: Option<&'a [PathBuf]>,
    pub(crate) visited_config_paths: &'a [String],
    pub(crate) stdin_config_payloads: &'a [StdinPayload],
    pub(crate) stdin_uses_local_file: bool,
}

impl<'a> UploadScan<'a> {
    pub(crate) fn new(cwd: Option<&'a Path>, home_dir: Option<&'a Path>) -> Self {
        Self {
            cwd,
            home_dir,
            allowed_roots: None,
            visited_config_paths: &[],
            stdin_config_payloads: &[],
            stdin_uses_local_file: false,
        }
    }
}

fn next_value(args: &[String], index: usize) -> &str {
    args.get(index + 1).map_or("", String::as_str)
}

/// `_segment_uses_network_file_upload`.
pub(crate) fn segment_uses_network_file_upload(
    segment: &[String],
    cwd: Option<&Path>,
    home_dir: Option<&Path>,
    allowed_roots: Option<&[PathBuf]>,
    stdin_uses_local_file: bool,
) -> bool {
    let (Some(command_name), Some(command_index)) = shell_segment_primary_command(segment) else {
        return false;
    };
    let segment_args = &segment[command_index + 1..];
    match command_name.as_str() {
        "curl" => {
            let mut scan = UploadScan::new(cwd, home_dir);
            scan.allowed_roots = allowed_roots;
            scan.stdin_uses_local_file = stdin_uses_local_file;
            curl_segment_uses_file_upload(segment_args, &scan)
        }
        "wget" => wget_segment_uses_file_upload(segment_args, stdin_uses_local_file),
        _ => false,
    }
}

const ATTACHED_UPLOAD_FLAGS: &[&str] = &[
    "--data",
    "--data-ascii",
    "--data-binary",
    "--json",
    "--url-query",
    "--data-urlencode",
    "--data-raw",
    "--form",
    "--upload-file",
];

/// `_curl_segment_uses_file_upload`.
pub(crate) fn curl_segment_uses_file_upload(
    segment_args: &[String],
    scan: &UploadScan<'_>,
) -> bool {
    let mut index = 0;
    let mut saw_variable_file_input = false;
    let mut saw_variable_expansion = false;
    let stdin = scan.stdin_uses_local_file;
    while index < segment_args.len() {
        let token = segment_args[index].as_str();
        if token == "--" {
            break;
        }
        if CURL_CONFIG_FLAGS_WITH_VALUE.contains(&token) {
            if curl_config_uses_file_upload(next_value(segment_args, index), scan) {
                return true;
            }
            index += 2;
            continue;
        }
        if CURL_AT_FILE_FLAGS_WITH_VALUE.contains(&token)
            || CURL_DATA_URLENCODE_FLAGS_WITH_VALUE.contains(&token)
            || CURL_FORM_FLAGS_WITH_VALUE.contains(&token)
            || CURL_DIRECT_FILE_FLAGS_WITH_VALUE.contains(&token)
        {
            if curl_upload_value_uses_local_file(token, next_value(segment_args, index), stdin) {
                return true;
            }
            index += 2;
            continue;
        }
        if CURL_VARIABLE_FLAGS_WITH_VALUE.contains(&token) {
            saw_variable_file_input = saw_variable_file_input
                || curl_variable_value_uses_local_file(next_value(segment_args, index));
            index += 2;
            continue;
        }
        if CURL_EXPAND_FLAGS_WITH_VALUE.contains(&token) {
            saw_variable_expansion = true;
            index += 2;
            continue;
        }
        if let Some(value) = token.strip_prefix("--config=") {
            if curl_config_uses_file_upload(value, scan) {
                return true;
            }
        }
        if let Some((flag, value)) = token.split_once('=') {
            if ATTACHED_UPLOAD_FLAGS.contains(&flag)
                && curl_upload_value_uses_local_file(flag, value, stdin)
            {
                return true;
            }
        }
        if let Some(value) = token.strip_prefix("--variable=") {
            saw_variable_file_input =
                saw_variable_file_input || curl_variable_value_uses_local_file(value);
            index += 1;
            continue;
        }
        if token.starts_with("--expand-") {
            saw_variable_expansion = true;
            index += 1;
            continue;
        }
        let consumed = curl_clustered_short_flag_tokens_consumed(segment_args, index);
        if let Some(value) = curl_clustered_short_flag_value(segment_args, index, 'T') {
            if curl_upload_value_uses_local_file("-T", &value, stdin) {
                return true;
            }
        }
        if let Some(value) = curl_clustered_short_flag_value(segment_args, index, 'K') {
            if curl_config_uses_file_upload(&value, scan) {
                return true;
            }
        }
        if let Some(value) = curl_clustered_short_flag_value(segment_args, index, 'F') {
            if curl_upload_value_uses_local_file("-F", &value, false) {
                return true;
            }
        }
        if let Some(value) = curl_clustered_short_flag_value(segment_args, index, 'd') {
            if curl_upload_value_uses_local_file("-d", &value, stdin) {
                return true;
            }
        }
        index += consumed;
    }
    saw_variable_file_input && saw_variable_expansion
}

fn config_value_is_stdin(value: &str) -> bool {
    strip_cli_value(&shell_command_token_without_attached_redirection(value)) == "-"
}

/// `_curl_segment_reads_config_from_stdin`.
pub(crate) fn curl_segment_reads_config_from_stdin(segment_args: &[String]) -> bool {
    let mut index = 0;
    while index < segment_args.len() {
        let token = segment_args[index].as_str();
        if token == "--" {
            return false;
        }
        if CURL_CONFIG_FLAGS_WITH_VALUE.contains(&token) {
            if config_value_is_stdin(next_value(segment_args, index)) {
                return true;
            }
            index += 2;
            continue;
        }
        if let Some(value) = token.strip_prefix("--config=") {
            if config_value_is_stdin(value) {
                return true;
            }
        }
        if let Some(value) = curl_clustered_short_flag_value(segment_args, index, 'K') {
            if config_value_is_stdin(&value) {
                return true;
            }
        }
        index += 1;
    }
    false
}

/// `_curl_inline_config_text_uses_file_upload`.
pub(crate) fn curl_inline_config_text_uses_file_upload(
    config_text: &str,
    cwd: Option<&Path>,
    home_dir: Option<&Path>,
) -> bool {
    if config_text.is_empty() || config_text.len() as u64 > MAX_DECODED_PAYLOAD_BYTES {
        return false;
    }
    let config_args = curl_config_arguments(config_text);
    if config_args.is_empty() {
        return false;
    }
    curl_segment_uses_file_upload(&config_args, &UploadScan::new(cwd, home_dir))
}

/// `_stdin_redirect_uses_local_file`.
pub(crate) fn stdin_redirect_uses_local_file(target: &str) -> bool {
    looks_like_local_stdin_source(target)
}

/// `_looks_like_local_stdin_source`.
pub(crate) fn looks_like_local_stdin_source(value: &str) -> bool {
    let stripped = strip_cli_value(value).to_lowercase();
    !stripped.is_empty()
        && stripped != "-"
        && stripped != "@-"
        && !SAFE_SHELL_REDIRECT_TARGETS.contains(&stripped.as_str())
        && !stripped.starts_with('&')
}

/// `_curl_config_uses_file_upload`.
pub(crate) fn curl_config_uses_file_upload(value: &str, scan: &UploadScan<'_>) -> bool {
    let normalized_value = shell_command_token_without_attached_redirection(value);
    if strip_cli_value(&normalized_value) == "-" {
        return scan
            .stdin_config_payloads
            .iter()
            .any(|(text, payload_cwd)| {
                curl_inline_config_text_uses_file_upload(
                    text,
                    payload_cwd.as_deref(),
                    scan.home_dir,
                )
            });
    }
    let read_roots = effective_read_roots(scan.allowed_roots, scan.cwd, scan.home_dir);
    let Some(config_file) = resolved_runtime_path(
        &normalized_value,
        scan.cwd,
        scan.home_dir,
        Some(&read_roots),
    ) else {
        return false;
    };
    let normalized_path = config_file.to_string_lossy().into_owned();
    if scan.visited_config_paths.contains(&normalized_path) {
        return false;
    }
    let Some(config_text) = read_small_runtime_text_file(&config_file, &read_roots) else {
        return false;
    };
    let config_args = curl_config_arguments(&config_text);
    if config_args.is_empty() {
        return false;
    }
    let mut visited = scan.visited_config_paths.to_vec();
    visited.push(normalized_path);
    let parent = py_parent(&config_file);
    let nested = UploadScan {
        cwd: Some(&parent),
        home_dir: scan.home_dir,
        allowed_roots: Some(&read_roots),
        visited_config_paths: &visited,
        stdin_config_payloads: scan.stdin_config_payloads,
        stdin_uses_local_file: false,
    };
    curl_segment_uses_file_upload(&config_args, &nested)
}

/// `_command_uses_curl_stdin_heredoc`.
pub(crate) fn command_uses_curl_stdin_heredoc(command_text: &str) -> bool {
    let parts = split_shell_parts(command_text);
    for segment in iter_shell_command_segments(&parts) {
        if !segment.iter().any(|token| token_is_heredoc_operator(token)) {
            continue;
        }
        let (Some(command_name), Some(command_index)) = shell_segment_primary_command(&segment)
        else {
            continue;
        };
        if command_name == "curl"
            && curl_segment_reads_config_from_stdin(&segment[command_index + 1..])
        {
            return true;
        }
    }
    false
}

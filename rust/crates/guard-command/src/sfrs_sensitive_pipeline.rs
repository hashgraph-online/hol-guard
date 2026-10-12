//! Port of `secret_file_request_services.sensitive_read_pipeline`: a pipeline
//! that reads a protected path into a network sink reading stdin.

// Consumed by the dispatcher slice.
#![allow(dead_code)]

use std::path::Path;

use crate::codex_output_py::strip_quotes;
use crate::sfrs_constants::{FIND_EXEC_ACTION_FLAGS, FIND_EXEC_TERMINATOR_TOKENS};
use crate::sfrs_gh_body_safety::shell_segment_reads_sensitive_path;
use crate::sfrs_patterns::{
    CURL_AT_FILE_FLAGS_WITH_VALUE, CURL_DIRECT_FILE_FLAGS_WITH_VALUE, CURL_FORM_FLAGS_WITH_VALUE,
    SHELL_NETWORK_SINK_COMMANDS, WGET_UPLOAD_FLAGS_WITH_VALUE,
};
use crate::sfrs_shell_tokens::shell_segment_primary_command;

const SSH_FLAGS_WITH_VALUES: &[&str] = &[
    "-b", "-c", "-D", "-E", "-e", "-F", "-I", "-i", "-J", "-L", "-l", "-m", "-O", "-o", "-p", "-R",
    "-S", "-W", "-w",
];

/// `value.split("=", 1)[1]` when `value` starts with `flag=`.
fn flag_assignment<'a>(value: &'a str, flag: &str) -> Option<&'a str> {
    value.strip_prefix(flag)?.strip_prefix('=')
}

/// `_shell_pipeline_reads_sensitive_path_to_network`.
pub(crate) fn shell_pipeline_reads_sensitive_path_to_network(
    parts: &[String],
    cwd: Option<&Path>,
    home_dir: Option<&Path>,
) -> bool {
    let mut secret_in_pipeline = false;
    let mut segment: Vec<String> = Vec::new();
    for token in parts.iter().map(String::as_str).chain([";"]) {
        if token == ";" && find_segment_expects_exec_terminator(&segment) {
            segment.push(token.to_owned());
            continue;
        }
        if matches!(token, "|" | "|&") {
            if shell_segment_network_sink_receives_pipeline(&segment) && secret_in_pipeline {
                return true;
            }
            if shell_segment_reads_sensitive_path(&segment, cwd, home_dir) {
                secret_in_pipeline = true;
            }
            segment.clear();
            continue;
        }
        if matches!(token, "&&" | "||" | ";" | "&") {
            if shell_segment_network_sink_receives_pipeline(&segment) && secret_in_pipeline {
                return true;
            }
            secret_in_pipeline = false;
            segment.clear();
            continue;
        }
        segment.push(token.to_owned());
    }
    false
}

/// `_find_segment_expects_exec_terminator`.
pub(crate) fn find_segment_expects_exec_terminator(segment: &[String]) -> bool {
    let (Some(command_name), Some(command_index)) = shell_segment_primary_command(segment) else {
        return false;
    };
    if command_name != "find" {
        return false;
    }
    let args = &segment[command_index + 1..];
    let mut index = 0;
    while index < args.len() {
        if !FIND_EXEC_ACTION_FLAGS.contains(&args[index].as_str()) {
            index += 1;
            continue;
        }
        index += 1;
        while index < args.len() && !FIND_EXEC_TERMINATOR_TOKENS.contains(&args[index].as_str()) {
            index += 1;
        }
        if index >= args.len() {
            return true;
        }
        index += 1;
    }
    false
}

/// `_shell_segment_network_sink_receives_pipeline`.
pub(crate) fn shell_segment_network_sink_receives_pipeline(segment: &[String]) -> bool {
    let (Some(command_name), Some(command_index)) = shell_segment_primary_command(segment) else {
        return false;
    };
    if !SHELL_NETWORK_SINK_COMMANDS.contains(&command_name.as_str()) {
        return false;
    }
    let args = &segment[command_index + 1..];
    match command_name.as_str() {
        "curl" => curl_segment_consumes_stdin(args),
        "wget" => wget_segment_consumes_stdin(args),
        "ssh" => ssh_segment_consumes_stdin(args),
        other => matches!(other, "nc" | "ncat" | "netcat"),
    }
}

/// `_ssh_segment_consumes_stdin`.
pub(crate) fn ssh_segment_consumes_stdin(args: &[String]) -> bool {
    if args.is_empty() {
        return false;
    }
    let mut skip_next = false;
    for arg in args {
        if skip_next {
            skip_next = false;
            continue;
        }
        if arg == "--" {
            break;
        }
        if SSH_FLAGS_WITH_VALUES.contains(&arg.as_str()) {
            skip_next = true;
            continue;
        }
        if SSH_FLAGS_WITH_VALUES
            .iter()
            .any(|flag| arg.starts_with(flag) && arg.chars().count() > flag.chars().count())
        {
            continue;
        }
        if matches!(arg.as_str(), "-n" | "-f" | "-G" | "-N" | "-Q" | "-V") {
            return false;
        }
        if ["-G", "-N", "-Q"]
            .iter()
            .any(|flag| arg.starts_with(flag) && arg.chars().count() > 2)
        {
            return false;
        }
        if let Some(cluster) = arg.strip_prefix('-').filter(|_| !arg.starts_with("--")) {
            for flag in cluster.chars() {
                if matches!(flag, 'n' | 'f' | 'N') {
                    return false;
                }
                if SSH_FLAGS_WITH_VALUES.contains(&format!("-{flag}").as_str()) {
                    break;
                }
            }
        }
    }
    true
}

/// `_curl_segment_consumes_stdin`.
pub(crate) fn curl_segment_consumes_stdin(args: &[String]) -> bool {
    let at_or_form = || {
        CURL_AT_FILE_FLAGS_WITH_VALUE
            .iter()
            .chain(CURL_FORM_FLAGS_WITH_VALUE)
    };
    for (index, arg) in args.iter().enumerate() {
        let arg = arg.as_str();
        if CURL_DIRECT_FILE_FLAGS_WITH_VALUE.contains(&arg) {
            if args
                .get(index + 1)
                .is_some_and(|next| strip_quotes(next) == "-")
            {
                return true;
            }
            continue;
        }
        if let Some(value) = CURL_DIRECT_FILE_FLAGS_WITH_VALUE
            .iter()
            .find_map(|flag| flag_assignment(arg, flag))
        {
            if strip_quotes(value) == "-" {
                return true;
            }
            continue;
        }
        if let Some(value) = arg.strip_prefix("-T").filter(|value| !value.is_empty()) {
            if strip_quotes(value) == "-" {
                return true;
            }
            continue;
        }
        if at_or_form().any(|flag| *flag == arg) {
            if args
                .get(index + 1)
                .is_some_and(|next| curl_value_consumes_stdin(next))
            {
                return true;
            }
            continue;
        }
        if let Some(value) = at_or_form().find_map(|flag| flag_assignment(arg, flag)) {
            if curl_value_consumes_stdin(value) {
                return true;
            }
            continue;
        }
        for prefix in ["-d", "-F"] {
            if let Some(value) = arg.strip_prefix(prefix).filter(|value| !value.is_empty()) {
                if curl_value_consumes_stdin(value) {
                    return true;
                }
                break;
            }
        }
    }
    false
}

/// `_curl_value_consumes_stdin`.
pub(crate) fn curl_value_consumes_stdin(value: &str) -> bool {
    let stripped = strip_quotes(value);
    stripped == "@-" || stripped.ends_with("=@-")
}

/// `_wget_segment_consumes_stdin`.
pub(crate) fn wget_segment_consumes_stdin(args: &[String]) -> bool {
    for (index, arg) in args.iter().enumerate() {
        let arg = arg.as_str();
        if WGET_UPLOAD_FLAGS_WITH_VALUE.contains(&arg) {
            if args
                .get(index + 1)
                .is_some_and(|next| strip_quotes(next) == "-")
            {
                return true;
            }
            continue;
        }
        if WGET_UPLOAD_FLAGS_WITH_VALUE
            .iter()
            .find_map(|flag| flag_assignment(arg, flag))
            .is_some_and(|value| strip_quotes(value) == "-")
        {
            return true;
        }
    }
    false
}

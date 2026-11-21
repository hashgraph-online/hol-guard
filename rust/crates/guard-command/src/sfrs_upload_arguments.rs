//! Network upload argument classification (`upload_arguments.py`): the curl
//! and wget flag-value readers that decide whether an argument names a local
//! file to send.

// Consumed by the later classifier slices.
#![allow(dead_code)]

use crate::codex_output_py::{py_splitlines, py_strip};
use crate::sfrs_patterns::{
    CURL_DATA_URLENCODE_FLAGS_WITH_VALUE, CURL_DIRECT_FILE_FLAGS_WITH_VALUE,
    CURL_FORM_FLAGS_WITH_VALUE, CURL_SHORT_FLAGS_WITH_VALUES, WGET_UPLOAD_FLAGS_WITH_VALUE,
};
use crate::sfrs_shlex::{split_with, COMMENT_LEXER};

/// `_strip_cli_value`: `value.strip().strip("'").strip('"')`.
pub(crate) fn strip_cli_value(value: &str) -> String {
    py_strip(value)
        .trim_matches('\'')
        .trim_matches('"')
        .to_owned()
}

fn next_value(segment_args: &[String], index: usize) -> &str {
    segment_args.get(index + 1).map_or("", String::as_str)
}

/// `_wget_segment_uses_file_upload`.
pub(crate) fn wget_segment_uses_file_upload(
    segment_args: &[String],
    stdin_uses_local_file: bool,
) -> bool {
    let mut index = 0;
    while index < segment_args.len() {
        let token = segment_args[index].as_str();
        if token == "--" {
            return false;
        }
        if WGET_UPLOAD_FLAGS_WITH_VALUE.contains(&token) {
            let value = next_value(segment_args, index);
            if direct_file_operand_uses_local_file(value, stdin_uses_local_file) {
                return true;
            }
            index += 2;
            continue;
        }
        for prefix in ["--body-file=", "--post-file="] {
            if let Some(value) = token.strip_prefix(prefix) {
                if direct_file_operand_uses_local_file(value, stdin_uses_local_file) {
                    return true;
                }
            }
        }
        index += 1;
    }
    false
}

/// `_curl_upload_value_uses_local_file`.
pub(crate) fn curl_upload_value_uses_local_file(
    flag: &str,
    value: &str,
    stdin_uses_local_file: bool,
) -> bool {
    let stripped_value = py_strip(value);
    if CURL_DIRECT_FILE_FLAGS_WITH_VALUE.contains(&flag) {
        return direct_file_operand_uses_local_file(stripped_value, stdin_uses_local_file);
    }
    if CURL_FORM_FLAGS_WITH_VALUE.contains(&flag) {
        return curl_form_value_uses_local_file(stripped_value);
    }
    if CURL_DATA_URLENCODE_FLAGS_WITH_VALUE.contains(&flag) {
        return curl_data_urlencode_value_uses_local_file(stripped_value);
    }
    if flag == "--data-raw" {
        return false;
    }
    value_uses_local_file(stripped_value, stdin_uses_local_file)
}

/// `_curl_form_value_uses_local_file`.
pub(crate) fn curl_form_value_uses_local_file(value: &str) -> bool {
    let stripped_value = strip_cli_value(value);
    if stripped_value.is_empty() {
        return false;
    }
    let field_value = stripped_value
        .split_once('=')
        .map_or(stripped_value.as_str(), |(_, rest)| rest);
    let mut chars = field_value.chars();
    if !matches!(chars.next(), Some('@' | '<')) {
        return false;
    }
    let rest = chars.as_str();
    let first = rest.split([';', ',']).next().unwrap_or("");
    direct_file_operand_uses_local_file(first, false)
}

/// `_curl_data_urlencode_value_uses_local_file`.
pub(crate) fn curl_data_urlencode_value_uses_local_file(value: &str) -> bool {
    let stripped_value = strip_cli_value(value);
    if stripped_value.is_empty() {
        return false;
    }
    if stripped_value.starts_with('@') {
        return value_uses_local_file(&stripped_value, false);
    }
    let Some((name, file_candidate)) = stripped_value.split_once('@') else {
        return false;
    };
    if name.contains('=') {
        return false;
    }
    direct_file_operand_uses_local_file(file_candidate, false)
}

/// `_curl_variable_value_uses_local_file`.
pub(crate) fn curl_variable_value_uses_local_file(value: &str) -> bool {
    let stripped_value = strip_cli_value(value);
    let Some((variable_name, file_candidate)) = stripped_value.split_once('@') else {
        return false;
    };
    let normalized_name = variable_name.trim_start_matches('%');
    if normalized_name.is_empty() || normalized_name.contains('=') {
        return false;
    }
    direct_file_operand_uses_local_file(file_candidate, false)
}

/// `_curl_config_arguments`.
pub(crate) fn curl_config_arguments(config_text: &str) -> Vec<String> {
    let mut arguments: Vec<String> = Vec::new();
    for raw_line in py_splitlines(config_text) {
        let stripped_line = py_strip(&raw_line);
        if stripped_line.is_empty() || stripped_line.starts_with('#') {
            continue;
        }
        let Ok(mut tokens) = split_with(COMMENT_LEXER, stripped_line) else {
            continue;
        };
        if tokens.is_empty() {
            continue;
        }
        if tokens.len() == 1
            && !tokens[0].starts_with('-')
            && tokens[0].contains(':')
            && !tokens[0].ends_with(':')
        {
            if let Some((name, value)) = tokens[0].split_once(':') {
                if !name.is_empty() && !value.is_empty() {
                    tokens = vec![name.to_owned(), value.to_owned()];
                }
            }
        }
        if tokens[0].ends_with(':') {
            tokens[0].pop();
        } else if tokens.len() >= 3 && (tokens[1] == "=" || tokens[1] == ":") {
            let first = tokens[0].clone();
            tokens.splice(0..2, [first]);
        }
        if !tokens[0].starts_with('-') {
            tokens[0] = format!("--{}", tokens[0]);
        }
        arguments.extend(tokens);
    }
    arguments
}

/// `_curl_clustered_short_flag_value`.
pub(crate) fn curl_clustered_short_flag_value(
    segment_args: &[String],
    index: usize,
    flag_character: char,
) -> Option<String> {
    let token = segment_args[index].as_str();
    if !token.starts_with('-') || token.starts_with("--") || token.chars().count() <= 2 {
        return None;
    }
    let cluster: Vec<char> = token.chars().skip(1).collect();
    for (flag_index, cluster_flag) in cluster.iter().enumerate() {
        if *cluster_flag == flag_character {
            let attached: String = cluster[flag_index + 1..].iter().collect();
            if !attached.is_empty() {
                return Some(attached);
            }
            return Some(next_value(segment_args, index).to_owned());
        }
        if short_flag_takes_value(*cluster_flag) {
            return None;
        }
    }
    None
}

/// Membership in `_CURL_SHORT_FLAGS_WITH_VALUES` for one flag character.
pub(crate) fn short_flag_takes_value(flag: char) -> bool {
    let mut buffer = [0u8; 4];
    CURL_SHORT_FLAGS_WITH_VALUES.contains(&&*flag.encode_utf8(&mut buffer))
}

/// `_direct_file_operand_uses_local_file`.
pub(crate) fn direct_file_operand_uses_local_file(
    value: &str,
    stdin_uses_local_file: bool,
) -> bool {
    let stripped_value = strip_cli_value(value);
    if stripped_value.is_empty() {
        return false;
    }
    if stripped_value == "-" || stripped_value == "@-" {
        return stdin_uses_local_file;
    }
    true
}

/// `_value_uses_local_file`.
pub(crate) fn value_uses_local_file(value: &str, stdin_uses_local_file: bool) -> bool {
    let stripped_value = strip_cli_value(value);
    if stripped_value.is_empty() {
        return false;
    }
    if stripped_value == "@-" {
        return stdin_uses_local_file;
    }
    if let Some(rest) = stripped_value.strip_prefix('@') {
        return rest != "-";
    }
    false
}

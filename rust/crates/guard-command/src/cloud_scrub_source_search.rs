//! Source-search pattern detection for the cloud text scrub
//! (`local_request_snapshots.py` `_source_search_pattern_spans` and helpers).
//! A grep/rg pattern is code the user searches for, so it is protected from
//! the generic secret-assignment scrub and scrubbed with a narrower rule.

use std::collections::BTreeMap;

use crate::cloud_scrub_shell::{shell_tokens, ShellToken};
use crate::env_wrapper::parse_env_wrapper;

const SOURCE_SEARCH_COMMANDS: [&str; 4] = ["grep", "egrep", "fgrep", "rg"];
const SOURCE_SEARCH_VALUE_FLAGS: [&str; 21] = [
    "-A",
    "-B",
    "-C",
    "-f",
    "-g",
    "-m",
    "-t",
    "--after-context",
    "--before-context",
    "--color",
    "--context",
    "--exclude",
    "--exclude-dir",
    "--file",
    "--glob",
    "--iglob",
    "--include",
    "--max-count",
    "--type",
    "--type-add",
    "--type-not",
];
const SOURCE_SEARCH_PATTERN_FLAGS: [&str; 2] = ["-e", "--regexp"];
const SUDO_VALUE_OPTIONS: [&str; 17] = [
    "-C",
    "-D",
    "-g",
    "-p",
    "-r",
    "-t",
    "-u",
    "--chdir",
    "--close-from",
    "--group",
    "--host",
    "--other-user",
    "--preserve-env",
    "--prompt",
    "--role",
    "--type",
    "--user",
];
const GIT_VALUE_OPTIONS: [&str; 8] = [
    "-C",
    "-c",
    "--attr-source",
    "--config-env",
    "--exec-path",
    "--git-dir",
    "--namespace",
    "--work-tree",
];

type Span = (usize, usize);

fn is_env_assignment(value: &str) -> bool {
    let mut chars = value.chars();
    match chars.next() {
        Some(c) if c.is_ascii_alphabetic() || c == '_' => {}
        _ => return false,
    }
    for c in chars {
        if c == '=' {
            return true;
        }
        if !(c.is_ascii_alphanumeric() || c == '_') {
            return false;
        }
    }
    false
}

fn command_basename(value: &str) -> &str {
    value.rsplit('/').next().unwrap_or(value)
}

pub(crate) fn source_search_pattern_spans(value: &[char]) -> Vec<Span> {
    let Some(tokens) = shell_tokens(value) else {
        return Vec::new();
    };
    let mut spans = Vec::new();
    let mut segment_start = 0usize;
    for index in 0..=tokens.len() {
        let control = tokens.get(index).is_none_or(|token| token.is_control);
        if !control {
            continue;
        }
        spans.extend(segment_spans(&tokens, segment_start, index));
        segment_start = index + 1;
    }
    spans
}

fn token_span(tokens: &[ShellToken], index: usize) -> Span {
    (tokens[index].start, tokens[index].end)
}

fn segment_spans(tokens: &[ShellToken], start: usize, end: usize) -> Vec<Span> {
    let mut spans: Vec<Span> = split_string_indexes(tokens, start, end)
        .into_iter()
        .map(|index| token_span(tokens, index))
        .collect();
    let command_index = command_index(tokens, start, end);
    if command_index >= end {
        return spans;
    }
    let name = command_basename(&tokens[command_index].value);
    let mut argument_index = command_index + 1;
    if name == "git" {
        argument_index = git_grep_argument_index(tokens, argument_index, end);
        if argument_index >= end {
            return spans;
        }
    } else if !SOURCE_SEARCH_COMMANDS.contains(&name) {
        return spans;
    }
    spans.extend(
        pattern_token_indexes(tokens, argument_index, end)
            .into_iter()
            .map(|index| token_span(tokens, index)),
    );
    spans
}

fn split_string_indexes(tokens: &[ShellToken], start: usize, end: usize) -> Vec<usize> {
    let mut index = start;
    while index < end {
        while index < end && is_env_assignment(&tokens[index].value) {
            index += 1;
        }
        if index >= end {
            return Vec::new();
        }
        let name = command_basename(&tokens[index].value);
        if let Some(next) = skip_transparent_wrapper(name, tokens, index + 1, end) {
            index = next;
            continue;
        }
        if name != "env" {
            return Vec::new();
        }
        return env_split_string_indexes(tokens, index + 1, end);
    }
    Vec::new()
}

fn env_values(tokens: &[ShellToken], start: usize, end: usize) -> Vec<String> {
    let end = end.min(tokens.len());
    let start = start.min(end);
    tokens[start..end]
        .iter()
        .map(|token| token.value.clone())
        .collect()
}

fn env_split_string_indexes(tokens: &[ShellToken], start: usize, end: usize) -> Vec<usize> {
    let parsed = parse_env_wrapper(&env_values(tokens, start, end), None, None);
    let mut seen: Vec<usize> = Vec::new();
    for expansion in &parsed.split_expansions {
        let payload: Vec<char> = expansion.payload.chars().collect();
        if source_search_pattern_spans(&payload).is_empty() {
            continue;
        }
        let index = start + expansion.source_index;
        if !seen.contains(&index) {
            seen.push(index);
        }
    }
    seen
}

fn command_index(tokens: &[ShellToken], start: usize, end: usize) -> usize {
    let mut index = start;
    while index < end {
        while index < end && is_env_assignment(&tokens[index].value) {
            index += 1;
        }
        if index >= end {
            return index;
        }
        let name = command_basename(&tokens[index].value);
        if let Some(next) = skip_transparent_wrapper(name, tokens, index + 1, end) {
            index = next;
            continue;
        }
        if name == "env" {
            index = skip_env_prefix_options(tokens, index + 1, end);
            continue;
        }
        return index;
    }
    index
}

fn skip_transparent_wrapper(
    name: &str,
    tokens: &[ShellToken],
    start: usize,
    end: usize,
) -> Option<usize> {
    match name {
        "command" | "nohup" => Some(skip_command_prefix_options(tokens, start, end)),
        "nice" => Some(skip_options(tokens, start, end, &["-n", "--adjustment"])),
        "stdbuf" => Some(skip_options(
            tokens,
            start,
            end,
            &["-e", "-i", "-o", "--error", "--input", "--output"],
        )),
        "sudo" => Some(skip_options(tokens, start, end, &SUDO_VALUE_OPTIONS)),
        "time" => Some(skip_options(
            tokens,
            start,
            end,
            &["-f", "-o", "--format", "--output"],
        )),
        _ => None,
    }
}

fn skip_command_prefix_options(tokens: &[ShellToken], start: usize, end: usize) -> usize {
    let mut index = start;
    while index < end {
        let value = tokens[index].value.as_str();
        if value == "--" {
            return index + 1;
        }
        if !value.starts_with('-') {
            return index;
        }
        index += 1;
    }
    index
}

/// Shared prefix-option scan: `--` ends options, a value option consumes its
/// operand, every other dash word is a flag. (The per-wrapper attached forms
/// in the Python helpers all begin with a dash, so they are plain flags.)
fn skip_options(tokens: &[ShellToken], start: usize, end: usize, value_options: &[&str]) -> usize {
    let mut index = start;
    while index < end {
        let value = tokens[index].value.as_str();
        if value == "--" {
            return index + 1;
        }
        if value_options.contains(&value) {
            index += 2;
            continue;
        }
        if value.starts_with('-') {
            index += 1;
            continue;
        }
        return index;
    }
    index
}

fn skip_env_prefix_options(tokens: &[ShellToken], start: usize, end: usize) -> usize {
    let parsed = parse_env_wrapper(&env_values(tokens, start, end), None, None);
    match parsed.command_index {
        Some(command_index) if parsed.complete && parsed.split_expansions.is_empty() => {
            start + command_index
        }
        _ => end,
    }
}

fn git_grep_argument_index(tokens: &[ShellToken], start: usize, end: usize) -> usize {
    let mut index = start;
    while index < end {
        let value = tokens[index].value.as_str();
        if value == "grep" {
            return index + 1;
        }
        if value == "--" {
            return end;
        }
        if GIT_VALUE_OPTIONS.contains(&value) {
            index += 2;
            continue;
        }
        if value.starts_with('-') {
            index += 1;
            continue;
        }
        return end;
    }
    end
}

fn is_attached_pattern_option(value: &str) -> bool {
    value.starts_with("--regexp=") || (value.starts_with("-e") && value.chars().count() > 2)
}

fn pattern_token_indexes(tokens: &[ShellToken], start: usize, end: usize) -> Vec<usize> {
    let mut indexes: Vec<usize> = Vec::new();
    let mut options_enabled = true;
    let mut index = start;
    while index < end {
        let value = tokens[index].value.as_str();
        if options_enabled && value == "--" {
            options_enabled = false;
            index += 1;
            continue;
        }
        if options_enabled && SOURCE_SEARCH_PATTERN_FLAGS.contains(&value) {
            if index + 1 >= end {
                return Vec::new();
            }
            indexes.push(index + 1);
            index += 2;
            continue;
        }
        if options_enabled && is_attached_pattern_option(value) {
            indexes.push(index);
            index += 1;
            continue;
        }
        if options_enabled && SOURCE_SEARCH_VALUE_FLAGS.contains(&value) {
            if index + 1 >= end {
                return Vec::new();
            }
            index += 2;
            continue;
        }
        if options_enabled && value.starts_with('-') {
            index += 1;
            continue;
        }
        if indexes.is_empty() {
            indexes.push(index);
        }
        return indexes;
    }
    indexes
}

/// Replace every protected span with a unique placeholder; returns the
/// protected text and the placeholder -> safe-token replacements in order.
pub(crate) fn protect_spans(
    value: &[char],
    spans: &[Span],
    safe_token: impl Fn(&str) -> String,
) -> (String, Vec<(String, String)>) {
    let text: String = value.iter().collect();
    let mut parts = String::new();
    let mut replacements: BTreeMap<usize, (String, String)> = BTreeMap::new();
    let mut cursor = 0usize;
    for (index, &(start, end)) in spans.iter().enumerate() {
        if start < cursor {
            continue;
        }
        let end_clamped = end.min(value.len());
        let raw: String = value[start..end_clamped].iter().collect();
        let placeholder = placeholder(index, &text);
        parts.extend(value[cursor.min(value.len())..start].iter());
        parts.push_str(&placeholder);
        replacements.insert(index, (placeholder, safe_token(&raw)));
        cursor = end;
    }
    parts.extend(value[cursor.min(value.len())..].iter());
    (parts, replacements.into_values().collect())
}

fn placeholder(index: usize, value: &str) -> String {
    let mut nonce = 0usize;
    loop {
        let candidate = format!("__HOL_GUARD_SOURCE_SEARCH_PATTERN_{index}_{nonce}__");
        if !value.contains(&candidate) {
            return candidate;
        }
        nonce += 1;
    }
}

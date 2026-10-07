//! Local data-flow source and sink helpers (`runtime/data_flow.py` — the
//! pipe/segment/redirect subset consumed by `command_model` and
//! `kubernetes_commands`: `extract_command_segments`, `extract_pipes`,
//! `extract_input_redirects`).

use std::collections::HashSet;

use fancy_regex::Regex as FancyRegex;

use crate::shell_structure::{self, ShellScanState};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ShellPipe {
    pub left: String,
    pub right: String,
}

/// `_INPUT_REDIRECT_PATTERN`.
#[allow(clippy::invalid_regex)]
fn input_redirect_pattern() -> &'static FancyRegex {
    static RE: std::sync::OnceLock<FancyRegex> = std::sync::OnceLock::new();
    RE.get_or_init(|| {
        FancyRegex::new(r#"(?<!<)(?:\d*)<\s*(?![<&])(?P<target>"[^"]+"|'[^']+'|[^ \t\r\n;&|<>]+)"#)
            .expect("input redirect pattern")
    })
}

/// `extract_input_redirects` (:166-174).
pub fn extract_input_redirects(command: &str) -> Vec<String> {
    let mut targets: Vec<String> = Vec::new();
    for segment in split_top_level_commands(command) {
        for caps in input_redirect_pattern().captures_iter(&segment).flatten() {
            let target = strip_shell_quotes(caps.name("target").map(|m| m.as_str()).unwrap_or(""));
            if !target.is_empty() && !target.starts_with('(') && !target.starts_with('&') {
                targets.push(target);
            }
        }
    }
    dedupe(targets)
}

/// `extract_pipes` (:177-190).
pub fn extract_pipes(command: &str) -> Vec<ShellPipe> {
    let mut pipes: Vec<ShellPipe> = Vec::new();
    for segment in split_top_level_commands(command) {
        let parts = split_top_level_pipes(&segment);
        if parts.len() < 2 {
            continue;
        }
        for pair in parts.windows(2) {
            let left = pair[0].trim();
            let right = pair[1].trim();
            if !left.is_empty() && !right.is_empty() {
                pipes.push(ShellPipe {
                    left: left.to_owned(),
                    right: right.to_owned(),
                });
            }
        }
    }
    pipes
}

/// `extract_command_segments` (:193-196).
pub fn extract_command_segments(command: &str) -> Vec<String> {
    split_top_level_commands(command)
}

/// `_dedupe` (:230-241).
fn dedupe(values: Vec<String>) -> Vec<String> {
    let mut seen: HashSet<String> = HashSet::new();
    let mut result = Vec::new();
    for value in values {
        if seen.insert(value.clone()) {
            result.push(value);
        }
    }
    result
}

/// `_strip_shell_quotes` (:244-248).
fn strip_shell_quotes(value: &str) -> String {
    let stripped = value.trim();
    let chars: Vec<char> = stripped.chars().collect();
    if chars.len() >= 2
        && chars[0] == chars[chars.len() - 1]
        && (chars[0] == '\'' || chars[0] == '"')
    {
        chars[1..chars.len() - 1].iter().collect()
    } else {
        stripped.to_owned()
    }
}

/// `_split_top_level_commands` (:255-277). Indices are char offsets.
fn split_top_level_commands(command: &str) -> Vec<String> {
    let chars: Vec<char> = command.chars().collect();
    let n = chars.len();
    let mut parts: Vec<String> = Vec::new();
    let mut start = 0usize;
    let mut index = 0usize;
    let mut state = ShellScanState::new();
    while index < n {
        let next_index = state.advance(&chars, index);
        if next_index != index + 1 {
            index = next_index;
            continue;
        }
        if state.is_top_level() && (chars[index] == ';' || chars[index] == '\n') {
            append_segment(&mut parts, &chars[start..index]);
            start = index + 1;
        } else if state.is_top_level() && (at(&chars, index, "&&") || at(&chars, index, "||")) {
            append_segment(&mut parts, &chars[start..index]);
            start = index + 2;
            index += 1;
        } else if state.is_top_level()
            && chars[index] == '&'
            && is_background_separator(&chars, index)
        {
            append_segment(&mut parts, &chars[start..index]);
            start = index + 1;
        }
        index += 1;
    }
    append_segment(&mut parts, &chars[start.min(n)..]);
    parts
}

/// `_is_background_separator` (:280-283).
fn is_background_separator(chars: &[char], index: usize) -> bool {
    let previous = if index > 0 { chars[index - 1] } else { '\0' };
    let next = if index + 1 < chars.len() {
        chars[index + 1]
    } else {
        '\0'
    };
    !['>', '<', '|'].contains(&previous) && !['&', '>'].contains(&next)
}

/// `_split_top_level_pipes` (:286-304).
fn split_top_level_pipes(command: &str) -> Vec<String> {
    let chars: Vec<char> = command.chars().collect();
    let n = chars.len();
    let mut parts: Vec<String> = Vec::new();
    let mut start = 0usize;
    let mut index = 0usize;
    let mut state = ShellScanState::new();
    while index < n {
        let next_index = state.advance(&chars, index);
        if next_index != index + 1 {
            index = next_index;
            continue;
        }
        if state.is_top_level() && chars[index] == '|' {
            let previous_is_pipe = index > 0 && chars[index - 1] == '|';
            let next_is_pipe = index + 1 < n && chars[index + 1] == '|';
            if !previous_is_pipe && !next_is_pipe {
                append_segment(&mut parts, &chars[start..index]);
                start = if index + 1 < n && chars[index + 1] == '&' {
                    index + 2
                } else {
                    index + 1
                };
            }
        }
        index += 1;
    }
    append_segment(&mut parts, &chars[start.min(n)..]);
    parts
}

/// `_append_segment` (:307-310).
fn append_segment(parts: &mut Vec<String>, slice: &[char]) {
    let value: String = slice.iter().collect();
    let stripped = value.trim();
    if !stripped.is_empty() {
        parts.push(stripped.to_owned());
    }
}

fn at(chars: &[char], index: usize, pat: &str) -> bool {
    let p: Vec<char> = pat.chars().collect();
    index + p.len() <= chars.len() && chars[index..index + p.len()] == p[..]
}

// Re-exported shell-structure surface used by consumers (:11-31).
pub use shell_structure::{
    extract_command_substitution_spans, extract_expanded_heredoc_substitution_spans,
    extract_heredocs, mask_heredoc_bodies, ShellHeredoc,
};

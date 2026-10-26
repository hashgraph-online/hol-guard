//! Heredoc scanning primitives (`runtime/kubernetes_heredoc_support.py`).

#![allow(dead_code)]

use crate::hook_adapter_pytext::is_py_space;
use crate::sfrs_kubernetes_support::wrapper_options_with_values;

use crate::sfrs_kubernetes_heredoc::{slice, starts_with_at};

/// `_heredoc_body_and_end`: the body before the first terminator line and the
/// index just past that line.
pub(crate) fn heredoc_body_and_end(
    chars: &[char],
    tag: &str,
    start: usize,
) -> Option<(String, usize)> {
    let tag_chars: Vec<char> = tag.chars().collect();
    let is_blank = |c: char| c == '\t' || c == ' ';
    let mut line_start = start;
    while line_start <= chars.len() {
        if line_start == start || (line_start > 0 && chars[line_start - 1] == '\n') {
            let mut lead = line_start;
            while lead < chars.len() && is_blank(chars[lead]) {
                lead += 1;
            }
            // `[\t ]*` is greedy but gives characters back when the tag itself
            // starts with blanks.
            for tag_start in (line_start..=lead).rev() {
                let tag_end = tag_start + tag_chars.len();
                if tag_end > chars.len() || chars[tag_start..tag_end] != tag_chars[..] {
                    continue;
                }
                let mut cursor = tag_end;
                while cursor < chars.len() && is_blank(chars[cursor]) {
                    cursor += 1;
                }
                let end = if cursor >= chars.len() {
                    Some(cursor)
                } else if chars[cursor] == '\n' {
                    Some(cursor + 1)
                } else if chars[cursor] == '\r' && chars.get(cursor + 1) == Some(&'\n') {
                    Some(cursor + 2)
                } else {
                    None
                };
                if let Some(end) = end {
                    return Some((slice(chars, start, line_start), end));
                }
            }
        }
        line_start += 1;
    }
    None
}

/// `_is_background_separator`.
pub(crate) fn is_background_separator(chars: &[char], index: usize) -> bool {
    let previous = if index > 0 { chars[index - 1] } else { '\0' };
    let next = chars.get(index + 1).copied().unwrap_or('\0');
    chars[index] == '&' && !matches!(previous, '>' | '<' | '|') && !matches!(next, '&' | '>')
}

/// `_parse_heredoc`: `(tag, after_tag_start, body_start, line_end)`.
pub(crate) fn parse_heredoc(chars: &[char], index: usize) -> Option<(String, usize, usize, usize)> {
    let mut cursor = index + 2;
    if chars.get(cursor) == Some(&'-') {
        cursor += 1;
    }
    while matches!(chars.get(cursor), Some(' ' | '\t')) {
        cursor += 1;
    }
    if cursor >= chars.len() {
        return None;
    }
    let quote = Some(chars[cursor]).filter(|c| matches!(c, '\'' | '"'));
    if quote.is_some() {
        cursor += 1;
    }
    let tag_start = cursor;
    while cursor < chars.len() {
        let current = chars[cursor];
        match quote {
            Some(open) => {
                if current == open {
                    break;
                }
            }
            None => {
                if is_py_space(current) || "'\"`;&|<>".contains(current) {
                    break;
                }
            }
        }
        cursor += 1;
    }
    if cursor == tag_start {
        return None;
    }
    let tag = slice(chars, tag_start, cursor);
    if quote.is_some() {
        if cursor >= chars.len() || Some(chars[cursor]) != quote {
            return None;
        }
        cursor += 1;
    }
    let newline_index = (cursor..chars.len()).find(|&i| chars[i] == '\n')?;
    let line_end = if newline_index > cursor && chars[newline_index - 1] == '\r' {
        newline_index - 1
    } else {
        newline_index
    };
    Some((tag, cursor, newline_index + 1, line_end))
}

/// `_skip_command_whitespace`.
pub(crate) fn skip_command_whitespace(chars: &[char], mut index: usize) -> usize {
    while index < chars.len() && is_py_space(chars[index]) {
        index += 1;
    }
    index
}

/// `_wrapper_option_tokens_consumed`.
pub(crate) fn wrapper_option_tokens_consumed(command_name: &str, token: &str) -> usize {
    if wrapper_options_with_values(command_name).contains(&token) {
        2
    } else {
        1
    }
}

/// `_starts_command_separator`.
pub(crate) fn starts_command_separator(chars: &[char], index: usize) -> bool {
    starts_with_at(chars, index, "&&") || starts_with_at(chars, index, "||")
}

/// `_looks_like_heredoc_operator`.
pub(crate) fn looks_like_heredoc_operator(chars: &[char], index: usize) -> bool {
    starts_with_at(chars, index, "<<") && !starts_with_at(chars, index, "<<<")
}

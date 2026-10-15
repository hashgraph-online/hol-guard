//! Quote-preserving shell tokens shared by command classifiers
//! (`shell_quote_tokens.py`).

// Consumed by the later classifier slices.
#![allow(dead_code)]

use crate::codex_output_py::{is_py_space, shlex_split, strip_quotes};

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct QuotedToken {
    pub(crate) raw: String,
    pub(crate) plain: String,
}

fn is_line_break(c: char) -> bool {
    c == '\n' || c == '\r'
}

fn is_control(c: char) -> bool {
    matches!(c, ';' | '&' | '|')
}

fn separator() -> QuotedToken {
    QuotedToken {
        raw: ";".to_owned(),
        plain: ";".to_owned(),
    }
}

/// `shell_tokens_preserving_quote_context`.
pub(crate) fn shell_tokens_preserving_quote_context(command_text: &str) -> Vec<QuotedToken> {
    let chars: Vec<char> = command_text.chars().collect();
    let starts = |at: usize, pattern: &str| {
        pattern
            .chars()
            .enumerate()
            .all(|(offset, c)| chars.get(at + offset) == Some(&c))
    };
    let mut tokens = Vec::new();
    let mut index = 0;
    while index < chars.len() {
        if is_line_break(chars[index]) {
            tokens.push(separator());
            index += 1;
            continue;
        }
        while index < chars.len() && is_py_space(chars[index]) && !is_line_break(chars[index]) {
            index += 1;
        }
        if index >= chars.len() {
            break;
        }
        if is_line_break(chars[index]) {
            tokens.push(separator());
            index += 1;
            continue;
        }
        if is_control(chars[index]) {
            let width = if starts(index, "&&") || starts(index, "||") {
                2
            } else {
                1
            };
            let raw: String = chars[index..index + width].iter().collect();
            index += width;
            tokens.push(QuotedToken {
                raw: raw.clone(),
                plain: raw,
            });
            continue;
        }
        let start = index;
        let mut quote: Option<&str> = None;
        let mut escaped = false;
        while index < chars.len() {
            let c = chars[index];
            if escaped {
                escaped = false;
                index += 1;
                continue;
            }
            if c == '\\' && quote != Some("'") {
                escaped = true;
                index += 1;
                continue;
            }
            if let Some(open) = quote {
                let closing = if open == "$'" {
                    '\''
                } else {
                    open.chars().next().unwrap_or('"')
                };
                if c == closing {
                    quote = None;
                }
                index += 1;
                continue;
            }
            if starts(index, "$'") {
                quote = Some("$'");
                index += 2;
                continue;
            }
            if c == '\'' || c == '"' {
                quote = Some(if c == '\'' { "'" } else { "\"" });
                index += 1;
                continue;
            }
            if c == '&' && is_fd_duplication_ampersand(&chars, index, start) {
                index += 1;
                continue;
            }
            if is_py_space(c) || is_control(c) {
                break;
            }
            index += 1;
        }
        let raw: String = chars[start..index].iter().collect();
        if !raw.is_empty() {
            let plain = plain_shell_token(&raw);
            tokens.push(QuotedToken { raw, plain });
        }
    }
    tokens
}

/// Only ASCII digits count as descriptors; other Unicode digits are not shell
/// file descriptors.
fn is_fd_duplication_ampersand(chars: &[char], index: usize, token_start: usize) -> bool {
    if index <= token_start || !matches!(chars[index - 1], '<' | '>') {
        return false;
    }
    let mut at = index + 1;
    if at >= chars.len() {
        return false;
    }
    if chars[at] == '-' {
        at += 1;
    } else {
        if !chars[at].is_ascii_digit() {
            return false;
        }
        while at < chars.len() && chars[at].is_ascii_digit() {
            at += 1;
        }
    }
    at >= chars.len() || is_py_space(chars[at]) || is_control(chars[at])
}

/// `plain_shell_token`.
pub(crate) fn plain_shell_token(raw_token: &str) -> String {
    match shlex_split(raw_token) {
        None => strip_quotes(raw_token).to_owned(),
        Some(parts) => parts.into_iter().next().unwrap_or_default(),
    }
}

/// `shell_token_segments`.
pub(crate) fn shell_token_segments(tokens: &[QuotedToken]) -> Vec<Vec<QuotedToken>> {
    let mut segments = Vec::new();
    let mut current: Vec<QuotedToken> = Vec::new();
    for token in tokens {
        if matches!(token.plain.as_str(), "&&" | "||" | ";" | "&" | "|" | "|&") {
            if !current.is_empty() {
                segments.push(std::mem::take(&mut current));
            }
            continue;
        }
        current.push(token.clone());
    }
    if !current.is_empty() {
        segments.push(current);
    }
    segments
}

#[cfg(test)]
mod tests {
    use super::*;

    fn raws(text: &str) -> Vec<String> {
        shell_tokens_preserving_quote_context(text)
            .into_iter()
            .map(|token| token.raw)
            .collect()
    }

    #[test]
    fn keeps_quotes_in_raw_and_strips_them_in_plain() {
        let tokens = shell_tokens_preserving_quote_context("echo 'a b' \"c\" $'d e'");
        assert_eq!(tokens[1].raw, "'a b'");
        assert_eq!(tokens[1].plain, "a b");
        assert_eq!(tokens[3].plain, "$d e");
    }

    #[test]
    fn control_operators_and_fd_duplication() {
        assert_eq!(raws("a && b; c |d"), ["a", "&&", "b", ";", "c", "|", "d"]);
        assert_eq!(raws("cmd 2>&1 | x"), ["cmd", "2>&1", "|", "x"]);
        assert_eq!(raws("a\nb"), ["a", ";", "b"]);
    }
}

//! Chain and pipeline splitting for the Codex read-only source inspection review.

use crate::codex_output_py::{is_py_space, py_strip, shlex_join, shlex_split};

fn starts_with_at(chars: &[char], index: usize, needle: &str) -> bool {
    let needle: Vec<char> = needle.chars().collect();
    chars.len() >= index + needle.len() && chars[index..index + needle.len()] == needle[..]
}

fn slice(chars: &[char], start: usize, end: usize) -> String {
    chars[start..end].iter().collect()
}

/// `_split_codex_safe_read_only_chain`.
pub(crate) fn split_chain(command: &str) -> Option<Vec<String>> {
    let chars: Vec<char> = command.chars().collect();
    let mut segments: Vec<String> = Vec::new();
    let mut start = 0;
    let mut quote: Option<char> = None;
    let mut escaped = false;
    let mut found_chain = false;
    let mut index = 0;
    while index < chars.len() {
        let c = chars[index];
        if escaped {
            escaped = false;
            index += 1;
            continue;
        }
        if c == '\\' {
            escaped = true;
            index += 1;
            continue;
        }
        if let Some(open) = quote {
            if c == open {
                quote = None;
            }
            index += 1;
            continue;
        }
        if c == '\'' || c == '"' {
            quote = Some(c);
            index += 1;
            continue;
        }
        if starts_with_at(&chars, index, "&&") {
            let segment = py_strip(&slice(&chars, start, index)).to_owned();
            if segment.is_empty() {
                return None;
            }
            segments.push(segment);
            found_chain = true;
            index += 2;
            start = index;
            continue;
        }
        if starts_with_at(&chars, index, "||") || c == '&' {
            return None;
        }
        if c == ';' {
            let segment = py_strip(&slice(&chars, start, index)).to_owned();
            if segment.is_empty() || starts_with_at(&chars, index, ";;") {
                return None;
            }
            segments.push(segment);
            found_chain = true;
            index += 1;
            start = index;
            continue;
        }
        index += 1;
    }
    if quote.is_some() || escaped || !found_chain {
        return None;
    }
    let segment = py_strip(&slice(&chars, start, chars.len())).to_owned();
    if segment.is_empty() {
        return None;
    }
    segments.push(segment);
    (segments.len() > 1).then_some(segments)
}

/// `_codex_command_has_unquoted_glob_metachar`.
pub(crate) fn has_unquoted_glob_metachar(command: &str) -> bool {
    let chars: Vec<char> = command.chars().collect();
    let mut quote: Option<char> = None;
    let mut escaped = false;
    let mut index = 0;
    while index < chars.len() {
        let c = chars[index];
        if escaped {
            escaped = false;
            index += 1;
            continue;
        }
        if c == '\\' {
            escaped = true;
            index += 1;
            continue;
        }
        if let Some(open) = quote {
            if c == open {
                quote = None;
            }
            index += 1;
            continue;
        }
        if c == '\'' || c == '"' {
            quote = Some(c);
            index += 1;
            continue;
        }
        if starts_with_at(&chars, index, "{}") {
            index += 2;
            continue;
        }
        if matches!(c, '*' | '?' | '[' | ']' | '{' | '}') {
            return true;
        }
        index += 1;
    }
    false
}

/// `_codex_command_uses_untrusted_search_binary`.
pub(crate) fn uses_untrusted_search_binary(executable_token: &str) -> bool {
    executable_token.starts_with('.')
        || executable_token.contains('/')
        || executable_token.contains('\\')
}

/// `_split_codex_safe_read_only_pipeline`.
pub(crate) fn split_pipeline(command: &str) -> Option<Vec<String>> {
    let mut segments: Vec<String> = Vec::new();
    let mut current = String::new();
    let mut quote: Option<char> = None;
    let mut escaped = false;
    for c in command.chars() {
        if escaped {
            current.push(c);
            escaped = false;
            continue;
        }
        if c == '\\' {
            current.push(c);
            escaped = true;
            continue;
        }
        if let Some(open) = quote {
            current.push(c);
            if c == open {
                quote = None;
            } else if open == '"' && (c == '`' || c == '$') {
                return None;
            }
            continue;
        }
        if c == '\'' || c == '"' {
            current.push(c);
            quote = Some(c);
            continue;
        }
        if matches!(c, '\n' | '\r' | '&' | ';' | '<' | '`' | '$') {
            return None;
        }
        if c == '|' {
            let segment = py_strip(&current).to_owned();
            if segment.is_empty() {
                return None;
            }
            segments.push(strip_stderr_discard(&segment)?);
            current.clear();
            continue;
        }
        current.push(c);
    }
    let segment = py_strip(&current).to_owned();
    if segments.is_empty() || segment.is_empty() {
        return None;
    }
    segments.push(strip_stderr_discard(&segment)?);
    Some(segments)
}

/// `_strip_codex_safe_stderr_discard`.
pub(crate) fn strip_stderr_discard(segment: &str) -> Option<String> {
    let cleaned = remove_stderr_discard(segment)?;
    let parts = shlex_split(&cleaned)?;
    let first = parts.first()?;
    if uses_untrusted_search_binary(first) {
        return None;
    }
    Some(shlex_join(&parts))
}

/// `_remove_codex_safe_stderr_discard`.
pub(crate) fn remove_stderr_discard(segment: &str) -> Option<String> {
    let chars: Vec<char> = segment.chars().collect();
    let mut cleaned = String::new();
    let mut quote: Option<char> = None;
    let mut escaped = false;
    let mut index = 0;
    while index < chars.len() {
        let c = chars[index];
        if escaped {
            cleaned.push(c);
            escaped = false;
            index += 1;
            continue;
        }
        if c == '\\' {
            cleaned.push(c);
            escaped = true;
            index += 1;
            continue;
        }
        if let Some(open) = quote {
            cleaned.push(c);
            if c == open {
                quote = None;
            }
            index += 1;
            continue;
        }
        if c == '\'' || c == '"' {
            cleaned.push(c);
            quote = Some(c);
            index += 1;
            continue;
        }
        if starts_with_at(&chars, index, "2>") {
            let mut after_redirect = index + 2;
            while after_redirect < chars.len() && is_py_space(chars[after_redirect]) {
                after_redirect += 1;
            }
            if starts_with_at(&chars, after_redirect, "/dev/null") {
                let after_target = after_redirect + "/dev/null".len();
                if after_target == chars.len() || is_py_space(chars[after_target]) {
                    index = after_target;
                    continue;
                }
            }
            return None;
        }
        if c == '>' {
            return None;
        }
        cleaned.push(c);
        index += 1;
    }
    Some(py_strip(&cleaned).to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chain_and_pipeline_split_like_python() {
        assert_eq!(
            split_chain("cat a && cat b; cat c"),
            Some(vec!["cat a".into(), "cat b".into(), "cat c".into()])
        );
        assert_eq!(split_chain("cat a || cat b"), None);
        assert_eq!(split_chain("cat a"), None);
        assert_eq!(
            split_pipeline("rg x src 2>/dev/null | head -n 5"),
            Some(vec!["rg x src".into(), "head -n 5".into()])
        );
        assert_eq!(split_pipeline("cat a | head > out"), None);
        assert_eq!(split_pipeline("cat a"), None);
        assert!(has_unquoted_glob_metachar("cat *.rs"));
        assert!(!has_unquoted_glob_metachar("cat '*.rs' {}"));
        assert!(uses_untrusted_search_binary("./rg"));
    }
}

//! CPython string and regex semantics shared by the hook adapter port.

use fancy_regex::Regex as FancyRegex;
use regex::Regex;

/// `str.isspace` for one code point (`Py_UNICODE_ISSPACE`): Unicode
/// `White_Space` plus the ASCII separators `\x1c`-`\x1f`.
pub fn is_py_space(ch: char) -> bool {
    ch.is_whitespace() || ('\u{1c}'..='\u{1f}').contains(&ch)
}

/// `str.strip()`.
pub fn py_strip(text: &str) -> &str {
    text.trim_matches(is_py_space)
}

/// `str.split()` joined by one space: `" ".join(text.split())`.
pub fn py_collapse_whitespace(text: &str) -> String {
    text.split(is_py_space)
        .filter(|part| !part.is_empty())
        .collect::<Vec<_>>()
        .join(" ")
}

/// `text[:limit]` counted in code points.
pub fn py_prefix_chars(text: &str, limit: usize) -> &str {
    match text.char_indices().nth(limit) {
        Some((index, _)) => &text[..index],
        None => text,
    }
}

/// Python `str.lower()` (full Unicode lowercasing, final-sigma aware).
pub fn py_lower(text: &str) -> String {
    text.to_lowercase()
}

/// Order-preserving de-duplication (`list(dict.fromkeys(items))`).
pub fn dedupe_preserving_order(items: Vec<String>) -> Vec<String> {
    let mut seen = std::collections::HashSet::new();
    items
        .into_iter()
        .filter(|item| seen.insert(item.clone()))
        .collect()
}

/// Python `str.isprintable` approximation used by `repr(str)`.
fn is_printable(ch: char) -> bool {
    if ch == ' ' {
        return true;
    }
    if ch.is_control() || ch.is_whitespace() {
        return false;
    }
    let code = ch as u32;
    !matches!(
        code,
        0xad | 0x600..=0x605
            | 0x61c
            | 0x6dd
            | 0x70f
            | 0x180e
            | 0x200b..=0x200f
            | 0x202a..=0x202e
            | 0x2060..=0x206f
            | 0xfeff
            | 0xfff9..=0xfffb
            | 0xd800..=0xf8ff
            | 0xe0000..=0xe007f
            | 0xf0000..=0x10ffff
    )
}

/// `repr(str)` (single-quote preference, `\xNN`/`\uNNNN` escapes for
/// non-printable code points).
pub fn py_repr_str(text: &str) -> String {
    let quote = if text.contains('\'') && !text.contains('"') {
        '"'
    } else {
        '\''
    };
    let mut out = String::with_capacity(text.len() + 2);
    out.push(quote);
    for ch in text.chars() {
        match ch {
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            other if other == quote => {
                out.push('\\');
                out.push(other);
            }
            other if (other as u32) < 0x20 || other as u32 == 0x7f => {
                out.push_str(&format!("\\x{:02x}", other as u32));
            }
            other if (other as u32) < 0x7f || is_printable(other) => out.push(other),
            other => {
                let code = other as u32;
                if code <= 0xff {
                    out.push_str(&format!("\\x{code:02x}"));
                } else if code <= 0xffff {
                    out.push_str(&format!("\\u{code:04x}"));
                } else {
                    out.push_str(&format!("\\U{code:08x}"));
                }
            }
        }
    }
    out.push(quote);
    out
}

/// Compile a lookaround-free pattern once.
pub fn compile(pattern: &str) -> Regex {
    Regex::new(pattern).expect("hook adapter pattern is a compile-time constant")
}

/// Compile a lookbehind-bearing pattern once.
pub fn compile_fancy(pattern: &str) -> FancyRegex {
    FancyRegex::new(pattern).expect("hook adapter pattern is a compile-time constant")
}

/// `pattern.sub(callback, text)` over non-overlapping matches.
pub fn fancy_replace_all<F>(pattern: &FancyRegex, text: &str, mut replace: F) -> String
where
    F: FnMut(&fancy_regex::Captures<'_, str>) -> String,
{
    let mut out = String::with_capacity(text.len());
    let mut last = 0usize;
    let mut cursor = 0usize;
    while cursor <= text.len() {
        let Ok(Some(captures)) = pattern.captures_from_pos(text, cursor) else {
            break;
        };
        let Some(whole) = captures.get(0) else { break };
        out.push_str(&text[last..whole.start()]);
        out.push_str(&replace(&captures));
        last = whole.end();
        cursor = if whole.end() == whole.start() {
            whole.end() + text[whole.end()..].chars().next().map_or(1, char::len_utf8)
        } else {
            whole.end()
        };
    }
    out.push_str(&text[last.min(text.len())..]);
    out
}

/// Every non-overlapping `finditer` capture of group `name`.
pub fn fancy_find_group_all(pattern: &FancyRegex, text: &str, name: &str) -> Vec<String> {
    let mut found = Vec::new();
    let mut cursor = 0usize;
    while cursor <= text.len() {
        let Ok(Some(captures)) = pattern.captures_from_pos(text, cursor) else {
            break;
        };
        let Some(whole) = captures.get(0) else { break };
        if let Some(group) = captures.name(name) {
            found.push(group.as_str().to_owned());
        }
        cursor = if whole.end() == whole.start() {
            whole.end() + text[whole.end()..].chars().next().map_or(1, char::len_utf8)
        } else {
            whole.end()
        };
    }
    found
}

/// `shlex.join(args)`.
pub fn shlex_join(args: &[String]) -> String {
    args.iter()
        .map(|arg| crate::command_launcher_floors::shlex_quote(arg))
        .collect::<Vec<_>>()
        .join(" ")
}

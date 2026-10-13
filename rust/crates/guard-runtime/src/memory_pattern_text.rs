//! CPython `re`-compatible text normalization for memory pattern path families.
//!
//! Path families collapse hashes, UUIDs, environment references and decimal
//! runs with the same Unicode word and digit classes the retired Python
//! builders used, so saved ids keep matching.

use std::sync::LazyLock;

use guard_command::command_option_parsing::python_is_alphanumeric;
use regex::Regex;

static DECIMAL_DIGIT: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^\p{Nd}$").expect("decimal digit class compiles"));

/// CPython `re` `\w`: `str.isalnum()` or underscore.
fn is_python_word(character: char) -> bool {
    character == '_' || python_is_alphanumeric(character)
}

/// CPython `re` `\d`: `str.isdecimal()`.
pub(super) fn is_python_decimal(character: char) -> bool {
    if character.is_ascii() {
        return character.is_ascii_digit();
    }
    let mut buffer = [0; 4];
    DECIMAL_DIGIT.is_match(character.encode_utf8(&mut buffer))
}

pub(super) fn is_lower_hex(character: char) -> bool {
    matches!(character, '0'..='9' | 'a'..='f')
}

fn word_boundary_before(chars: &[char], index: usize) -> bool {
    index == 0 || !is_python_word(chars[index - 1])
}

fn word_boundary_after(chars: &[char], index: usize) -> bool {
    index == chars.len() || !is_python_word(chars[index])
}

/// `re.sub(r"\b<class>{min,}\b", replacement, text)` for a word-character
/// class: a run only matches whole, so the scan never backtracks.
pub(super) fn replace_bounded_runs(
    text: &str,
    class: fn(char) -> bool,
    min: usize,
    replacement: &str,
) -> String {
    let chars: Vec<char> = text.chars().collect();
    let mut out = String::with_capacity(text.len());
    let mut index = 0;
    while index < chars.len() {
        if !class(chars[index]) || !word_boundary_before(&chars, index) {
            out.push(chars[index]);
            index += 1;
            continue;
        }
        let mut end = index;
        while end < chars.len() && class(chars[end]) {
            end += 1;
        }
        if end - index >= min && word_boundary_after(&chars, end) {
            out.push_str(replacement);
        } else {
            out.extend(&chars[index..end]);
        }
        index = end;
    }
    out
}

/// `re.sub(r"\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b", "<uuid>", text)`.
pub(super) fn replace_uuids(text: &str) -> String {
    const GROUPS: [usize; 5] = [8, 4, 4, 4, 12];
    let chars: Vec<char> = text.chars().collect();
    let mut out = String::with_capacity(text.len());
    let mut index = 0;
    while index < chars.len() {
        let end = word_boundary_before(&chars, index)
            .then(|| uuid_end(&chars, index, &GROUPS))
            .flatten()
            .filter(|end| word_boundary_after(&chars, *end));
        if let Some(end) = end {
            out.push_str("<uuid>");
            index = end;
        } else {
            out.push(chars[index]);
            index += 1;
        }
    }
    out
}

fn uuid_end(chars: &[char], start: usize, groups: &[usize]) -> Option<usize> {
    let mut index = start;
    for (position, length) in groups.iter().enumerate() {
        if position > 0 {
            (chars.get(index) == Some(&'-')).then_some(())?;
            index += 1;
        }
        let group = chars.get(index..index + length)?;
        group
            .iter()
            .all(|character| is_lower_hex(*character))
            .then_some(())?;
        index += length;
    }
    Some(index)
}

/// `re.sub(r"\$\{?\w+\}?", "<env>", text)`.
pub(super) fn replace_env_references(text: &str) -> String {
    let chars: Vec<char> = text.chars().collect();
    let mut out = String::with_capacity(text.len());
    let mut index = 0;
    while index < chars.len() {
        if chars[index] == '$' {
            let mut name_start = index + 1;
            if chars.get(name_start) == Some(&'{') {
                name_start += 1;
            }
            let mut end = name_start;
            while end < chars.len() && is_python_word(chars[end]) {
                end += 1;
            }
            if end > name_start {
                if chars.get(end) == Some(&'}') {
                    end += 1;
                }
                out.push_str("<env>");
                index = end;
                continue;
            }
        }
        out.push(chars[index]);
        index += 1;
    }
    out
}

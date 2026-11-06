//! Reading the Codex `config.toml` and `hooks.json` sources the way
//! `_read_toml` and `_json_object` do: a missing, unreadable or malformed
//! source is an empty table, and text CPython would raise on is a refusal.

use std::fs;
use std::path::Path;

use serde_json::{Map, Value};

use super::aibom_paths::is_file;
use super::codex_value::HookVal;
use super::pyjson::{parse_marking_lone_surrogates, JsonFailure};
use super::runner_authority_op::ERR_INVALID;

pub(super) const ERR_TEXT: &str = "native_runner_authority_codex_text_undecodable";
pub(super) const ERR_VALUE: &str = "native_runner_authority_codex_value_unrepresentable";

/// A source file: whether it counts as found, and its bytes when readable.
pub(super) struct Raw {
    pub(super) present: bool,
    pub(super) bytes: Option<Vec<u8>>,
}

pub(super) fn read_source(
    path: &str,
    contents: Option<&Map<String, Value>>,
) -> Result<Raw, &'static str> {
    match contents {
        None => {
            let location = Path::new(path);
            let present = is_file(location);
            Ok(Raw {
                present,
                bytes: if present {
                    fs::read(location).ok()
                } else {
                    None
                },
            })
        }
        Some(captured) => match captured.get(path) {
            Some(Value::Null) => Ok(Raw {
                present: false,
                bytes: None,
            }),
            Some(Value::String(text)) => Ok(Raw {
                present: true,
                bytes: Some(hex::decode(text).map_err(|_| ERR_INVALID)?),
            }),
            _ => Err(ERR_INVALID),
        },
    }
}

/// The bare tokens of a TOML line outside quoted strings and comments, as
/// byte ranges.
fn bare_tokens(line: &str) -> Vec<(usize, usize)> {
    let mut tokens = Vec::new();
    let mut quote: Option<char> = None;
    let mut escaped = false;
    let mut start: Option<usize> = None;
    for (index, character) in line.char_indices() {
        if let Some(open) = quote {
            if escaped {
                escaped = false;
            } else if character == '\\' && open == '"' {
                escaped = true;
            } else if character == open {
                quote = None;
            }
            continue;
        }
        if character == '"' || character == '\'' {
            if let Some(from) = start.take() {
                tokens.push((from, index));
            }
            quote = Some(character);
        } else if character == '#'
            || character.is_whitespace()
            || matches!(character, ',' | '[' | ']' | '{' | '}' | '=')
        {
            if let Some(from) = start.take() {
                tokens.push((from, index));
            }
            if character == '#' {
                return tokens;
            }
        } else if start.is_none() {
            start = Some(index);
        }
    }
    if let Some(from) = start {
        tokens.push((from, line.len()));
    }
    tokens
}

/// Whether a whole token is a number `tomllib` reads but this parser cannot
/// hold: an integer past 64 bits or a float that overflows.
fn unrepresentable_literal(token: &str) -> bool {
    let cleaned: String = token
        .chars()
        .filter(|character| *character != '_')
        .collect();
    let unsigned = cleaned.strip_prefix(['+', '-']).unwrap_or(&cleaned);
    if unsigned.is_empty() {
        return false;
    }
    for (prefix, radix) in [("0x", 16_u32), ("0o", 8), ("0b", 2)] {
        if let Some(digits) = unsigned.strip_prefix(prefix) {
            return !digits.is_empty()
                && digits.chars().all(|digit| digit.is_digit(radix))
                && i64::from_str_radix(digits, radix).is_err();
        }
    }
    if unsigned.bytes().all(|byte| byte.is_ascii_digit()) {
        return cleaned.parse::<i64>().is_err();
    }
    unsigned.starts_with(|first: char| first.is_ascii_digit())
        && unsigned
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'.' | b'e' | b'E' | b'+' | b'-'))
        && cleaned.parse::<f64>().is_ok_and(f64::is_infinite)
}

/// The text with every unrepresentable number on the line holding `span`
/// replaced by `0`, or `None` when that line has none.
fn without_unrepresentable_numbers(text: &str, span: usize) -> Option<String> {
    let mut span = span.min(text.len());
    while !text.is_char_boundary(span) {
        span -= 1;
    }
    let start = text[..span].rfind('\n').map_or(0, |index| index + 1);
    let end = text[span..]
        .find('\n')
        .map_or(text.len(), |index| span + index);
    let line = &text[start..end];
    let found: Vec<(usize, usize)> = bare_tokens(line)
        .into_iter()
        .filter(|(from, to)| unrepresentable_literal(&line[*from..*to]))
        .collect();
    if found.is_empty() {
        return None;
    }
    let mut repaired = text.to_owned();
    for (from, to) in found.into_iter().rev() {
        repaired.replace_range(start + from..start + to, "0");
    }
    Some(repaired)
}

/// Failing lines patched one at a time before a TOML error stops being read
/// as an unrepresentable number.
const MAX_NUMBER_REPAIRS: usize = 64;

/// `_read_toml`: missing, unreadable or malformed text is an empty table.
///
/// A parse failure is a refusal only when it is the number the parser cannot
/// hold: the text parses once those numbers are replaced. Any other syntax
/// error is a malformed file, which `tomllib` also reports as empty.
pub(super) fn toml_payload(bytes: Option<&[u8]>) -> Result<HookVal, &'static str> {
    let empty = HookVal::Dict(Vec::new());
    let Some(bytes) = bytes else {
        return Ok(empty);
    };
    let text = std::str::from_utf8(bytes).map_err(|_| ERR_TEXT)?;
    // `tomllib` rejects a byte-order mark where this parser skips it.
    if text.starts_with('\u{feff}') {
        return Ok(empty);
    }
    let mut current = std::borrow::Cow::Borrowed(text);
    for repairs in 0..=MAX_NUMBER_REPAIRS {
        match current.parse::<toml_edit::DocumentMut>() {
            Ok(document) if repairs == 0 => {
                return Ok(HookVal::from_document(document.as_table()));
            }
            Ok(_) => return Err(ERR_VALUE),
            Err(error) => {
                let span = error.span().map_or(0, |span| span.start);
                match without_unrepresentable_numbers(&current, span) {
                    Some(repaired) => current = std::borrow::Cow::Owned(repaired),
                    None => return Ok(empty),
                }
            }
        }
    }
    Err(ERR_VALUE)
}

/// `_json_object`: missing, unreadable, not JSON or not an object is `{}`.
pub(super) fn json_payload(bytes: Option<&[u8]>) -> Result<HookVal, &'static str> {
    let empty = HookVal::Dict(Vec::new());
    let Some(bytes) = bytes else {
        return Ok(empty);
    };
    let text = std::str::from_utf8(bytes).map_err(|_| ERR_TEXT)?;
    match parse_marking_lone_surrogates(text) {
        Ok(value @ super::pyjson::PyVal::Dict(_)) => Ok(HookVal::from_py(&value)),
        Ok(_) | Err(JsonFailure::Syntax) => Ok(empty),
        Err(JsonFailure::Unrepresentable | JsonFailure::IntegerLimit | JsonFailure::Duplicate)
            if text.trim_start().starts_with('[') =>
        {
            Ok(empty)
        }
        Err(JsonFailure::Unrepresentable | JsonFailure::IntegerLimit | JsonFailure::Duplicate) => {
            Err(ERR_VALUE)
        }
    }
}

pub(super) fn is_empty(payload: &HookVal) -> bool {
    payload.as_dict().is_none_or(<[_]>::is_empty)
}

/// `_payload_has_hooks_feature_enabled`.
pub(super) fn hooks_feature_enabled(config: &HookVal) -> bool {
    match config.get("features") {
        Some(features @ HookVal::Dict(_)) => features.get("hooks") != Some(&HookVal::Bool(false)),
        _ => true,
    }
}

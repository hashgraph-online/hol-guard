//! The document `hol-guard hook` prints for a harness that reads the
//! daemon's answer as is: `_emit_native_hook_json_document` with
//! `render._redact_payload(command="hook")` and
//! `render._render_redacted_json_payload`. Secrets are masked and local home
//! paths shortened, while the signed approval link the user is meant to open
//! survives byte for byte. The string rules live in
//! `hook_cli_emit_redaction_text`.

use std::sync::OnceLock;

use regex::{Captures, Regex};

use crate::hook_cli_emit_redaction_text::{compiled, redact_text, MASK};
use crate::hook_env_stamp::{dumps, json_string};
use crate::pyjson::PyVal;

/// `_SENSITIVE_KEY_TOKENS`.
const SENSITIVE_KEY_TOKENS: [&str; 6] =
    ["key", "token", "auth", "secret", "password", "credential"];
/// `_NON_SECRET_STRUCTURED_KEYS`.
const NON_SECRET_STRUCTURED_KEY: &str = "oauth_storage_health";
/// `_NON_SECRET_DIAGNOSTIC_KEYS`.
const NON_SECRET_DIAGNOSTIC_KEYS: [&str; 2] = ["authority_error", "authority_error_message"];
/// `_SAFE_POLICY_LITERALS`.
const SAFE_POLICY_LITERALS: [&str; 9] = [
    "allow",
    "warn",
    "review",
    "block",
    "require-reapproval",
    "sandbox-required",
    "strict",
    "balanced",
    "custom",
];
/// The text that stands in for a signed approval fragment while the rest of
/// the answer is redacted. The answer can carry text an agent wrote, so a
/// sentinel is only half the mark: each document also draws a random one,
/// and a sentinel is turned back into a token only when it carries this
/// document's mark.
const SENTINEL_PREFIX: &str = "hgdfrag=efgh";
/// The length, in lowercase hexadecimal characters, of a document's mark.
const SENTINEL_MARK_HEX: usize = 32;
/// The lowercase hexadecimal alphabet a mark is written in.
const MARK_DIGITS: [u8; 16] = *b"0123456789abcdef";

/// The redacted document Python prints for the daemon answer `response`.
/// `home_dir` is the caller's `Path.home()`, `None` when it has none.
/// `unmap` writes a mapped lone surrogate back as its `\udXXX` escape.
pub(crate) fn redacted_hook_document(
    response: &[(String, PyVal)],
    home_dir: Option<&str>,
    unmap: bool,
) -> String {
    let document = PyVal::Dict(response.to_vec());
    let mut tokens = Vec::new();
    // Without a mark a sentinel cannot be told apart from text the answer
    // itself carries, so the approval fragments are left where they are and
    // masked like any other secret rather than printed on an answer's word.
    let mark = document_mark();
    let protected = match mark.as_deref() {
        Some(mark) => protect_approval_tokens(document, mark, &mut tokens),
        None => document,
    };
    let masked = redact_value(protected, None, home_dir);
    let restored = match mark.as_deref() {
        Some(mark) => restore_approval_tokens(masked, mark, &tokens),
        None => masked,
    };
    let mut out = String::new();
    serialize(&restored, 0, unmap, &mut out);
    out
}

/// This document's mark, drawn fresh from the operating system. `None` when
/// the operating system has no entropy to give.
fn document_mark() -> Option<String> {
    let mut entropy = [0u8; SENTINEL_MARK_HEX / 2];
    getrandom::fill(&mut entropy).ok()?;
    let mut mark = String::with_capacity(SENTINEL_MARK_HEX);
    for byte in entropy {
        mark.push(char::from(MARK_DIGITS[usize::from(byte >> 4)]));
        mark.push(char::from(MARK_DIGITS[usize::from(byte & 0x0f)]));
    }
    Some(mark)
}

/// `_protect_ephemeral_approval_tokens`: each signed dashboard fragment, in
/// traversal order, becomes a sentinel that no redaction rule touches.
fn protect_approval_tokens(value: PyVal, mark: &str, tokens: &mut Vec<String>) -> PyVal {
    static TOKEN_URL_VALUE: OnceLock<Regex> = OnceLock::new();
    match value {
        PyVal::Str(text) => {
            let pattern = compiled(&TOKEN_URL_VALUE, || {
                r"guard-token=([A-Za-z0-9._~%+-]+)".to_owned()
            });
            let replaced = pattern.replace_all(&text, |captures: &Captures<'_>| {
                tokens.push(captures[1].to_owned());
                format!("{SENTINEL_PREFIX}{mark}{}", tokens.len() - 1)
            });
            PyVal::Str(replaced.into_owned())
        }
        PyVal::Dict(entries) => PyVal::Dict(
            entries
                .into_iter()
                .map(|(key, item)| (key, protect_approval_tokens(item, mark, tokens)))
                .collect(),
        ),
        PyVal::List(items) => PyVal::List(
            items
                .into_iter()
                .map(|item| protect_approval_tokens(item, mark, tokens))
                .collect(),
        ),
        other => other,
    }
}

/// `_restore_ephemeral_approval_tokens`: a sentinel carrying this document's
/// mark, whose index names a protected fragment, gets that fragment back.
/// Any other sentinel stays exactly as the answer wrote it.
fn restore_approval_tokens(value: PyVal, mark: &str, tokens: &[String]) -> PyVal {
    static SENTINEL: OnceLock<Regex> = OnceLock::new();
    match value {
        PyVal::Str(text) if text.contains(SENTINEL_PREFIX) => {
            let pattern = compiled(&SENTINEL, || {
                format!(r"{SENTINEL_PREFIX}([0-9a-f]{{{SENTINEL_MARK_HEX}}})(\d+)")
            });
            let replaced = pattern.replace_all(&text, |captures: &Captures<'_>| {
                if &captures[1] != mark {
                    return captures[0].to_owned();
                }
                match decimal_index(&captures[2]).and_then(|index| tokens.get(index)) {
                    Some(token) => format!("guard-token={token}"),
                    None => captures[0].to_owned(),
                }
            });
            PyVal::Str(replaced.into_owned())
        }
        PyVal::Dict(entries) => PyVal::Dict(
            entries
                .into_iter()
                .map(|(key, item)| (key, restore_approval_tokens(item, mark, tokens)))
                .collect(),
        ),
        PyVal::List(items) => PyVal::List(
            items
                .into_iter()
                .map(|item| restore_approval_tokens(item, mark, tokens))
                .collect(),
        ),
        other => other,
    }
}

/// Python `int()` of a run of `\d` (Unicode `Nd`) digits; `None` past
/// `usize`, which no protected index reaches.
fn decimal_index(digits: &str) -> Option<usize> {
    digits.chars().try_fold(0usize, |total, digit| {
        total
            .checked_mul(10)?
            .checked_add(decimal_value(digit) as usize)
    })
}

/// The value of one `Nd` digit. Unicode encodes decimal digits only in
/// contiguous runs from zero to nine, so a digit's value is its distance
/// from the start of its run, modulo ten.
fn decimal_value(digit: char) -> u32 {
    static DECIMAL: OnceLock<Regex> = OnceLock::new();
    let decimal = compiled(&DECIMAL, || r"\A\d\z".to_owned());
    let is_decimal = |codepoint: u32| {
        char::from_u32(codepoint)
            .is_some_and(|character| decimal.is_match(character.encode_utf8(&mut [0; 4])))
    };
    let mut start = u32::from(digit);
    while start > 0 && is_decimal(start - 1) {
        start -= 1;
    }
    (u32::from(digit) - start) % 10
}

fn sensitive_key(key: &str) -> bool {
    if key == NON_SECRET_STRUCTURED_KEY || NON_SECRET_DIAGNOSTIC_KEYS.contains(&key) {
        return false;
    }
    let lowered = key.to_lowercase();
    SENSITIVE_KEY_TOKENS
        .iter()
        .any(|token| lowered.contains(token))
}

/// `_redact_payload(value, key=key, command="hook")`.
fn redact_value(value: PyVal, key: Option<&str>, home_dir: Option<&str>) -> PyVal {
    if let Some(key) = key {
        if sensitive_key(key) {
            return match value {
                PyVal::Str(text)
                    if SAFE_POLICY_LITERALS.contains(&text.to_lowercase().as_str()) =>
                {
                    PyVal::Str(text)
                }
                _ => PyVal::Str(MASK.to_owned()),
            };
        }
    }
    match value {
        PyVal::Dict(entries) => PyVal::Dict(
            entries
                .into_iter()
                .map(|(item_key, item)| {
                    let redacted = redact_value(item, Some(&item_key), home_dir);
                    (item_key, redacted)
                })
                .collect(),
        ),
        PyVal::List(items) => PyVal::List(
            items
                .into_iter()
                .map(|item| redact_value(item, None, home_dir))
                .collect(),
        ),
        PyVal::Str(text) => PyVal::Str(redact_text(&text, home_dir)),
        other => other,
    }
}

/// `_serialize_redacted_json`: two-space indentation, `": "` after a key,
/// and `json.dumps` (ASCII only) for every key and scalar.
fn serialize(value: &PyVal, indent: usize, unmap: bool, out: &mut String) {
    let child_indent = indent + 2;
    match value {
        PyVal::Dict(entries) if entries.is_empty() => out.push_str("{}"),
        PyVal::List(items) if items.is_empty() => out.push_str("[]"),
        PyVal::Dict(entries) => {
            out.push_str("{\n");
            for (index, (key, item)) in entries.iter().enumerate() {
                if index > 0 {
                    out.push_str(",\n");
                }
                out.push_str(&" ".repeat(child_indent));
                out.push_str(&json_string(key, true, unmap));
                out.push_str(": ");
                serialize(item, child_indent, unmap, out);
            }
            out.push('\n');
            out.push_str(&" ".repeat(indent));
            out.push('}');
        }
        PyVal::List(items) => {
            out.push_str("[\n");
            for (index, item) in items.iter().enumerate() {
                if index > 0 {
                    out.push_str(",\n");
                }
                out.push_str(&" ".repeat(child_indent));
                serialize(item, child_indent, unmap, out);
            }
            out.push('\n');
            out.push_str(&" ".repeat(indent));
            out.push(']');
        }
        scalar => dumps(scalar, true, unmap, out),
    }
}

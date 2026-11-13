//! Credentials the value screens in `literal_secrets` set aside but that are
//! still unmistakable once their context is read.
//!
//! `looks_random` is cautious on purpose: a value next to a credential name
//! is often an identifier, a phrase or a placeholder. Four shapes carry their
//! own proof instead:
//!
//! - a `user:password` pair handed to `b64encode`, which builds a Basic
//!   credential inline;
//! - a `Basic` header written in any letter case whose base64 decodes to a
//!   `user:password` pair;
//! - a password set by `ALTER USER`, `CREATE USER`, `ALTER ROLE` or
//!   `CREATE ROLE`;
//! - a long, high-entropy value assigned or passed to a credential-named
//!   setting (`SECRET_KEY = '…'`, `setClientSecret("…")`), such as a Django
//!   secret key, padded base64 or 32 or more hex digits.
//!
//! Placeholders and sequential filler are still left alone, and a name that
//! says the value is public, fake or a reference is skipped.

use std::sync::LazyLock;

use regex::Regex;

use super::value::{decode_base64, placeholder, placeholder_within};

fn pattern(source: &str) -> Regex {
    Regex::new(source).expect("strong literal secret pattern compiles")
}

macro_rules! patterns {
    ($($name:ident = $source:expr;)*) => {
        $(static $name: LazyLock<Regex> = LazyLock::new(|| pattern($source));)*
    };
}

patterns! {
    ENCODED_PAIR = r#"b64encode\(\s*b?["'](?P<u>[^"'\s:]{1,64}):(?P<v>[^"'\s]{3,64})["']"#;
    BASIC_ANY_CASE = r"(?i)\bbasic\s+(?P<v>[A-Za-z0-9+/]{8,}={0,2})(?:[^A-Za-z0-9+/=]|$)";
    ROLE_PASSWORD = r#"(?i)\b(?:alter|create)\s+(?:user|role)\b[^;\n]{0,200}?\bpassword\s+["'](?P<v>[^"'\s]{4,64})["']"#;
    NAMED_VALUE = r#"(?i)(?P<k>[A-Za-z0-9_.\-]{0,40}?(?:secret|token|passw(?:or)?d|passwd|api[_-]?key|access[_-]?key|private[_-]?key|verifier|credential)[A-Za-z0-9_]{0,30})["']?\s*(?:=>|[:=(])\s*(?:new\s+\w{1,40}\(\s*)?["'](?P<v>[^"'\s]{16,200})["']"#;
    NOT_A_SECRET_NAME = r"(?i)public|foreign|fake|dummy|example|sample|mock|placeholder|url|cache|expir|limit|type|name|header|field|path|file|count|length|size|_?id$|_len|tokenizer";
    HEX = r"^[0-9a-f]{32,}$|^[0-9A-F]{32,}$";
    PADDED_BASE64 = r"^[A-Za-z0-9+/]{14,}={1,2}$";
    FILLER = r"(?i)\$\{|\{\{|\$\(|%\(|<[^>]*>|x{4,}|\*{3,}|change_?me|example|dummy|fake|placeholder|redacted|your[_\-]?|insert|replace";
    SEQUENTIAL = r"(?i)0123|1234|2345|3456|4567|5678|6789|abcd|bcde|cdef|defg|qwer|asdf";
}

/// Shannon entropy of `value` in bits per character.
fn entropy(value: &str) -> f64 {
    let mut counts = std::collections::HashMap::new();
    let mut total = 0usize;
    for ch in value.chars() {
        *counts.entry(ch).or_insert(0usize) += 1;
        total += 1;
    }
    counts
        .values()
        .map(|&count| {
            let share = count as f64 / total as f64;
            -share * share.log2()
        })
        .sum()
}

/// Whether a value next to a credential name is long and random enough that
/// it cannot be an identifier, phrase or placeholder.
fn strongly_random(raw: &str) -> bool {
    // A YAML or JSON string often carries its newline as a `\n` escape.
    let value = raw.strip_suffix("\\n").unwrap_or(raw);
    // `$NAME` and `%NAME%` read the value from another variable.
    if value.starts_with('$') || (value.starts_with('%') && value.ends_with('%')) {
        return false;
    }
    if value.chars().count() < 16 || FILLER.is_match(value) || SEQUENTIAL.is_match(value) {
        return false;
    }
    let has_lower = value.bytes().any(|byte| byte.is_ascii_lowercase());
    let has_upper = value.bytes().any(|byte| byte.is_ascii_uppercase());
    let has_digit = value.bytes().any(|byte| byte.is_ascii_digit());
    if HEX.is_match(value) {
        return has_digit && (has_lower || has_upper);
    }
    if PADDED_BASE64.is_match(value) {
        return has_lower && has_upper;
    }
    let symbol = value
        .chars()
        .any(|ch| !ch.is_ascii_alphanumeric() && !ch.is_whitespace());
    let kinds = [has_lower, has_upper, has_digit, symbol]
        .iter()
        .filter(|kind| **kind)
        .count();
    kinds >= 3 && entropy(value) >= 3.5
}

fn basic_pair(encoded: &str) -> bool {
    decode_base64(encoded).is_some_and(|text| {
        !text.chars().any(char::is_control)
            && text.split_once(':').is_some_and(|(user, password)| {
                // A pair whose password repeats the user name, such as
                // `guest:guest`, is a well-known default, not a secret.
                !password.is_empty() && password != user && !placeholder(password)
            })
    })
}

/// Whether `text` holds a credential that its context proves real.
pub(super) fn holds_proven_secret(text: &str) -> bool {
    ENCODED_PAIR
        .captures_iter(text)
        .any(|found| found["v"] != found["u"] && !placeholder_within(&found["v"]))
        || BASIC_ANY_CASE
            .captures_iter(text)
            .any(|found| basic_pair(&found["v"]))
        || ROLE_PASSWORD
            .captures_iter(text)
            .any(|found| !placeholder_within(&found["v"]))
        || NAMED_VALUE
            .captures_iter(text)
            .any(|found| !NOT_A_SECRET_NAME.is_match(&found["k"]) && strongly_random(&found["v"]))
}

#[cfg(test)]
#[path = "literal_secret_strong_tests.rs"]
mod tests;

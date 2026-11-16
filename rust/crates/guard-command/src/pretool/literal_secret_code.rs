//! Credentials written as code literals that only the code around them names.
//!
//! The name screens in `literal_secrets` and `literal_secret_bare` read a
//! quoted value next to a credential name. Some credentials are written one
//! step removed from that name, in a shape a credential is the only plausible
//! reading of:
//!
//! - a credential setter handed a wrapped literal,
//!   `setClientSecret(new SecretValue("…"))`, whose value mixes letters and
//!   digits;
//! - a credential setter handed dashed four-character groups of random
//!   lowercase letters and digits, `setToken("qzvt-kmbr-…")`;
//! - a comment that gives an auth token as 64 hex characters;
//! - a `long[]` constant named `…KEY…` that spells key material as hex longs;
//! - an API key name given dashed lowercase groups that mix letters and
//!   digits and read as noise (`MAILGUN_API_KEY = "key-…"`); a UUID-shaped
//!   value is left alone, since sites publish those as embed keys.
//!
//! Placeholders, counting and keyboard runs, hex digests in setters, readable
//! words and `long[]` tables under other names are ordinary code.

use std::sync::LazyLock;

use regex::Regex;

use super::bare::{letters_only, typed_value};
use super::letters::english_score;

fn pattern(source: &str) -> Regex {
    Regex::new(source).expect("code literal secret pattern compiles")
}

macro_rules! patterns {
    ($($name:ident = $source:expr;)*) => {
        $(static $name: LazyLock<Regex> = LazyLock::new(|| pattern($source));)*
    };
}

patterns! {
    WRAPPED_SETTER = r#"\bset\w*(?:Secret|Password|Token)\w*\(\s*new\s+\w+\(\s*["'](?P<v>[A-Za-z0-9]{8,40})["']\s*\)\s*\)"#;
    DASHED_SETTER = r#"\bset\w*(?:Secret|Password|Token)\w*\(\s*["'](?P<v>[a-z0-9]{4}(?:-[a-z0-9]{4}){3,})["']\s*\)"#;
    AUTH_TOKEN_COMMENT = r"(?i)\bauth(?:entication)?[ _-]token\s+[0-9a-f]{64}\b";
    LONG_KEY = r"\blong\[\]\s+\w*KEY\w*\s*=\s*\{\s*(?:-?(?:0x)?[0-9a-fA-F]{12,}L?\s*,\s*)+-?(?:0x)?[0-9a-fA-F]{12,}L?\s*\}";
    DASHED_API_KEY = r#"(?i:["']?\w*api_?key\w*["']?\]?)\s*[:=]\s*["'](?P<v>[a-z0-9]{2,}(?:-[a-z0-9]{3,}){2,})["']"#;
    UUID_TAIL = r"[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$";
    HEX = r"^[0-9a-f]+$";
}

/// Below this mean letter-pair score a token does not read as words.
const RANDOM_TOKEN: i32 = -770;

fn mixed(value: &str) -> bool {
    value.bytes().any(|byte| byte.is_ascii_digit())
        && value.bytes().any(|byte| byte.is_ascii_alphabetic())
}

fn wrapped_value(value: &str) -> bool {
    mixed(value) && !typed_value(value) && !HEX.is_match(&value.to_ascii_lowercase())
}

fn dashed_value(value: &str) -> bool {
    let joined = value.replace('-', "");
    let letters = letters_only(value);
    !HEX.is_match(&joined)
        && letters.len() >= 8
        && !typed_value(value)
        && !typed_value(&joined)
        && english_score(&letters) <= RANDOM_TOKEN
}

fn dashed_api_key(value: &str) -> bool {
    let joined = value.replace('-', "");
    mixed(value)
        && !HEX.is_match(&joined)
        && !UUID_TAIL.is_match(value)
        && !typed_value(value)
        && !typed_value(&joined)
        && english_score(&letters_only(value)) <= RANDOM_TOKEN
}

fn any_value(shape: &Regex, text: &str, keep: fn(&str) -> bool) -> bool {
    shape.captures_iter(text).any(|found| keep(&found["v"]))
}

/// Whether `text` writes a credential as a code literal its surroundings name.
pub(super) fn holds_code_secret(text: &str) -> bool {
    (text.contains("set")
        && (any_value(&WRAPPED_SETTER, text, wrapped_value)
            || any_value(&DASHED_SETTER, text, dashed_value)))
        || AUTH_TOKEN_COMMENT.is_match(text)
        || (text.contains("long[]") && LONG_KEY.is_match(text))
        || any_value(&DASHED_API_KEY, text, dashed_api_key)
}

#[cfg(test)]
#[path = "literal_secret_code_tests.rs"]
mod tests;

//! Credentials written as code literals that only the code around them names.
//!
//! The name screens in `literal_secrets` and `literal_secret_bare` read a
//! quoted value next to a credential name. Some credentials are written one
//! step removed from that name, in a shape a credential is the only plausible
//! reading of:
//!
//! - a credential setter handed a wrapped literal,
//!   `setClientSecret(new SecretValue("…"))`, whose value mixes letters and
//!   digits; the setter name ends in the credential word or in a value
//!   suffix (`setSecretKey`), never a metadata one (`setSecretName`);
//! - a credential setter handed dashed four-character groups of random
//!   lowercase letters and digits, `setToken("qzvt-kmbr-…")`;
//! - a comment that gives an auth token as 64 hex characters;
//! - a `long[]` constant with a `KEY` name segment that spells key material as hex longs;
//! - an API key name given dashed lowercase groups that mix letters and
//!   digits and read as noise (`MAILGUN_API_KEY = "key-…"`); a UUID-shaped
//!   value is left alone, since sites publish those as embed keys.
//!
//! Placeholders, counting and keyboard runs, hex digests in setters, readable
//! words and `long[]` tables under other names are ordinary code.

use std::sync::LazyLock;

use regex::Regex;

use super::bare::{letters_only, metadata_name, typed_value};
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
    WRAPPED_SETTER = r#"\bset\w*(?:Secret|Password|Token)(?:Key|Value|Str|String|Literal|Bytes|Data)?\(\s*new\s+\w+\(\s*["'](?P<v>[A-Za-z0-9]{8,40})["']\s*\)\s*\)"#;
    DASHED_SETTER = r#"\bset\w*(?:Secret|Password|Token)\w*\(\s*["'](?P<v>[a-z0-9]{4}(?:-[a-z0-9]{4}){3,})["']\s*\)"#;
    AUTH_TOKEN_COMMENT = r"(?i)\bauth(?:entication)?[ _-]token\s+(?P<v>[0-9a-f]{64})\b";
    LONG_KEY = r"\blong\[\]\s+(?:\w*_)?KEYS?(?:_\w*)?\s*=\s*\{(?P<v>\s*(?:-?0[xX][0-9a-fA-F]{12,}L?\s*,\s*)+-?0[xX][0-9a-fA-F]{12,}L?\s*,?\s*)\}";
    DASHED_API_KEY = r#"(?i:["']?(?P<n>\w*api_?key\w*)["']?\]?)\s*[:=]\s*["'](?P<v>[a-z0-9]{2,}(?:-[a-z0-9]{3,}){2,})["']"#;
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

fn dashed_api_key(found: &regex::Captures) -> bool {
    let value = &found["v"];
    let joined = value.replace('-', "");
    !metadata_name(&found["n"])
        && !id_list_name(&found["n"])
        && mixed(value)
        && !HEX.is_match(&joined)
        && !UUID_TAIL.is_match(value)
        && !typed_value(value)
        && !typed_value(&joined)
        && english_score(&letters_only(value)) <= RANDOM_TOKEN
}

/// `IDS`, `API_KEY_IDS`, `apiKeyIds`: a list of key IDs, not a key.
fn id_list_name(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    lower == "ids" || lower.ends_with("_ids") || name.ends_with("Ids")
}

fn any_value(shape: &Regex, text: &str, keep: fn(&str) -> bool) -> bool {
    shape.captures_iter(text).any(|found| keep(&found["v"]))
}

/// A value that is one short unit said over and over (`0000…`, `deadbeef…`,
/// `0123…f0123…f`) is filler, not key material.
fn repeated_unit(value: &str) -> bool {
    let bytes = value.as_bytes();
    (1..=bytes.len() / 2).any(|unit| {
        bytes.len() % unit == 0 && bytes.chunks(unit).all(|chunk| chunk == &bytes[..unit])
    })
}

fn auth_token_value(value: &str) -> bool {
    let lower = value.to_ascii_lowercase();
    let distinct = lower
        .bytes()
        .collect::<std::collections::HashSet<_>>()
        .len();
    distinct >= 8 && !repeated_unit(&lower) && !typed_value(&lower)
}

/// Every element of the `long[]` body carries key material, not filler.
fn long_key_body(body: &str) -> bool {
    body.split(',')
        .map(str::trim)
        .filter(|element| !element.is_empty())
        .all(|element| {
            let digits = element
                .trim_start_matches('-')
                .get(2..)
                .unwrap_or_default()
                .trim_end_matches(['L', 'l'])
                .to_ascii_lowercase();
            let distinct = digits
                .bytes()
                .collect::<std::collections::HashSet<_>>()
                .len();
            distinct >= 4 && !repeated_unit(&digits)
        })
}

/// Whether `text` writes a credential as a code literal its surroundings name.
pub(super) fn holds_code_secret(text: &str) -> bool {
    (text.contains("set")
        && (any_value(&WRAPPED_SETTER, text, wrapped_value)
            || any_value(&DASHED_SETTER, text, dashed_value)))
        || any_value(&AUTH_TOKEN_COMMENT, text, auth_token_value)
        || (text.contains("long[]") && any_value(&LONG_KEY, text, long_key_body))
        || DASHED_API_KEY
            .captures_iter(text)
            .any(|found| dashed_api_key(&found))
}

#[cfg(test)]
#[path = "literal_secret_code_tests.rs"]
mod tests;

//! Credentials whose value carries no strong shape of its own.
//!
//! The other screens need either a known prefix, a long random value, or a
//! credential name next to a value that looks random by itself. Some written
//! credentials have none of that, yet the place they sit leaves little doubt:
//!
//! - a list item that is nothing but a random lowercase token, as a list of
//!   app secrets is written (`- qzvtxkmbrwplhsn`);
//! - an `API:` label followed by a short key that mixes letters and digits;
//! - a token, secret or key name assigned a quoted run of nine or ten digits;
//! - an `…_API_…_ID` name assigned a value that mixes letters and digits;
//! - an SQL `IDENTIFIED … AS '…'` clause under a password plugin, which
//!   writes a stored password hash;
//! - a `"secret"` field given a short random lowercase value;
//! - a quoted value of six to eight space-separated four-character groups
//!   that read as noise, the way app passwords and OTP seeds are written;
//! - a `secret` name given random lowercase words joined by underscores;
//! - a `set…Secret/Password/Token("…")` call with a random letter value;
//! - a URL whose password part is random letters and whose host is not local;
//! - a line keyed by a random fifteen-letter name, the shape of an app
//!   secret written as a YAML or Markdown key.
//!
//! Each screen is held to words, counting runs, hex digests and placeholders
//! staying out: `- troubleshooting`, `API: v2`, `max_tokens = "100000000"`,
//! `VOICE_ID = "…"`, `"secret": "changeme"`, `setToken("refreshing")` and
//! `postgres://app:pass@db.company.com` are ordinary text.

use std::sync::LazyLock;

use regex::{Captures, Regex};

use super::letters::english_score;

fn pattern(source: &str) -> Regex {
    Regex::new(source).expect("bare literal secret pattern compiles")
}

macro_rules! patterns {
    ($($name:ident = $source:expr;)*) => {
        $(static $name: LazyLock<Regex> = LazyLock::new(|| pattern($source));)*
    };
}

patterns! {
    LIST_TOKEN = r"(?m)^[ \t]*(?:[-*]|[0-9]+\.)[ \t]+(?P<v>[a-z0-9]{15,32})[ \t\r]*$";
    API_LABEL = r"\bAPI:[ \t]+(?P<v>[A-Za-z0-9]{8,12})\b";
    NUMERIC_NAMED = r#"(?i)\b(?P<n>\w*(?:token|secret|key)\w*)\s*=\s*['"](?P<v>[0-9]{9,10})['"]"#;
    API_ID = r#"\b(?:\w+_)?API_(?:\w+_)?ID\s*=\s*['"](?P<v>[A-Za-z0-9]{8,40})['"]"#;
    SQL_AUTH_STRING = r"(?i)\bIDENTIFIED\s+(?:WITH\s+'?(?P<p>\w+)'?\s+)?AS\s+'(?P<v>[A-Za-z0-9*$./+=]{5,})'";
    SECRET_FIELD = r#"["']secret["']\]?\s*(?:==|[:=])\s*["'](?P<v>[a-z]{6,10})["']"#;
    HEX = r"^[0-9a-f]+$";
    SEQUENTIAL = r"(?i)0123|1234|2345|3456|4567|5678|6789|9876|8765|7654|6543|5432|4321|abcd|bcde|cdef|qwer|asdf";
    WORD_THEN_DIGITS = r"^(?:[A-Za-z]+[0-9]+|[0-9]+[A-Za-z]+)$";
    HASH_PLUGIN = r"(?i)^(?:mysql_native_password|caching_sha2_password|sha256_password|mysql_old_password)$";
    FILLER = r"(?i)x{3,}|\*{3,}|change_?me|example|dummy|fake|placeholder|redacted|password|secret|your";
    SPACED_GROUPS = r#"["'](?P<v>(?:[a-z0-9]{4} ){5,7}[a-z0-9]{4})["']"#;
    SECRET_WORD_GROUPS = r#"(?i)["']?\w*secret\w*["']?\s*[:=]\s*["'](?P<v>[a-z]{3,}(?:_[a-z]{3,}){2,})["']"#;
    SECRET_SETTER = r#"\bset\w*(?:Secret|Password|Token)\w*\(\s*["'](?P<v>[A-Za-z]{8,16})["']\s*\)"#;
    URL_PASSWORD = r#"\b[a-zA-Z][a-zA-Z0-9+.-]*://[^\s/?#"'<>]*:(?P<v>[a-z]{4,})@(?P<h>[A-Za-z0-9.-]+\.[A-Za-z]{2,})"#;
    LOCAL_HOST = r"localhost|127\.|0\.0\.0\.0|\.local$|\.test$|\.invalid$|\.internal$|\.example$|(?:^|\.)example\.(?:com|net|org)$";
    RANDOM_KEY = r"(?m)^\s*(?P<k>[a-z]{15}):\s";
    RANDOM_KEY_VALUE = r"(?m)^[ \t]*(?P<k>[a-z]{15}):[ \t]+(?P<v>[A-Za-z0-9]{8,32})[ \t\r]*$";
    WIDE_FILLER = r"(?i)test|sample|demo|abc|foo|bar|zxcv|hjkl";
}

/// Below this mean letter-pair score a token does not read as words.
const RANDOM_TOKEN: i32 = -770;
/// A short field value needs a stronger signal: fewer pairs, more noise.
const RANDOM_SHORT_VALUE: i32 = -750;
/// A fifteen-letter key next to a mixed value may read a little more like
/// words; the value carries the rest of the signal.
const RANDOM_KEY_NAME: i32 = -700;

fn count(value: &str, test: fn(&u8) -> bool) -> usize {
    value.bytes().filter(test).count()
}

fn vowel_share(value: &str) -> f64 {
    let letters = count(value, u8::is_ascii_alphabetic);
    let vowels = value
        .bytes()
        .filter(|byte| b"aeiouy".contains(byte))
        .count();
    vowels as f64 / letters.max(1) as f64
}

fn random_list_token(value: &str) -> bool {
    !HEX.is_match(value)
        && !FILLER.is_match(value)
        && count(value, u8::is_ascii_alphabetic) >= 10
        && english_score(value) <= RANDOM_TOKEN
        && vowel_share(value) <= 0.40
}

fn mixed_key(value: &str) -> bool {
    count(value, u8::is_ascii_digit) >= 2
        && count(value, u8::is_ascii_alphabetic) >= 3
        && !SEQUENTIAL.is_match(value)
        && !WORD_THEN_DIGITS.is_match(value)
        && !HEX.is_match(&value.to_ascii_lowercase())
        && !FILLER.is_match(value)
}

/// Unix seconds from 2001 to 2033 are ten digits that start with `1`.
fn timestamp_like(value: &str) -> bool {
    value.len() == 10 && value.starts_with('1')
}

fn digit_secret(value: &str) -> bool {
    let distinct = value
        .bytes()
        .collect::<std::collections::HashSet<_>>()
        .len();
    !SEQUENTIAL.is_match(value) && distinct >= 5 && !timestamp_like(value)
}

/// Recognize metadata from whole snake_case/camelCase name segments, not
/// substrings of credential names (account, admin, support, runtime).
fn metadata_segment(segment: &str) -> bool {
    let lower = segment.to_ascii_lowercase();
    lower.starts_with("expir")
        || matches!(
            lower.as_str(),
            "ttl"
                | "time"
                | "timestamp"
                | "stamp"
                | "issued"
                | "created"
                | "updated"
                | "max"
                | "min"
                | "limit"
                | "count"
                | "size"
                | "len"
                | "length"
                | "version"
                | "index"
                | "port"
        )
}

pub(super) fn metadata_name(name: &str) -> bool {
    let mut start = 0;
    let mut previous: Option<char> = None;
    for (index, current) in name.char_indices() {
        let boundary = current == '_'
            || (current.is_ascii_uppercase()
                && previous.is_some_and(|c| c.is_ascii_lowercase() || c.is_ascii_digit()));
        if boundary {
            if start < index && metadata_segment(&name[start..index]) {
                return true;
            }
            start = if current == '_' { index + 1 } else { index };
        }
        previous = Some(current);
    }
    let last = &name[start..];
    metadata_segment(last) || last.eq_ignore_ascii_case("at") || last.eq_ignore_ascii_case("id")
}

fn named_digit_secret(found: &Captures) -> bool {
    !metadata_name(&found["n"]) && digit_secret(&found["v"])
}

fn api_id(value: &str) -> bool {
    value.bytes().any(|byte| byte.is_ascii_digit())
        && value.bytes().any(|byte| byte.is_ascii_alphabetic())
        && !SEQUENTIAL.is_match(value)
        && !WORD_THEN_DIGITS.is_match(value)
        && !HEX.is_match(&value.to_ascii_lowercase())
        && !FILLER.is_match(value)
}

fn auth_string(value: &str) -> bool {
    !SEQUENTIAL.is_match(value) && !FILLER.is_match(value)
}

/// Only password plugins store a hash after `AS`; `auth_socket` and the
/// directory plugins name an operating-system user or a directory entry.
fn hashed_auth_string(found: &Captures) -> bool {
    found
        .name("p")
        .is_none_or(|plugin| HASH_PLUGIN.is_match(plugin.as_str()))
        && auth_string(&found["v"])
}

fn short_secret(value: &str) -> bool {
    !FILLER.is_match(value) && english_score(value) <= RANDOM_SHORT_VALUE
}

fn any_value(shape: &Regex, text: &str, keep: fn(&str) -> bool) -> bool {
    shape.captures_iter(text).any(|found| keep(&found["v"]))
}

/// A key a template or a person would type: a placeholder, a counting or
/// keyboard run, or a test word.
pub(super) fn typed_value(value: &str) -> bool {
    FILLER.is_match(value) || WIDE_FILLER.is_match(value) || SEQUENTIAL.is_match(value)
}

pub(super) fn letters_only(value: &str) -> String {
    value.chars().filter(char::is_ascii_alphabetic).collect()
}

fn random_letters(value: &str, cut: i32) -> bool {
    english_score(&letters_only(value)) <= cut
}

/// Placeholders and keyboard runs are checked on the joined value too, so a
/// run split across groups (`cvzx cvzx …`) still reads as typed; a value
/// that repeats one group is a sample, not a generated password.
fn spaced_groups(value: &str) -> bool {
    let joined = value.replace(' ', "");
    let letters = letters_only(value);
    let groups = value.split(' ').collect::<Vec<_>>();
    let distinct = groups
        .iter()
        .collect::<std::collections::HashSet<_>>()
        .len();
    !HEX.is_match(&joined)
        && letters.len() >= 16
        && distinct == groups.len()
        && !typed_value(value)
        && !typed_value(&joined)
        && english_score(&letters) <= RANDOM_TOKEN
}

fn random_word_value(value: &str) -> bool {
    !typed_value(value) && random_letters(value, RANDOM_TOKEN)
}

/// A URL password counts only off a local or documentation host.
fn url_password(found: &Captures) -> bool {
    !LOCAL_HOST.is_match(&found["h"].to_ascii_lowercase()) && random_word_value(&found["v"])
}

fn random_key(found: &Captures) -> bool {
    let key = &found["k"];
    !typed_value(key) && english_score(key) <= RANDOM_TOKEN && vowel_share(key) <= 0.40
}

/// A slightly word-like key still marks a secret when its value mixes
/// letters and digits the way a generated key does.
fn random_key_with_mixed_value(found: &Captures) -> bool {
    let (key, value) = (&found["k"], &found["v"]);
    !typed_value(key)
        && english_score(key) <= RANDOM_KEY_NAME
        && value.bytes().any(|byte| byte.is_ascii_digit())
        && value.bytes().any(|byte| byte.is_ascii_alphabetic())
        && !typed_value(value)
        && !HEX.is_match(&value.to_ascii_lowercase())
}

fn holds_shaped_secret(text: &str) -> bool {
    (text.contains(' ') && any_value(&SPACED_GROUPS, text, spaced_groups))
        || any_value(&SECRET_WORD_GROUPS, text, random_word_value)
        || (text.contains("set") && any_value(&SECRET_SETTER, text, random_word_value))
        || (text.contains("://") && URL_PASSWORD.captures_iter(text).any(|f| url_password(&f)))
        || RANDOM_KEY
            .captures_iter(text)
            .any(|found| random_key(&found))
        || RANDOM_KEY_VALUE
            .captures_iter(text)
            .any(|found| random_key_with_mixed_value(&found))
}

/// Whether `text` writes a credential that only its surroundings identify.
pub(super) fn holds_bare_secret(text: &str) -> bool {
    any_value(&LIST_TOKEN, text, random_list_token)
        || (text.contains("API:") && any_value(&API_LABEL, text, mixed_key))
        || NUMERIC_NAMED
            .captures_iter(text)
            .any(|found| named_digit_secret(&found))
        || (text.contains("API_") && any_value(&API_ID, text, api_id))
        || SQL_AUTH_STRING
            .captures_iter(text)
            .any(|found| hashed_auth_string(&found))
        || (text.contains("secret") && any_value(&SECRET_FIELD, text, short_secret))
        || holds_shaped_secret(text)
}

#[cfg(test)]
#[path = "literal_secret_bare_tests.rs"]
mod tests;

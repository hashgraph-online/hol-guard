//! Whether a value written next to a credential name looks like a real secret.
//!
//! A real key, token or password is random: hex, mixed-case letters and
//! digits, base32, or letters that follow no English spelling. What sits next
//! to a credential name in ordinary code is usually not: an identifier, a
//! dotted reference, a function call, a placeholder, a date, a snake_case
//! phrase or an English word. The checks below set those shapes aside first
//! and then look for randomness, scoring letter runs against English letter
//! pairs so that `qeyjjicm` counts as random and `postgres` does not.

use std::sync::LazyLock;

use base64::engine::{general_purpose::GeneralPurpose, DecodePaddingMode, GeneralPurposeConfig};
use base64::{alphabet, Engine};
use regex::Regex;

use super::pairs::PAIRS;

fn pattern(source: &str) -> Regex {
    Regex::new(source).expect("literal secret value pattern compiles")
}

macro_rules! patterns {
    ($($name:ident = $source:expr;)*) => {
        $(static $name: LazyLock<Regex> = LazyLock::new(|| pattern($source));)*
    };
}

patterns! {
    VENDOR_PREFIX = r"^(?:glsa_[A-Za-z0-9]{20,}|glc_[A-Za-z0-9+/=]{20,}|key-[a-z0-9]{32}|AKIA[A-Z0-9]{16}|gh[pousr]_[A-Za-z0-9]{30,}|xox[abposr]-[A-Za-z0-9\-]{10,}|AIza[0-9A-Za-z_\-]{30,}|ya29\.[0-9A-Za-z_\-]{20,}|sk-[A-Za-z0-9]{20,})";
    PLACEHOLDER = r"(?i)^(?:x+|\*+|\.+|<.*>|\{.*\}|\$.*|%.*%|changeme|change_me|password|secret|token|example|sample|test|dummy|fake|null|none|true|false|undefined|your.*|my.*|xxx.*)$";
    PLACEHOLDER_PART = r"(?i)pass|secret|pwd|xxx|\*\*|\$|\{|example|changeme|test|demo|admin|user";
    COMMON_PART = r"(?i)pass|test|admin|demo|user|secret";
    SHORT_BASE64 = r"^[A-Za-z0-9+/]{8,16}={0,2}$";
    LOWER_TEXT = r"^[a-z ]+\n?$";
    PUNCTUATION = r"[&\[\]]";
    PERCENT_SYNTAX = r"%(?:[0-9A-Fa-f]{2}|[({]|[-+ #0-9.]*[sdifuxXoeEgGcr]|\w+%)";
    MEMBER_REFERENCE = r"^[A-Za-z0-9_]+\.[A-Z][A-Za-z]+$";
    BASE32 = r"^[A-Z2-7]{16,}$";
    UPPER_LETTERS = r"^[A-Z]{20,}$";
    UPPER_CONSONANTS = r"[BCDFGHJKLMNPQRSTVWXZ]+";
    WORD = r"^[A-Z]?[a-z]{6,}$";
    PATHLIKE = r"[:/\\]";
    LONG_BASE64 = r"^[A-Za-z0-9+/=]{20,}$";
    CONSTANT_NAME = r"^[A-Z][A-Z0-9_]*$";
    HEX_NUMBER = r"^-?0x[0-9a-fA-F]+$";
    TIMESTAMP = r"^[0-9TZ:\-.]+$";
    LETTERS = r"^[A-Za-z]+$";
    CASE_TURN = r"[a-z][A-Z]|[A-Z]{2}[a-z]";
    TITLE_WORDS = r"^(?:[A-Z][a-z]+|[A-Z]+|[0-9]+|v[0-9]+)+$";
    CAMEL = r"^[a-z]+(?:[A-Z][a-z0-9]*)+$";
    OPERATORS = r"[|&?!=]{2}|\.\w+\(|\|\|";
    DIGITS = r"^[0-9]+$";
    URL = r"^(?:https?|file)://";
    CALL = r"^[A-Za-z_][A-Za-z0-9_]*\([^)]*\)?$";
    PASCAL = r"^(?:[A-Z][a-z]+)+$";
    DOTTED = r"^[A-Za-z_][A-Za-z0-9_.]*$";
    SNAKE_WORDS = r"^[a-z]+(?:[_\-](?:[a-z]+|[0-9]{1,4}))+$";
    HEX_WORD_TAIL = r"^[0-9a-f]{20,}[a-f]*[g-z][a-z]{2,7}$";
    HEX = r"^[0-9a-fA-F\-]+$";
    LOWER_DIGITS = r"^[a-z]{5,}[0-9]{2,4}$";
    CONSONANTS = r"[bcdfghjklmnpqrstvwxz]+";
}

/// Mean English letter-pair log frequency of `letters` (lowercase `a`..`z`),
/// counting the start and end of the word. Words score near -2.5; random
/// letters fall below -3.9.
pub(super) fn pair_score(letters: &str) -> f64 {
    let bytes = letters.as_bytes();
    if bytes.is_empty() {
        return 0.0;
    }
    let mut total = 0_i64;
    let mut previous = 0_usize;
    for byte in bytes {
        let next = usize::from(byte - b'a');
        total += i64::from(PAIRS[previous][next]);
        previous = next + 1;
    }
    total += i64::from(PAIRS[previous][26]);
    total as f64 / 1000.0 / (bytes.len() + 1) as f64
}

fn random_letters(letters: &str, minimum: usize) -> bool {
    letters.len() >= minimum && pair_score(letters) < -3.9
}

fn distinct(letters: &str) -> usize {
    let mut seen = [false; 26];
    letters
        .bytes()
        .for_each(|byte| seen[usize::from(byte - b'a')] = true);
    seen.iter().filter(|present| **present).count()
}

fn lower_letters(value: &str) -> String {
    value
        .to_lowercase()
        .chars()
        .filter(char::is_ascii_lowercase)
        .collect()
}

/// Splits `value` into case chunks the way `[A-Z]+(?![a-z])|[A-Z]?[a-z]+`
/// does (with digits joining lowercase runs when `digits` is set).
fn case_chunks(value: &str, digits: bool) -> Vec<&str> {
    let bytes = value.as_bytes();
    let lower = |byte: u8| byte.is_ascii_lowercase() || (digits && byte.is_ascii_digit());
    let mut chunks = Vec::new();
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index].is_ascii_uppercase() {
            let mut end = index;
            while end < bytes.len() && bytes[end].is_ascii_uppercase() {
                end += 1;
            }
            if end < bytes.len() && bytes[end].is_ascii_lowercase() {
                if end - index >= 2 {
                    chunks.push(&value[index..end - 1]);
                }
                let start = end - 1;
                let mut stop = end;
                while stop < bytes.len() && lower(bytes[stop]) {
                    stop += 1;
                }
                chunks.push(&value[start..stop]);
                index = stop;
            } else {
                chunks.push(&value[index..end]);
                index = end;
            }
        } else if lower(bytes[index]) {
            let mut stop = index;
            while stop < bytes.len() && lower(bytes[stop]) {
                stop += 1;
            }
            chunks.push(&value[index..stop]);
            index = stop;
        } else {
            index += 1;
        }
    }
    chunks
}

fn has_word_chunk(value: &str) -> bool {
    case_chunks(value, false)
        .iter()
        .any(|chunk| chunk.len() >= 4 && pair_score(&chunk.to_ascii_lowercase()) > -3.0)
}

/// A GitHub token whose last six characters are not the CRC32 of its body is
/// a made-up example, not a token GitHub issued.
fn github_checksum_fails(value: &str) -> bool {
    let bytes = value.as_bytes();
    let shaped = bytes.len() == 40
        && value.starts_with("gh")
        && matches!(bytes[2], b'p' | b'o' | b'u' | b's' | b'r')
        && bytes[3] == b'_'
        && bytes[4..].iter().all(u8::is_ascii_alphanumeric);
    if !shaped {
        return false;
    }
    const DIGITS: &[u8] = b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
    let mut crc = !0_u32;
    for byte in &bytes[4..34] {
        crc ^= u32::from(*byte);
        for _ in 0..8 {
            crc = if crc & 1 == 1 {
                (crc >> 1) ^ 0xEDB8_8320
            } else {
                crc >> 1
            };
        }
    }
    let mut number = !crc;
    let mut encoded = [b'0'; 6];
    for slot in encoded.iter_mut().rev() {
        *slot = DIGITS[(number % 62) as usize];
        number /= 62;
    }
    encoded != bytes[34..40]
}

/// Decodes base64 text as UTF-8, accepting missing or extra padding.
pub(super) fn decode_base64(encoded: &str) -> Option<String> {
    static LENIENT: LazyLock<GeneralPurpose> = LazyLock::new(|| {
        GeneralPurpose::new(
            &alphabet::STANDARD,
            GeneralPurposeConfig::new()
                .with_decode_padding_mode(DecodePaddingMode::RequireNone)
                .with_decode_allow_trailing_bits(true),
        )
    });
    let bytes = LENIENT.decode(encoded.trim_end_matches('=')).ok()?;
    String::from_utf8(bytes).ok()
}

/// Base64 of a short lowercase phrase (`aGVsbG8K` is `hello`), as written in
/// sample configuration.
fn encodes_plain_text(value: &str) -> bool {
    if !SHORT_BASE64.is_match(value) || value.len() % 4 != 0 {
        return false;
    }
    decode_base64(value).is_some_and(|text| LOWER_TEXT.is_match(&text))
}

fn sequential(value: &str) -> bool {
    let lower = value.to_lowercase();
    ["abcdefgh", "01234567", "qwertyui", "abcd1234"]
        .iter()
        .any(|run| lower.contains(run))
}

/// Whether the text placed where a secret goes is only a placeholder.
pub(super) fn placeholder(value: &str) -> bool {
    PLACEHOLDER.is_match(value) || PLACEHOLDER_PART.is_match(value)
}

/// Whether a password written into a URL is a placeholder: a whole
/// placeholder, or one built from placeholder words (`testpass`,
/// `password123`) whose remainder is not random. A random password that only
/// happens to hold such a word (`Xk9test2Qm7LpR4`) is not.
pub(super) fn placeholder_within(value: &str) -> bool {
    if PLACEHOLDER.is_match(value) {
        return true;
    }
    if !PLACEHOLDER_PART.is_match(value) {
        return false;
    }
    let rest = PLACEHOLDER_PART.replace_all(value, "");
    let mixed = rest.chars().count() >= 8
        && rest.bytes().any(|byte| byte.is_ascii_digit())
        && rest.bytes().any(|byte| byte.is_ascii_uppercase())
        && rest.bytes().any(|byte| byte.is_ascii_lowercase());
    !(mixed || looks_random(&rest))
}

/// Whether `value` looks like a real, randomly generated secret.
pub(super) fn looks_random(value: &str) -> bool {
    if github_checksum_fails(value) || encodes_plain_text(value) || value.contains("EXAMPLE") {
        return false;
    }
    if VENDOR_PREFIX.is_match(value) {
        return true;
    }
    if PUNCTUATION.is_match(value)
        || PERCENT_SYNTAX.is_match(value)
        || value.starts_with('.')
        || MEMBER_REFERENCE.is_match(value)
    {
        return false;
    }
    let base32 = BASE32.is_match(value) && value.bytes().any(|byte| (b'2'..=b'7').contains(&byte));
    let upper_noise = UPPER_LETTERS.is_match(value)
        && UPPER_CONSONANTS
            .find_iter(value)
            .any(|run| run.as_str().len() >= 4);
    if base32 || upper_noise {
        return true;
    }
    if sequential(value) {
        return false;
    }
    if WORD.is_match(value) {
        let lower = value.to_ascii_lowercase();
        if distinct(&lower) >= 5 && random_letters(&lower, 6) {
            return true;
        }
    }
    if PATHLIKE.is_match(value) && !LONG_BASE64.is_match(value) {
        return false;
    }
    if (CONSTANT_NAME.is_match(value) && value.contains('_'))
        || HEX_NUMBER.is_match(value)
        || TIMESTAMP.is_match(value)
    {
        return false;
    }
    let length = value.chars().count();
    if length >= 10
        && LETTERS.is_match(value)
        && CASE_TURN.find_iter(value).count() >= 2
        && !has_word_chunk(value)
        && random_letters(&value.to_ascii_lowercase(), 6)
    {
        return true;
    }
    let has_lower = value.bytes().any(|byte| byte.is_ascii_lowercase());
    let has_digit = value.bytes().any(|byte| byte.is_ascii_digit());
    if TITLE_WORDS.is_match(value) && (has_lower || !has_digit || length < 10) {
        return false;
    }
    if CAMEL.is_match(value) {
        let chunks = case_chunks(value, true);
        let mean =
            chunks.iter().map(|chunk| chunk.len()).sum::<usize>() as f64 / chunks.len() as f64;
        return (length >= 12 && mean < 3.0)
            || (!has_word_chunk(value) && random_letters(&lower_letters(value), 6));
    }
    if OPERATORS.is_match(value)
        || DIGITS.is_match(value)
        || value.chars().any(char::is_whitespace)
        || PLACEHOLDER.is_match(value)
        || URL.is_match(value)
        || CALL.is_match(value)
        || PASCAL.is_match(value)
        || (value.contains('.') && DOTTED.is_match(value) && !has_digit)
    {
        return false;
    }
    if SNAKE_WORDS.is_match(value) && value.split(['_', '-']).all(|part| part.len() < 13) {
        return false;
    }
    if HEX_WORD_TAIL.is_match(value)
        && value
            .bytes()
            .filter(|byte| (b'g'..=b'z').contains(byte))
            .count()
            <= 3
    {
        return false;
    }
    let has_upper = value.bytes().any(|byte| byte.is_ascii_uppercase());
    let has_hex_letter = value
        .bytes()
        .any(|byte| byte.is_ascii_hexdigit() && byte.is_ascii_alphabetic());
    if length >= 16 && HEX.is_match(value) && has_digit && has_hex_letter {
        return true;
    }
    let classes = usize::from(has_lower) + usize::from(has_upper) + usize::from(has_digit);
    if length >= 8 && classes >= 3 && !COMMON_PART.is_match(value) {
        return true;
    }
    let letters = lower_letters(value);
    if distinct(&letters) >= 5 && random_letters(&letters, 6) {
        return true;
    }
    if LOWER_DIGITS.is_match(value) && distinct(&letters) >= 4 && random_letters(&letters, 5) {
        return true;
    }
    if letters.len() >= 6 {
        let run = CONSONANTS
            .find_iter(&letters)
            .map(|found| found.as_str().len())
            .max()
            .unwrap_or(0);
        let vowels = letters
            .bytes()
            .filter(|byte| b"aeiouy".contains(byte))
            .count();
        let sparse = (vowels as f64) / (letters.len() as f64) < 0.2;
        if (run >= 4 || sparse) && pair_score(&letters) < -3.0 {
            return true;
        }
    }
    if length >= 10 && classes >= 2 && has_digit && (has_lower || has_upper) {
        let ratio = value.bytes().filter(u8::is_ascii_digit).count() as f64 / length as f64;
        if ratio > 0.15 && ratio < 0.85 {
            return true;
        }
    }
    false
}

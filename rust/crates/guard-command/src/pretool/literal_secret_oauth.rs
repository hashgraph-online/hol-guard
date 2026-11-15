//! OAuth 1.0 credentials and inline cipher keys written into a file.
//!
//! The name screens in `literal_secrets` read a value next to a credential
//! name and keep only one that looks random by itself. OAuth 1.0 values are
//! often short or percent-encoded, so they fall below that bar even though
//! their context leaves no doubt about what they are. Three shapes carry
//! that proof:
//!
//! - a quoted value given to an OAuth 1.0 credential parameter
//!   (`oauth_token="…"`, `"oauth_consumer_key": "…"`,
//!   `put("oauth_signature", "…")`) that mixes letters with digits or
//!   percent escapes;
//! - an OAuth 1.0 signature base string (`GET&https%3A%2F%2F…&…`) that
//!   carries a consumer key, token, nonce, verifier or signature value;
//! - a literal key handed to `new SecretKeySpec("…")`.
//!
//! `oauth_signature_method`, `oauth_timestamp`, `oauth_callback` and
//! `oauth_version` are not credentials and are never read. Interpolated,
//! templated and placeholder values are left alone.

use std::sync::LazyLock;

use regex::Regex;

use super::value::{entropy, placeholder_within};

fn pattern(source: &str) -> Regex {
    Regex::new(source).expect("oauth literal secret pattern compiles")
}

macro_rules! patterns {
    ($($name:ident = $source:expr;)*) => {
        $(static $name: LazyLock<Regex> = LazyLock::new(|| pattern($source));)*
    };
}

patterns! {
    // `\b` after the name keeps `oauth_signature_method` and
    // `oauth_token_url` out: `_` is a word character.
    PARAMETER = r#"\boauth_(?:signature|token|token_secret|nonce|consumer_key|consumer_secret|verifier)\b\\?["']?\s*(?:=>|[=:,])\s*\\?["'](?P<v>[^"'\\\s]{8,200})"#;
    BASE_STRING = r"\b(?:GET|POST|PUT|PATCH|DELETE|HEAD)&https?%3A%2F%2F[A-Za-z0-9._~%\-]+&";
    BASE_PARAMETER = r"oauth_(?:signature|token|nonce|consumer_key|verifier)%3D(?P<v>(?:[A-Za-z0-9._~\-]|%25[0-9A-Fa-f]{2}){8,200})";
    CIPHER_KEY = r#"\bnew\s+SecretKeySpec\(\s*"(?P<v>[^"\\\s]{12,200})""#;
    ESCAPE = r"%(?:25)?[0-9A-Fa-f]{2}";
    FILLER = r"(?i)\$\{|\{\{|#\{|%[sd]\b|<[^>]*>|x{4,}|\*{3,}|change_?me|example|dummy|fake|placeholder|redacted|your[_\-]?|insert|replace|\.\.\.";
    VALUE_CHARACTERS = r"^[A-Za-z0-9%+/=_.~\-]+$";
    WORD_THEN_DIGITS = r"^(?:[A-Za-z]+[0-9]+|[0-9]+[A-Za-z]+)$";
    SEQUENTIAL = r"(?i)0123|1234|2345|3456|4567|5678|6789|abcd|bcde|cdef|qwer|asdf";
}

/// Whether a quoted OAuth parameter value is a credential rather than a
/// word, a template or a placeholder. The whole quoted value is read, so an
/// interpolation anywhere inside it keeps the value out.
fn parameter_value(raw: &str) -> bool {
    if FILLER.is_match(raw) || placeholder_within(raw) || !VALUE_CHARACTERS.is_match(raw) {
        return false;
    }
    let encoded = ESCAPE.is_match(raw);
    let value = ESCAPE.replace_all(raw, "");
    let length = value.chars().count();
    if length < 8 {
        return false;
    }
    // A short value needs letters and digits interleaved: `token123` or
    // `abc12345` is a word or a counting run, not a credential.
    if length < 12 && (SEQUENTIAL.is_match(&value) || WORD_THEN_DIGITS.is_match(&value)) {
        return false;
    }
    let lower = value.bytes().any(|byte| byte.is_ascii_lowercase());
    let upper = value.bytes().any(|byte| byte.is_ascii_uppercase());
    let digit = value.bytes().any(|byte| byte.is_ascii_digit());
    // Letters alone pass only when the value is long, or percent-encoded as
    // a signed value is; a camel-case word such as `AccessTokenValue` is
    // neither.
    let mixed = (digit && (lower || upper)) || (lower && upper && (length >= 20 || encoded));
    mixed && entropy(&value) >= 3.0
}

/// Whether a value inside a signature base string is filled in. The base
/// string itself proves the value is a signing input, so a run of digits (a
/// nonce) or letters (a consumer key) counts as long as it is not filler.
fn base_value(value: &str) -> bool {
    let distinct = value
        .chars()
        .collect::<std::collections::HashSet<_>>()
        .len();
    !FILLER.is_match(value) && distinct >= 6
}

fn cipher_key(value: &str) -> bool {
    !FILLER.is_match(value)
        && !SEQUENTIAL.is_match(value)
        && !placeholder_within(value)
        && entropy(value) >= 3.5
}

/// Whether `text` writes an OAuth 1.0 credential or an inline cipher key.
pub(super) fn holds_oauth_credential(text: &str) -> bool {
    if !text.contains("oauth_") && !text.contains("SecretKeySpec") {
        return false;
    }
    PARAMETER
        .captures_iter(text)
        .any(|found| parameter_value(&found["v"]))
        || (BASE_STRING.is_match(text)
            && BASE_PARAMETER
                .captures_iter(text)
                .any(|found| base_value(&found["v"])))
        || CIPHER_KEY
            .captures_iter(text)
            .any(|found| cipher_key(&found["v"]))
}

#[cfg(test)]
#[path = "literal_secret_oauth_tests.rs"]
mod tests;

//! Secret-shaped values in the path, query or fragment of a fetched URL.
//!
//! A GET to an arbitrary public host can carry data out in the request line,
//! so a URL that holds a known credential shape (the redaction patterns), a
//! JWT, or a long opaque token keeps the normal review.

use std::sync::LazyLock;

use regex::Regex;

static JWT_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]*").unwrap()
});

/// Shortest run of token characters treated as an opaque blob.
const MIN_BLOB_CHARS: usize = 40;

pub(super) fn carries_secret(url: &url::Url) -> bool {
    let mut tail = url.path().to_owned();
    for part in [url.query(), url.fragment()].into_iter().flatten() {
        tail.push('?');
        tail.push_str(part);
    }
    text_carries_secret(&tail)
}

/// Whether `text` holds a known credential shape (the redaction patterns),
/// a JWT, a PEM block or a long opaque token. Text a command sends to a
/// remote service, such as a posted comment, is scanned the same way.
pub(in crate::pretool) fn text_carries_secret(text: &str) -> bool {
    text.contains("-----BEGIN")
        || crate::redacted_command_tokens::redact_text(text).count > 0
        || JWT_RE.is_match(text)
        || text
            .split(|c: char| !(c.is_ascii_alphanumeric() || matches!(c, '+' | '-' | '_')))
            .any(opaque_blob)
}

/// A long hex run, or a long base64 run mixing digits with both letter cases.
/// Readable slugs (`how-to-deploy-in-2024-...`) are separated by many `-` or
/// `_` characters, which random base64url output rarely produces.
fn opaque_blob(token: &str) -> bool {
    if token.len() < MIN_BLOB_CHARS {
        return false;
    }
    if token.chars().all(|c| c.is_ascii_hexdigit()) {
        return true;
    }
    let separators = token.chars().filter(|c| matches!(c, '-' | '_')).count();
    token.chars().any(|c| c.is_ascii_digit())
        && token.chars().any(|c| c.is_ascii_uppercase())
        && token.chars().any(|c| c.is_ascii_lowercase())
        && separators * 10 < token.len()
}

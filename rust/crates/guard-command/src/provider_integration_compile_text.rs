//! Literal text rules for provider integration manifests. Each rule is checked here without a regex
//! engine, so a manifest is held to the same rules whether or not a schema validator ran first.

use crate::output_endpoint_lure::SHARED_HOSTING;

/// Suffixes of local, private or reserved namespaces. A provider endpoint never lives under one.
const LOCAL_SUFFIXES: &[&str] = &[
    "localhost",
    "local",
    "internal",
    "lan",
    "home",
    "home.arpa",
    "localdomain",
    "intranet",
    "corp",
    "private",
    "test",
    "invalid",
    "onion",
    "arpa",
];

/// Header names a credential may never be placed in: transport and framing headers the client
/// sets itself, headers that carry the user's own identity, and browser-reserved prefixes.
const FORBIDDEN_HEADERS: &[&str] = &[
    "host",
    "content-length",
    "content-type",
    "content-encoding",
    "transfer-encoding",
    "connection",
    "keep-alive",
    "upgrade",
    "te",
    "trailer",
    "expect",
    "cookie",
    "set-cookie",
    "user-agent",
    "accept",
    "accept-encoding",
    "origin",
    "referer",
    "forwarded",
    "via",
];
const FORBIDDEN_HEADER_PREFIXES: &[&str] = &["proxy-", "sec-", "x-forwarded-"];

fn is_lower_alnum(byte: u8) -> bool {
    byte.is_ascii_lowercase() || byte.is_ascii_digit()
}

fn is_dns_label(label: &str) -> bool {
    let bytes = label.as_bytes();
    !bytes.is_empty()
        && bytes.len() <= 63
        && is_lower_alnum(bytes[0])
        && is_lower_alnum(bytes[bytes.len() - 1])
        && bytes
            .iter()
            .all(|&byte| is_lower_alnum(byte) || byte == b'-')
}

fn has_suffix(host: &str, suffix: &str) -> bool {
    host == suffix
        || host
            .strip_suffix(suffix)
            .is_some_and(|rest| rest.ends_with('.'))
}

/// An exact public HTTPS host name: lowercase DNS labels, at least two of them, a top-level label
/// that starts with a letter (so no IP literal in any spelling), no wildcard, no port, nothing
/// under a local or reserved suffix and nothing under a shared-hosting domain.
pub(super) fn is_endpoint_host(host: &str) -> bool {
    let labels: Vec<&str> = host.split('.').collect();
    host.len() <= 253
        && labels.len() >= 2
        && labels.iter().all(|label| is_dns_label(label))
        && labels
            .last()
            .is_some_and(|tld| tld.as_bytes()[0].is_ascii_lowercase())
        && !LOCAL_SUFFIXES.iter().any(|suffix| has_suffix(host, suffix))
        && !SHARED_HOSTING.iter().any(|suffix| has_suffix(host, suffix))
}

/// `^[a-z0-9][a-z0-9-]{0,63}$`, and not a header the client owns.
pub(super) fn is_credential_header(name: &str) -> bool {
    let bytes = name.as_bytes();
    !bytes.is_empty()
        && bytes.len() <= 64
        && is_lower_alnum(bytes[0])
        && bytes
            .iter()
            .all(|&byte| is_lower_alnum(byte) || byte == b'-')
        && !FORBIDDEN_HEADERS.contains(&name)
        && !FORBIDDEN_HEADER_PREFIXES
            .iter()
            .any(|prefix| name.starts_with(prefix))
}

/// A literal absolute path: `/` then segments of `[A-Za-z0-9._~-]`, with no empty, `.` or `..`
/// segment and no query, fragment, template or escape. Credentials cannot ride in a query string.
pub(super) fn is_request_path(path: &str) -> bool {
    let Some(rest) = path.strip_prefix('/') else {
        return false;
    };
    path.len() <= 256
        && (rest.is_empty()
            || rest.split('/').all(|segment| {
                !segment.is_empty()
                    && segment != "."
                    && segment != ".."
                    && segment.bytes().all(|byte| {
                        byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'~' | b'-')
                    })
            }))
}

/// An RFC 6901 JSON pointer of at most 128 bytes with no control characters.
pub(super) fn is_json_pointer(pointer: &str) -> bool {
    if pointer.len() > 128 || pointer.chars().any(char::is_control) {
        return false;
    }
    if !pointer.is_empty() && !pointer.starts_with('/') {
        return false;
    }
    let bytes = pointer.as_bytes();
    bytes
        .iter()
        .enumerate()
        .all(|(index, &byte)| byte != b'~' || matches!(bytes.get(index + 1), Some(b'0' | b'1')))
}

/// `^[A-Za-z_][A-Za-z0-9_]{0,63}$`: a request body field name.
pub(super) fn is_body_field(value: &str) -> bool {
    let bytes = value.as_bytes();
    !bytes.is_empty()
        && bytes.len() <= 64
        && (bytes[0].is_ascii_alphabetic() || bytes[0] == b'_')
        && bytes
            .iter()
            .all(|&byte| byte.is_ascii_alphanumeric() || byte == b'_')
}

/// `^[A-Za-z0-9_.-]{1,64}$`: a provider's own verdict value.
pub(super) fn is_provider_token(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'.' | b'-'))
}

/// Non-empty display text within `max_chars`, with no control characters.
pub(super) fn is_display_text(value: &str, max_chars: usize) -> bool {
    !value.trim().is_empty()
        && value.chars().count() <= max_chars
        && !value
            .chars()
            .any(|ch| ch.is_control() || is_invisible_mark(ch))
}

/// Code points that reorder, hide or break text without being seen: zero-width marks, bidi
/// embeddings, overrides and isolates, invisible operators, line and paragraph separators. A name a
/// user reads before trusting a provider must not carry them.
fn is_invisible_mark(ch: char) -> bool {
    matches!(ch,
        '\u{00ad}'
            | '\u{061c}'
            | '\u{180e}'
            | '\u{200b}'..='\u{200f}'
            | '\u{2028}'..='\u{202e}'
            | '\u{2060}'..='\u{2064}'
            | '\u{2066}'..='\u{2069}'
            | '\u{feff}')
}

/// Display text that is also safe plain text for a card: no markup-significant characters, as for
/// discovery creative.
pub(super) fn is_safe_label(value: &str, max_chars: usize) -> bool {
    is_display_text(value, max_chars) && !value.chars().any(|ch| matches!(ch, '<' | '>'))
}

/// An `https://` URL on a lowercase DNS host with no port, user info, query or fragment.
pub(super) fn is_https_url(value: &str) -> bool {
    if value.len() > 256 {
        return false;
    }
    let Some(rest) = value.strip_prefix("https://") else {
        return false;
    };
    let (host, path) = rest.split_at(rest.find('/').unwrap_or(rest.len()));
    let labels: Vec<&str> = host.split('.').collect();
    labels.len() >= 2
        && labels.iter().all(|label| is_dns_label(label))
        && labels
            .last()
            .is_some_and(|tld| tld.as_bytes()[0].is_ascii_lowercase())
        && !path
            .chars()
            .any(|ch| ch.is_whitespace() || ch.is_control() || matches!(ch, '?' | '#' | '\\'))
}

/// The icon names a manifest may use: the same closed `react-icons` set command sources accept.
pub(super) const ICON_NAMES: [&str; 6] = [
    "HiMiniBolt",
    "HiMiniCommandLine",
    "HiMiniCube",
    "HiMiniFolder",
    "HiMiniGlobeAlt",
    "HiMiniCloud",
];

/// `none` or one of [`ICON_NAMES`]: an allowlisted icon component name, never a URL.
pub(super) fn is_icon(value: &str) -> bool {
    value == "none" || ICON_NAMES.contains(&value)
}

//! CPython 3.12 `urllib.parse`, for the seam that exports a redacted endpoint.
//!
//! `inventory_contract_redaction.redact_url` round-trips an untrusted string
//! through `urlsplit`, `parse_qsl`, `urlencode` and `urlunsplit`, so the port
//! has to reproduce that parser rather than an RFC-correct one. Three places
//! where a WHATWG or RFC 3986 parser disagrees and would change what is
//! exported:
//!
//! * `urlsplit` only *lstrips* the C0-control-or-space set, and then deletes
//!   every tab, CR and LF anywhere in the URL. `"ht\ntp://h/"` therefore parses
//!   with scheme `http`, while a trailing space survives into the path.
//! * `parse_qsl` drops empty fields but keeps blank values, and `unquote`
//!   decodes each maximal ASCII run separately with `errors="replace"`, so a
//!   `%C3` escape never combines with a following literal non-ASCII character.
//! * `quote_plus` escapes everything outside `[A-Za-z0-9_.~-]` as an uppercase
//!   `%XX`, which is far more than a minimal quoter would.
//!
//! The netloc checks that make `urlsplit` raise live in
//! [`crate::python_netloc`]. `scripts/ci/generate_inventory_url_parity.py`
//! records the corpus in `testdata/inventory_url_parity.json` that pins every
//! case below.

use crate::python_netloc::{
    bracketed_netloc_valid, host_info, is_scheme, netloc_normalization_valid,
    starts_with_ascii_alphabetic,
};

/// `urllib.parse._ALWAYS_SAFE`, minus the alphanumerics.
const ALWAYS_SAFE_PUNCTUATION: [u8; 4] = [b'_', b'.', b'-', b'~'];

/// `urllib.parse.uses_netloc`. CPython's list also holds the empty scheme, but
/// `urlunsplit` only consults it behind a truthy `scheme`.
const USES_NETLOC: &[&str] = &[
    "ftp",
    "http",
    "gopher",
    "nntp",
    "telnet",
    "imap",
    "wais",
    "file",
    "mms",
    "https",
    "shttp",
    "snews",
    "prospero",
    "rtsp",
    "rtsps",
    "rtspu",
    "rsync",
    "svn",
    "svn+ssh",
    "sftp",
    "nfs",
    "git",
    "git+ssh",
    "ws",
    "wss",
    "itms-services",
];

/// Every way CPython's URL handling raises `ValueError`. Callers only branch on
/// "it raised"; the variants keep the port readable.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum UrlValueError {
    /// `"Invalid IPv6 URL"`, or a bracketed host that is neither IPvFuture nor
    /// IPv6.
    InvalidIpv6Url,
    /// `"netloc '...' contains invalid characters under NFKC normalization"`.
    NetlocNormalization,
    /// `"Port could not be cast to integer value"`, or `"Port out of range"`.
    Port,
}

/// `urllib.parse.SplitResult` for `str` input.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub(crate) struct SplitUrl {
    pub(crate) scheme: String,
    pub(crate) netloc: String,
    pub(crate) path: String,
    pub(crate) query: String,
    pub(crate) fragment: String,
}

/// `urlsplit(url)` with the default `scheme` and `allow_fragments`.
pub(crate) fn urlsplit(url: &str) -> Result<SplitUrl, UrlValueError> {
    // Only lstrip, as CPython does: a trailing space belongs to the URL.
    let stripped = url.trim_start_matches(|value: char| value <= ' ');
    let mut rest: String = stripped
        .chars()
        .filter(|value| !matches!(value, '\t' | '\r' | '\n'))
        .collect();

    let mut scheme = String::new();
    let mut netloc = String::new();
    let mut query = String::new();
    let mut fragment = String::new();

    if let Some(index) = rest.find(':') {
        if index > 0 && starts_with_ascii_alphabetic(&rest) && is_scheme(&rest[..index]) {
            scheme = rest[..index].to_ascii_lowercase();
            rest = rest[index + 1..].to_string();
        }
    }

    if rest.starts_with("//") {
        let after_slashes = &rest[2..];
        let delimiter = after_slashes
            .find(['/', '?', '#'])
            .unwrap_or(after_slashes.len());
        let (head, tail) = after_slashes.split_at(delimiter);
        netloc = head.to_string();
        let remainder = tail.to_string();
        rest = remainder;
        let open = netloc.contains('[');
        if open != netloc.contains(']') {
            return Err(UrlValueError::InvalidIpv6Url);
        }
        if open && !bracketed_netloc_valid(&netloc) {
            return Err(UrlValueError::InvalidIpv6Url);
        }
    }

    if let Some((before, after)) = rest.split_once('#') {
        let head = before.to_string();
        fragment = after.to_string();
        rest = head;
    }
    if let Some((before, after)) = rest.split_once('?') {
        let head = before.to_string();
        query = after.to_string();
        rest = head;
    }

    if !netloc_normalization_valid(&netloc) {
        return Err(UrlValueError::NetlocNormalization);
    }

    Ok(SplitUrl {
        scheme,
        netloc,
        path: rest,
        query,
        fragment,
    })
}

impl SplitUrl {
    /// `SplitResult.hostname`: lowercased, but an IPv6 zone id is preserved.
    pub(crate) fn hostname(&self) -> Option<String> {
        let (hostname, _) = host_info(&self.netloc);
        if hostname.is_empty() {
            return None;
        }
        Some(match hostname.split_once('%') {
            Some((host, zone)) => format!("{}%{zone}", host.to_lowercase()),
            None => hostname.to_lowercase(),
        })
    }

    /// `SplitResult.port`: `None` when absent, an error when it is not an
    /// ASCII integer in `0..=65535`.
    pub(crate) fn port(&self) -> Result<Option<u16>, UrlValueError> {
        let (_, port) = host_info(&self.netloc);
        let Some(port) = port else {
            return Ok(None);
        };
        if !port.bytes().all(|byte| byte.is_ascii_digit()) {
            return Err(UrlValueError::Port);
        }
        // CPython builds an arbitrary-precision int and then range-checks it,
        // so an overflowing digit string is out of range, not malformed.
        port.parse::<u32>()
            .ok()
            .and_then(|value| u16::try_from(value).ok())
            .map(Some)
            .ok_or(UrlValueError::Port)
    }
}

/// `parse_qsl(qs, keep_blank_values=True)` with the default `&` separator.
pub(crate) fn parse_qsl_keep_blank(query: &str) -> Vec<(String, String)> {
    if query.is_empty() {
        return Vec::new();
    }
    query
        .split('&')
        .filter(|field| !field.is_empty())
        .map(|field| {
            let (name, value) = field.split_once('=').unwrap_or((field, ""));
            (unquote_plus(name), unquote_plus(value))
        })
        .collect()
}

/// `urlencode(pairs)`, which quotes with `quote_plus(..., safe="")`.
pub(crate) fn urlencode(pairs: &[(String, String)]) -> String {
    pairs
        .iter()
        .map(|(key, value)| format!("{}={}", quote_plus(key), quote_plus(value)))
        .collect::<Vec<String>>()
        .join("&")
}

/// `urlunsplit((scheme, netloc, path, query, fragment))`.
pub(crate) fn urlunsplit(
    scheme: &str,
    netloc: &str,
    path: &str,
    query: &str,
    fragment: &str,
) -> String {
    let mut url = path.to_string();
    if netloc.is_empty() {
        if url.starts_with("//")
            || (!scheme.is_empty()
                && USES_NETLOC.contains(&scheme)
                && (url.is_empty() || url.starts_with('/')))
        {
            url = format!("//{url}");
        }
    } else {
        if !url.is_empty() && !url.starts_with('/') {
            url.insert(0, '/');
        }
        url = format!("//{netloc}{url}");
    }
    if !scheme.is_empty() {
        url = format!("{scheme}:{url}");
    }
    if !query.is_empty() {
        url = format!("{url}?{query}");
    }
    if !fragment.is_empty() {
        url = format!("{url}#{fragment}");
    }
    url
}

/// `unquote_plus(value, errors="replace")`.
fn unquote_plus(value: &str) -> String {
    unquote(&value.replace('+', " "))
}

/// `unquote(value, encoding="utf-8", errors="replace")`.
///
/// CPython decodes each maximal ASCII run on its own and passes non-ASCII
/// characters through untouched, so `%C3` followed by a literal `é` does not
/// combine into one code point.
fn unquote(value: &str) -> String {
    if !value.contains('%') {
        return value.to_string();
    }
    let mut unquoted = String::new();
    let mut ascii_run = String::new();
    for character in value.chars() {
        if character.is_ascii() {
            ascii_run.push(character);
            continue;
        }
        if !ascii_run.is_empty() {
            unquoted.push_str(&unquote_ascii_run(&ascii_run));
            ascii_run.clear();
        }
        unquoted.push(character);
    }
    if !ascii_run.is_empty() {
        unquoted.push_str(&unquote_ascii_run(&ascii_run));
    }
    unquoted
}

/// `_unquote_impl(run).decode("utf-8", "replace")`.
fn unquote_ascii_run(run: &str) -> String {
    let mut fields = run.as_bytes().split(|byte| *byte == b'%');
    let mut decoded = fields.next().unwrap_or_default().to_vec();
    for field in fields {
        match field.get(..2).and_then(hex_byte) {
            Some(byte) => {
                decoded.push(byte);
                decoded.extend_from_slice(&field[2..]);
            }
            None => {
                decoded.push(b'%');
                decoded.extend_from_slice(field);
            }
        }
    }
    String::from_utf8_lossy(&decoded).into_owned()
}

/// `_hextobyte[pair]`, which accepts either hex case.
fn hex_byte(pair: &[u8]) -> Option<u8> {
    let high = char::from(pair[0]).to_digit(16)?;
    let low = char::from(pair[1]).to_digit(16)?;
    u8::try_from((high << 4) | low).ok()
}

/// `quote_plus(value, safe="")`.
fn quote_plus(value: &str) -> String {
    let mut quoted = String::new();
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric() || ALWAYS_SAFE_PUNCTUATION.contains(&byte) {
            quoted.push(char::from(byte));
        } else if byte == b' ' {
            // CPython quotes with `safe=" "` when the value holds a space, and
            // then replaces every space with `+`.
            quoted.push('+');
        } else {
            quoted.push_str(&format!("%{byte:02X}"));
        }
    }
    quoted
}

#[cfg(test)]
#[path = "python_url_tests.rs"]
mod tests;

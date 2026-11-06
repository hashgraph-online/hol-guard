//! `urllib.parse` url splitting, query parsing and re-encoding, byte for byte.
//!
//! Artifact hashes bind persisted approvals, and the Python shaping that
//! produced them redacts secret-looking query parameters by round-tripping the
//! URL through `urlsplit`/`parse_qsl`/`urlencode`/`urlunsplit`. Re-encoding
//! rewrites the query even where nothing was secret, so reproducing those
//! functions — including the inputs `urlsplit` rejects — is what keeps a hash
//! computed here equal to the one Python computed.

use std::net::Ipv6Addr;

use unicode_normalization::UnicodeNormalization;

const SCHEME_CHARS: &str = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789+-.";
const UNRESERVED: &str = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_.-~";
/// `urllib.parse.uses_netloc`, which decides when `urlunsplit` restores `//`.
const USES_NETLOC: [&str; 27] = [
    "",
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

/// The five-item result of `urlsplit`.
pub(crate) struct SplitUrl {
    pub(crate) scheme: String,
    pub(crate) netloc: String,
    pub(crate) path: String,
    pub(crate) query: String,
    pub(crate) fragment: String,
}

/// `urlsplit(url)`; `None` where CPython raises `ValueError`.
pub(crate) fn urlsplit(url: &str) -> Option<SplitUrl> {
    let lstripped = url.trim_start_matches(|character: char| (character as u32) <= 0x20);
    let mut rest: String = lstripped
        .chars()
        .filter(|character| !matches!(character, '\t' | '\r' | '\n'))
        .collect();

    let mut scheme = String::new();
    if let Some(index) = rest.find(':').filter(|index| *index > 0) {
        let head = &rest[..index];
        let leads = head.chars().next().is_some_and(|c| c.is_ascii_alphabetic());
        if leads && head.chars().all(|c| SCHEME_CHARS.contains(c)) {
            scheme = head.to_lowercase();
            rest = rest[index + 1..].to_owned();
        }
    }

    let mut netloc = String::new();
    if let Some(after) = rest.strip_prefix("//") {
        let delimiter = after.find(['/', '?', '#']).unwrap_or(after.len());
        netloc = after[..delimiter].to_owned();
        let tail = after[delimiter..].to_owned();
        let open = netloc.contains('[');
        let close = netloc.contains(']');
        if open != close {
            return None;
        }
        if open && close && !bracketed_netloc_is_valid(&netloc) {
            return None;
        }
        rest = tail;
    }

    let mut fragment = String::new();
    if let Some(index) = rest.find('#') {
        fragment = rest[index + 1..].to_owned();
        rest = rest[..index].to_owned();
    }
    let mut query = String::new();
    if let Some(index) = rest.find('?') {
        query = rest[index + 1..].to_owned();
        rest = rest[..index].to_owned();
    }

    netloc_is_safe(&netloc).then_some(SplitUrl {
        scheme,
        netloc,
        path: rest,
        query,
        fragment,
    })
}

/// `_check_bracketed_netloc`: the host after any userinfo, with nothing
/// before its `[` and only a port after its `]`.
fn bracketed_netloc_is_valid(netloc: &str) -> bool {
    let host_and_port = netloc.rsplit_once('@').map_or(netloc, |(_, tail)| tail);
    let hostname = match host_and_port.split_once('[') {
        Some((before, bracketed)) => {
            if !before.is_empty() {
                return false;
            }
            let (hostname, port) = bracketed.split_once(']').unwrap_or((bracketed, ""));
            if !port.is_empty() && !port.starts_with(':') {
                return false;
            }
            hostname
        }
        None => host_and_port
            .split_once(':')
            .map_or(host_and_port, |(hostname, _)| hostname),
    };
    bracketed_host_is_valid(hostname)
}

/// `_check_bracketed_host`: IPvFuture by shape, otherwise IPv6 only.
fn bracketed_host_is_valid(hostname: &str) -> bool {
    if let Some(tail) = hostname.strip_prefix('v') {
        let digits = tail
            .chars()
            .take_while(|character| character.is_ascii_hexdigit())
            .count();
        if digits == 0 {
            return false;
        }
        let remainder = &tail[digits..];
        return remainder
            .strip_prefix('.')
            .is_some_and(|body| !body.is_empty() && !body.contains('\n'));
    }
    // `ipaddress.ip_address` accepts an IPv6 scope id and rejects IPv4.
    let (address, scope) = match hostname.split_once('%') {
        Some((address, scope)) => (address, Some(scope)),
        None => (hostname, None),
    };
    if scope.is_some_and(|scope| scope.is_empty() || scope.contains('%')) {
        return false;
    }
    address.parse::<Ipv6Addr>().is_ok()
}

/// `_checknetloc`: reject a netloc that NFKC-normalizes into a delimiter.
fn netloc_is_safe(netloc: &str) -> bool {
    if netloc.is_empty() || netloc.is_ascii() {
        return true;
    }
    let stripped: String = netloc
        .chars()
        .filter(|character| !matches!(character, '@' | ':' | '#' | '?'))
        .collect();
    let normalized: String = stripped.nfkc().collect();
    if stripped == normalized {
        return true;
    }
    !normalized.contains(['/', '?', '#', '@', ':'])
}

/// `parse_qsl(query, keep_blank_values=True)`.
pub(crate) fn parse_qsl(query: &str) -> Vec<(String, String)> {
    if query.is_empty() {
        return Vec::new();
    }
    query
        .split('&')
        .filter(|pair| !pair.is_empty())
        .map(|pair| {
            let (name, value) = pair.split_once('=').unwrap_or((pair, ""));
            (unquote_plus(name), unquote_plus(value))
        })
        .collect()
}

/// `urlencode(pairs)` with the default `quote_plus` encoder.
pub(crate) fn urlencode(pairs: &[(String, String)]) -> String {
    pairs
        .iter()
        .map(|(name, value)| format!("{}={}", quote_plus(name), quote_plus(value)))
        .collect::<Vec<_>>()
        .join("&")
}

/// `urlunsplit((scheme, netloc, path, query, fragment))`.
pub(crate) fn urlunsplit(split: &SplitUrl, query: &str) -> String {
    let mut url = split.path.clone();
    // Two of these arms are the same statement on purpose: 3.12's urlunsplit
    // prepends `//` both for a path that is already network-relative and for a
    // netloc-using scheme whose path is empty or rooted. Collapsing them into
    // one condition changes which paths get a separator, so the duplication is
    // the contract rather than an oversight.
    #[allow(clippy::if_same_then_else)]
    if !split.netloc.is_empty() {
        if !url.is_empty() && !url.starts_with('/') {
            url.insert(0, '/');
        }
        url = format!("//{}{}", split.netloc, url);
    } else if url.starts_with("//") {
        url = format!("//{url}");
    } else if !split.scheme.is_empty()
        && USES_NETLOC.contains(&split.scheme.as_str())
        && (url.is_empty() || url.starts_with('/'))
    {
        url = format!("//{url}");
    }
    if !split.scheme.is_empty() {
        url = format!("{}:{url}", split.scheme);
    }
    if !query.is_empty() {
        url = format!("{url}?{query}");
    }
    if !split.fragment.is_empty() {
        url = format!("{url}#{}", split.fragment);
    }
    url
}

fn quote_plus(value: &str) -> String {
    let mut encoded = String::with_capacity(value.len());
    for byte in value.as_bytes() {
        match byte {
            b' ' => encoded.push('+'),
            _ if UNRESERVED.contains(char::from(*byte)) => encoded.push(char::from(*byte)),
            _ => encoded.push_str(&format!("%{byte:02X}")),
        }
    }
    encoded
}

fn unquote_plus(value: &str) -> String {
    unquote(&value.replace('+', " "))
}

/// `unquote(value, errors="replace")`, which decodes only ASCII runs.
fn unquote(value: &str) -> String {
    if !value.contains('%') {
        return value.to_owned();
    }
    let mut decoded = String::with_capacity(value.len());
    let mut ascii_run = String::new();
    for character in value.chars() {
        if character.is_ascii() {
            ascii_run.push(character);
            continue;
        }
        if !ascii_run.is_empty() {
            decoded.push_str(&unquote_ascii(&ascii_run));
            ascii_run.clear();
        }
        decoded.push(character);
    }
    decoded.push_str(&unquote_ascii(&ascii_run));
    decoded
}

fn unquote_ascii(run: &str) -> String {
    let mut chunks = run.split('%');
    let mut bytes = chunks.next().unwrap_or_default().as_bytes().to_vec();
    for chunk in chunks {
        let raw = chunk.as_bytes();
        match (
            raw.first().and_then(hex_value),
            raw.get(1).and_then(hex_value),
        ) {
            (Some(high), Some(low)) => {
                bytes.push(high * 16 + low);
                bytes.extend_from_slice(&raw[2..]);
            }
            _ => {
                bytes.push(b'%');
                bytes.extend_from_slice(raw);
            }
        }
    }
    String::from_utf8_lossy(&bytes).into_owned()
}

fn hex_value(byte: &u8) -> Option<u8> {
    char::from(*byte).to_digit(16).map(|digit| digit as u8)
}

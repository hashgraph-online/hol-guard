//! Browser target and input facts for [`BrowserActionV2`](guard_contracts::BrowserActionV2).
//!
//! Every value that leaves this module is redacted: a URL keeps its scheme, host, port, path and
//! query keys, every query value becomes `[redacted]`, and the fragment and any userinfo are dropped.
//! Element names and input are kept only as a SHA-256 digest, a length and a bounded preview class.

use guard_contracts::{
    BrowserInputPreviewClassV1, BrowserTargetV2, BROWSER_ELEMENT_NAME_PREVIEW_MAX_CHARS,
    BROWSER_URL_REDACTED_MAX_CHARS, BROWSER_URL_REDACTED_VALUE,
};

use crate::launch_identity_common::sha256_hex;

/// A target with no URL: no origin, not loopback, not Guard's own origin.
pub(crate) fn empty_target() -> BrowserTargetV2 {
    BrowserTargetV2 {
        origin: None,
        site_group: None,
        path_prefix: None,
        is_loopback: false,
        is_guard_origin: false,
        url_redacted: None,
    }
}

/// Facts about one URL. `guard_origins` are Guard's own origins (`scheme://host:port`, lowercase).
pub(crate) fn browser_target(url: &str, guard_origins: &[&str]) -> BrowserTargetV2 {
    // The URL parser strips only what a browser strips (leading and trailing C0 controls and
    // spaces, inner tabs and newlines); a wider trim would drop a trailing U+00A0 the browser keeps.
    let Some(parts) = split_http_url(url) else {
        return empty_target();
    };
    let origin = match parts.port {
        Some(port) => format!("{}://{}:{port}", parts.scheme, parts.host),
        None => format!("{}://{}", parts.scheme, parts.host),
    };
    let mut url_redacted = format!("{origin}{}", parts.path);
    if let Some(query) = parts.query.as_deref() {
        url_redacted.push('?');
        url_redacted.push_str(&redacted_query(query));
    }
    let url_redacted =
        (url_redacted.chars().count() <= BROWSER_URL_REDACTED_MAX_CHARS).then_some(url_redacted);
    let is_guard_origin = guard_origins
        .iter()
        .any(|guard| guard.eq_ignore_ascii_case(&origin));
    BrowserTargetV2 {
        site_group: Some(site_group(&parts.host)),
        path_prefix: Some(path_prefix(&parts.path)),
        is_loopback: host_is_loopback(&parts.host),
        is_guard_origin,
        origin: Some(origin),
        url_redacted,
    }
}

/// True for a `javascript:` URL, which runs script in the page instead of navigating.
///
/// The scheme is read the way a browser reads it (WHATWG URL parsing): leading C0 control
/// characters and spaces are dropped, and ASCII tab and newline are removed wherever they appear,
/// so `java<TAB>script:` and a control-character prefix still count.
pub(crate) fn url_runs_script(url: &str) -> bool {
    const SCHEME: &[u8] = b"javascript:";
    let mut scheme = url
        .bytes()
        .skip_while(|byte| *byte <= b' ')
        .filter(|byte| !matches!(byte, b'\t' | b'\n' | b'\r'));
    SCHEME.iter().all(|expected| {
        scheme
            .next()
            .is_some_and(|byte| byte.eq_ignore_ascii_case(expected))
    })
}

struct HttpUrl {
    scheme: &'static str,
    host: String,
    port: Option<u16>,
    path: String,
    query: Option<String>,
}

/// Parse `url` with the WHATWG URL parser browsers use, so a backslash ends the authority, tab and
/// newline are stripped, and decimal, hex or short IPv4 hosts resolve to the address the browser
/// would load. The port is dropped when it is the scheme's default, as in a browser origin.
fn split_http_url(url: &str) -> Option<HttpUrl> {
    let parsed = url::Url::parse(url).ok()?;
    let scheme = match parsed.scheme() {
        "https" => "https",
        "http" => "http",
        _ => return None,
    };
    let host = parsed.host_str()?.to_ascii_lowercase();
    if host.is_empty() {
        return None;
    }
    Some(HttpUrl {
        scheme,
        host,
        port: parsed.port(),
        path: parsed.path().to_owned(),
        query: parsed.query().map(str::to_owned),
    })
}

fn redacted_query(query: &str) -> String {
    query
        .split('&')
        .filter(|field| !field.is_empty())
        .map(|field| match field.split_once('=') {
            Some((key, value)) if !value.is_empty() => {
                format!("{key}={BROWSER_URL_REDACTED_VALUE}")
            }
            Some((key, _)) => format!("{key}="),
            None => field.to_owned(),
        })
        .collect::<Vec<_>>()
        .join("&")
}

/// The first path segment, so `/docs/intro` and `/docs/api` share `/docs`.
fn path_prefix(path: &str) -> String {
    let first = path.trim_start_matches('/').split('/').next().unwrap_or("");
    format!("/{first}")
}

/// The last two DNS labels, or the whole host for an IP literal, `localhost` or a single label.
/// This is a display grouping, not a public-suffix decision: grants key on the origin.
fn site_group(host: &str) -> String {
    if host.starts_with('[') || host.parse::<std::net::Ipv4Addr>().is_ok() {
        return host.to_owned();
    }
    let labels: Vec<&str> = host.trim_end_matches('.').split('.').collect();
    if labels.len() <= 2 {
        return labels.join(".");
    }
    labels[labels.len() - 2..].join(".")
}

fn host_is_loopback(host: &str) -> bool {
    let host = host.trim_end_matches('.');
    if host == "localhost" || host.ends_with(".localhost") || host == "[::1]" {
        return true;
    }
    host.parse::<std::net::Ipv4Addr>()
        .is_ok_and(|address| address.is_loopback())
}

/// A bounded, display-only element name preview.
pub(crate) fn element_preview(name: &str) -> String {
    name.chars()
        .filter(|ch| !ch.is_control())
        .take(BROWSER_ELEMENT_NAME_PREVIEW_MAX_CHARS)
        .collect()
}

pub(crate) fn digest(text: &str) -> String {
    sha256_hex(text.as_bytes())
}

pub(crate) fn name_looks_like_password(name: &str) -> bool {
    let name = name.to_ascii_lowercase();
    ["password", "passwd", "passcode", "one-time code", "otp"]
        .iter()
        .any(|needle| name.contains(needle))
}

pub(crate) fn name_looks_like_payment(name: &str) -> bool {
    let name = name.to_ascii_lowercase();
    [
        "card number",
        "credit card",
        "cvv",
        "cvc",
        "security code",
        "expiry",
        "expiration",
    ]
    .iter()
    .any(|needle| name.contains(needle))
}

/// How the card may preview input, judged without storing it.
pub(crate) fn input_preview_class(text: &str) -> BrowserInputPreviewClassV1 {
    if text.trim().is_empty() {
        return BrowserInputPreviewClassV1::Empty;
    }
    if looks_like_card_number(text) {
        return BrowserInputPreviewClassV1::LooksLikePayment;
    }
    if looks_like_secret(text) {
        return BrowserInputPreviewClassV1::LooksLikeSecret;
    }
    BrowserInputPreviewClassV1::Plain
}

fn looks_like_card_number(text: &str) -> bool {
    if !text
        .chars()
        .all(|ch| ch.is_ascii_digit() || ch == ' ' || ch == '-')
    {
        return false;
    }
    let digits: Vec<u32> = text.chars().filter_map(|ch| ch.to_digit(10)).collect();
    if !(13..=19).contains(&digits.len()) {
        return false;
    }
    let sum: u32 = digits
        .iter()
        .rev()
        .enumerate()
        .map(|(index, &digit)| {
            if index % 2 == 1 {
                let doubled = digit * 2;
                if doubled > 9 {
                    doubled - 9
                } else {
                    doubled
                }
            } else {
                digit
            }
        })
        .sum();
    sum % 10 == 0
}

/// One unbroken token of 20 or more characters mixing letters and digits, or a known key prefix.
fn looks_like_secret(text: &str) -> bool {
    let text = text.trim();
    if text.chars().any(char::is_whitespace) {
        return false;
    }
    let known_prefix = [
        "sk-",
        "sk_live_",
        "ghp_",
        "gho_",
        "github_pat_",
        "xox",
        "AKIA",
        "eyJ",
    ]
    .iter()
    .any(|prefix| text.starts_with(prefix));
    let mixed = text.chars().any(|ch| ch.is_ascii_alphabetic())
        && text.chars().any(|ch| ch.is_ascii_digit());
    (known_prefix && text.len() >= 12) || (mixed && text.chars().count() >= 20)
}

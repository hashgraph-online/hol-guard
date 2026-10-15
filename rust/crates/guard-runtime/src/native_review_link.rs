//! The approval link a reviewed `PreToolUse` answer carries.
//!
//! Mirrors `native_review_reason` (`approval_link_output.py`) and the signed
//! dashboard session it attaches (`local_dashboard_session.py`): a loopback
//! approval link gets a `#guard-token=` fragment holding an HMAC-SHA256
//! session token keyed by the daemon auth token, so the browser opens signed
//! in. Every function answers `None` for a link shape it does not reproduce
//! byte for byte; the caller then leaves the answer to the daemon.

use base64ct::{Base64UrlUnpadded, Encoding};
use hmac::{Hmac, Mac};
use sha2::Sha256;

use crate::guard_store_json::py_strip;
use crate::policy_bundle_time::micros_to_utc_isoformat;

pub(crate) const APPROVAL_CENTER_SURFACE: &str = "approval-center";
const SESSION_PREFIX: &str = "gld1";
const SESSION_AUDIENCE: &str = "guard-local-daemon";
const SESSION_VERSION: &str = "guard-local-daemon-session.v1";
const SESSION_TTL_MICROS: i64 = 12 * 60 * 60 * 1_000_000;
pub(crate) const OPEN_GUARD: &str = "Open HOL Guard to approve or keep this blocked:";
pub(crate) const SIGNED_LINK_UNAVAILABLE: &str =
    "HOL Guard could not create a signed approval link; open Inbox from Guard on this device, then retry.";
const LOOPBACK_HOSTS: [&str; 3] = ["127.0.0.1", "::1", "localhost"];
/// `auth_token_path(guard_home)` (`daemon/auth_token.py`).
const AUTH_TOKEN_FILE: &str = "daemon-auth-token";

/// `build_local_dashboard_session_token(auth_token=..., surface=...)` at
/// `now_micros` (UTC microseconds since the epoch).
pub(crate) fn session_token(auth_token: &str, surface: &str, now_micros: i64) -> Option<String> {
    if !surface
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
    {
        return None;
    }
    let started = micros_to_utc_isoformat(now_micros, "+00:00")?;
    let expires = micros_to_utc_isoformat(now_micros.checked_add(SESSION_TTL_MICROS)?, "+00:00")?;
    let payload = format!(
        "{{\"aud\":\"{SESSION_AUDIENCE}\",\"version\":\"{SESSION_VERSION}\",\"surface\":\"{surface}\",\"expires_at\":\"{expires}\",\"session_started_at\":\"{started}\"}}"
    );
    let encoded = Base64UrlUnpadded::encode_string(payload.as_bytes());
    let mut mac = <Hmac<Sha256>>::new_from_slice(auth_token.as_bytes()).ok()?;
    mac.update(encoded.as_bytes());
    let signature = Base64UrlUnpadded::encode_string(&mac.finalize().into_bytes());
    Some(format!("{SESSION_PREFIX}.{encoded}.{signature}"))
}

/// An approval link this module reproduces: `http(s)://host[:port]/path`
/// with no query, parameters, fragment, credentials or escapes, so
/// `urlparse` and `urlunparse` hand it back unchanged.
struct ApprovalLink<'a> {
    url: &'a str,
    loopback: bool,
}

fn approval_link(url: &str) -> Option<ApprovalLink<'_>> {
    let rest = url
        .strip_prefix("http://")
        .or_else(|| url.strip_prefix("https://"))?;
    let (netloc, path) = rest.split_at(rest.find('/').unwrap_or(rest.len()));
    let path_safe = path.bytes().all(|byte| {
        byte.is_ascii_alphanumeric() || matches!(byte, b'/' | b'-' | b'_' | b'.' | b'~')
    });
    if netloc.is_empty() || !path_safe {
        return None;
    }
    let host = if let Some(bracketed) = netloc.strip_prefix('[') {
        let (host, port) = bracketed.split_once(']')?;
        if host != "::1" || !port_suffix(port) {
            return None;
        }
        host
    } else {
        let (host, port) = match netloc.split_once(':') {
            Some((host, port)) => (host, Some(port)),
            None => (netloc, None),
        };
        let host_safe = host
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'.' || byte == b'-');
        if host.is_empty() || !host_safe || port.is_some_and(|port| !port_digits(port)) {
            return None;
        }
        host
    };
    let host = host.to_ascii_lowercase();
    Some(ApprovalLink {
        url,
        loopback: LOOPBACK_HOSTS.contains(&host.as_str()),
    })
}

fn port_digits(port: &str) -> bool {
    !port.is_empty() && port.len() <= 5 && port.bytes().all(|byte| byte.is_ascii_digit())
}

fn port_suffix(text: &str) -> bool {
    text.is_empty() || text.strip_prefix(':').is_some_and(port_digits)
}

/// `build_approval_browser_url(url, auth_token=...)` for a link without a
/// fragment: the session token goes in a new `guard-token` fragment. The
/// token's alphabet is one `urlencode` leaves as is.
fn browser_url(link: &ApprovalLink<'_>, auth_token: &str, now_micros: i64) -> Option<String> {
    let token = session_token(auth_token, APPROVAL_CENTER_SURFACE, now_micros)?;
    Some(format!("{}#guard-token={token}", link.url))
}

fn py_space(character: char) -> bool {
    character.is_whitespace() || ('\u{1c}'..='\u{1f}').contains(&character)
}

/// `re.sub(r":\s*\.(?=\s|$)", ".", text)` on text without trailing space.
fn colon_before_period(text: &str) -> String {
    let characters: Vec<char> = text.chars().collect();
    let mut out = String::with_capacity(text.len());
    let mut index = 0;
    while index < characters.len() {
        if characters[index] == ':' {
            let mut end = index + 1;
            while end < characters.len() && py_space(characters[end]) {
                end += 1;
            }
            let period = characters.get(end) == Some(&'.');
            if period && characters.get(end + 1).is_none_or(|next| py_space(*next)) {
                out.push('.');
                index = end + 1;
                continue;
            }
        }
        out.push(characters[index]);
        index += 1;
    }
    out
}

/// `_without_raw_approval_url(message, review_url)`.
fn without_raw_url(message: &str, review_url: &str) -> String {
    let removed = message.replace(review_url, "");
    let joined = colon_before_period(py_strip(&removed));
    let mut trimmed = joined.trim_end_matches(py_space).to_owned();
    if let Some(body) = trimmed.strip_suffix('.') {
        let body = body.trim_end_matches([' ', '\t', '\r', '\n', ':', ';', ',']);
        trimmed = format!("{body}.");
    }
    trimmed.trim_end_matches([' ', ':', ';', ',']).to_owned()
}

/// `with_approval_review_url(reason, {"approval_url": url}, guard_home=...)`
/// where `auth_token` is what `load_guard_daemon_auth_token` read.
fn with_review_url(
    stripped: &str,
    link: &ApprovalLink<'_>,
    auth_token: Option<&str>,
    now_micros: i64,
) -> Option<String> {
    let review_url = link.url;
    let live_url = match auth_token {
        Some(token) if link.loopback => browser_url(link, token, now_micros)?,
        _ => review_url.to_owned(),
    };
    if live_url != review_url && stripped.contains(review_url) {
        return Some(stripped.replacen(review_url, &live_url, 1));
    }
    if stripped.contains(&live_url) {
        return Some(stripped.to_owned());
    }
    Some(format!("{stripped} {OPEN_GUARD} {live_url}."))
}

/// Whether `live_approval_review_url(url, guard_home=...)`
/// (`approval_hook_copy.py`) hands `url` back unchanged, whether or not the
/// caller can import Guard: `guard_home` holds no daemon auth token file, so
/// none is ever loaded, or `url` is a link this module reproduces whose host
/// `is_loopback_approval_url` rejects. A token file that exists counts as a
/// token, however it reads.
pub(crate) fn review_url_stays_unsigned(url: &str, guard_home: &std::path::Path) -> bool {
    if approval_link(url).is_some_and(|link| !link.loopback) {
        return true;
    }
    matches!(
        guard_home.join(AUTH_TOKEN_FILE).symlink_metadata(),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound
    )
}

/// Whether `is_loopback_approval_url` may accept `url`: `urlparse`'s
/// hostname read conservatively, so a doubtful link counts as loopback.
fn maybe_loopback(url: &str) -> bool {
    if url.contains(['\t', '\r', '\n']) {
        return true;
    }
    // `urlsplit` drops leading C0 controls and spaces before it parses.
    let url = url.trim_start_matches(|character: char| character <= ' ');
    let Some((scheme, rest)) = url.split_once(':') else {
        return false;
    };
    let web = scheme.eq_ignore_ascii_case("http") || scheme.eq_ignore_ascii_case("https");
    let Some(rest) = rest.strip_prefix("//").filter(|_| web) else {
        return false;
    };
    let netloc = &rest[..rest.find(['/', '?', '#']).unwrap_or(rest.len())];
    let host = netloc.rsplit_once('@').map_or(netloc, |(_, host)| host);
    let host = match host.strip_prefix('[') {
        Some(bracketed) => bracketed
            .split_once(']')
            .map_or(bracketed, |(host, _)| host),
        None => host.split_once(':').map_or(host, |(host, _)| host),
    };
    LOOPBACK_HOSTS.contains(&host.to_ascii_lowercase().as_str())
}

/// `live_approval_review_url(url, guard_home=...)` with `auth_token` what
/// `load_guard_daemon_auth_token` read: a loopback link this module
/// reproduces, signed; any other link, or a link without a token,
/// unchanged. `None` for a loopback link the client would sign that this
/// module does not reproduce, so the caller never shows it unsigned.
pub(crate) fn live_review_url(
    url: &str,
    auth_token: Option<&str>,
    now_micros: i64,
) -> Option<String> {
    match (approval_link(url), auth_token) {
        (Some(link), Some(token)) if link.loopback => browser_url(&link, token, now_micros),
        (None, Some(_)) if maybe_loopback(url) => None,
        _ => Some(url.to_owned()),
    }
}

/// `authenticated_approval_review_url(url, guard_home=...)` for a link this
/// module reproduces: an external link unchanged, a loopback link signed
/// with `auth_token`, and `None` when no safe link can be made (no token,
/// or a link shape this module does not reproduce).
pub(crate) fn approval_browser_url(
    url: &str,
    auth_token: impl FnOnce() -> Option<String>,
    now_micros: i64,
) -> Option<String> {
    let link = approval_link(url)?;
    if !link.loopback {
        return Some(url.to_owned());
    }
    browser_url(&link, &auth_token()?, now_micros)
}

/// `native_review_reason(canonical_harness, reason, approval_url, guard_home=...)`
/// for a stripped, non-empty `approval_url`.
pub(crate) fn native_review_reason(
    canonical_harness: &str,
    reason: &str,
    approval_url: &str,
    auth_token: Option<&str>,
    now_micros: i64,
) -> Option<String> {
    let link = approval_link(approval_url)?;
    let stripped = py_strip(reason);
    if canonical_harness != "codex" || !link.loopback {
        return with_review_url(stripped, &link, auth_token, now_micros);
    }
    let Some(token) = auth_token else {
        let without = without_raw_url(stripped, approval_url);
        return Some(py_strip(&format!("{without} {SIGNED_LINK_UNAVAILABLE}")).to_owned());
    };
    let signed_url = browser_url(&link, token, now_micros)?;
    if stripped.contains(&signed_url) {
        return Some(stripped.to_owned());
    }
    if stripped.contains(approval_url) {
        return Some(stripped.replace(approval_url, &signed_url));
    }
    Some(format!("{stripped} {OPEN_GUARD} {signed_url}."))
}

#[cfg(test)]
#[path = "native_review_link_tests.rs"]
mod tests;

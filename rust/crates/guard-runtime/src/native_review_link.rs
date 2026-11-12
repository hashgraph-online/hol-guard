//! The approval link a reviewed `PreToolUse` answer carries.
//!
//! Owns the review reason's approval link, signed with the dashboard session
//! `local_dashboard_session.py` also issues: a loopback approval link gets a
//! `#guard-token=` fragment holding an HMAC-SHA256 session token keyed by the
//! daemon auth token, so the browser opens signed in. The vectors under
//! `testdata/native_review_link` were recorded from the daemon's retired
//! implementation and stay frozen. Every function answers `None` for a link
//! shape it does not reproduce byte for byte; the caller then leaves the
//! reason unlinked.

use std::sync::LazyLock;

use base64ct::{Base64UrlUnpadded, Encoding};
use hmac::{Hmac, Mac};
use regex::Regex;
use sha2::Sha256;

use crate::guard_store_json::py_strip;
use crate::policy_bundle_time::micros_to_utc_isoformat;

pub(crate) const APPROVAL_CENTER_SURFACE: &str = "approval-center";
/// `PROTECTION_REPAIR_DASHBOARD_SURFACE` (`local_dashboard_session.py`).
const PROTECTION_REPAIR_SURFACE: &str = "protection-repair";
const SESSION_PREFIX: &str = "gld1";
const SESSION_AUDIENCE: &str = "guard-local-daemon";
const SESSION_VERSION: &str = "guard-local-daemon-session.v1";
const SESSION_TTL_MICROS: i64 = 12 * 60 * 60 * 1_000_000;
pub(crate) const OPEN_GUARD: &str = "Open HOL Guard to approve or keep this blocked:";
pub(crate) const SIGNED_LINK_UNAVAILABLE: &str =
    "HOL Guard could not create a signed approval link; open Inbox from Guard on this device, then retry.";
const LOOPBACK_HOSTS: [&str; 3] = ["127.0.0.1", "::1", "localhost"];

static GUARD_TOKEN_FRAGMENT: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)#guard-token=[A-Za-z0-9_~%+-]+(?:\.[A-Za-z0-9_~%+-]+)*")
        .expect("guard token pattern compiles")
});

static HANDOFF_CODE: LazyLock<Regex> = LazyLock::new(|| {
    // Ends where `carries_handoff_link` ends a code: at punctuation, space
    // or the end of the reason, never mid-path.
    Regex::new(r"(/requests/[0-9a-f]{32})/[0-9]{1,12}-[0-9a-f]{32}([^A-Za-z0-9/_-]|$)")
        .expect("approval handoff pattern compiles")
});

/// True when `text` holds a short signed `/requests/<id>/<expires>-<mac>` link.
pub(crate) fn has_handoff_code(text: &str) -> bool {
    HANDOFF_CODE.is_match(text)
}

/// `text` with every link's session fragment and short code removed, so two
/// copies of a reason that differ only in their signature compare equal.
pub(crate) fn strip_review_link_codes(text: &str) -> String {
    let unfragmented = GUARD_TOKEN_FRAGMENT.replace_all(text, "");
    HANDOFF_CODE.replace_all(&unfragmented, "$1$2").into_owned()
}

/// `canonical_harness` (`hook_fail_closed.py`).
pub(crate) fn canonical_harness(harness: &str) -> String {
    py_strip(harness).to_lowercase().replace('_', "-")
}

/// UTC microseconds since the epoch, the clock a session token is signed at.
pub(crate) fn now_micros() -> Option<i64> {
    let micros = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .ok()?
        .as_micros();
    i64::try_from(micros).ok()
}

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

/// `build_approval_browser_url(url, auth_token=..., surface=...)` for a link
/// without a fragment: the session token goes in a new `guard-token`
/// fragment. The token's alphabet is one `urlencode` leaves as is.
fn browser_url(
    link: &ApprovalLink<'_>,
    auth_token: &str,
    surface: &str,
    now_micros: i64,
) -> Option<String> {
    if surface == APPROVAL_CENTER_SURFACE {
        if let Some(short) = handoff_url(link.url, auth_token, now_micros) {
            return Some(short);
        }
    }
    let token = session_token(auth_token, surface, now_micros)?;
    Some(format!("{}#guard-token={token}", link.url))
}

const HANDOFF_VERSION: &str = "guard-approval-link.v1";
const HANDOFF_TTL_SECONDS: i64 = 12 * 60 * 60;
const HANDOFF_MAC_BYTES: usize = 16;
const HANDOFF_MAC_HEX: usize = HANDOFF_MAC_BYTES * 2;
/// `_CLOCK_SKEW_SECONDS` (`approval_handoff_link.py`).
const HANDOFF_CLOCK_SKEW_SECONDS: i64 = 60;

/// `build_approval_handoff_url`: `<origin>/requests/<id>/<expires>-<mac>` for
/// a bare request link. Agents relay this whole; they drop the long session
/// fragment. The daemon checks the MAC and redirects to the signed page.
fn handoff_url(url: &str, auth_token: &str, now_micros: i64) -> Option<String> {
    let request_id = crate::desktop_review_link::approval_request_id(url)?;
    let rest = url
        .strip_prefix("http://")
        .or_else(|| url.strip_prefix("https://"))?;
    let (_, path) = rest.split_once('/')?;
    if path.strip_prefix("requests/") != Some(request_id) {
        return None;
    }
    let expires = now_micros
        .div_euclid(1_000_000)
        .checked_add(HANDOFF_TTL_SECONDS)?;
    let mut mac = <Hmac<Sha256>>::new_from_slice(auth_token.as_bytes()).ok()?;
    mac.update(format!("{HANDOFF_VERSION}\n{request_id}\n{expires}").as_bytes());
    let digest = mac.finalize().into_bytes();
    let code = hex::encode(digest.get(..HANDOFF_MAC_BYTES)?);
    Some(format!("{url}/{expires}-{code}"))
}

/// `approval_handoff_location`: where `/requests/<id>/<code>` lands. A valid
/// code opens the request page with an approval session bound to that
/// request, started when the code was issued and ending when it does; any
/// other code lands on the unsigned page. `None` when `path` is not a short
/// link.
pub(crate) fn handoff_location(path: &str, auth_key: &str, now_micros: i64) -> Option<String> {
    let rest = path.strip_prefix("/requests/")?;
    let (request_id, code) = rest.split_once('/')?;
    if request_id.len() != 32
        || !request_id
            .bytes()
            .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
        || code.is_empty()
        || code.contains('/')
    {
        return None;
    }
    let page = format!("/requests/{request_id}");
    let Some(expires) = handoff_code_expiry(request_id, code, auth_key, now_micros) else {
        return Some(page);
    };
    let remaining = (expires * 1_000_000 - now_micros)
        .div_euclid(1_000_000)
        .max(1);
    let started = micros_to_utc_isoformat((expires - HANDOFF_TTL_SECONDS) * 1_000_000, "+00:00")?;
    let ends = micros_to_utc_isoformat(now_micros.checked_add(remaining * 1_000_000)?, "+00:00")?;
    let payload = format!(
        "{{\"aud\":\"{SESSION_AUDIENCE}\",\"version\":\"{SESSION_VERSION}\",\"surface\":\"{APPROVAL_CENTER_SURFACE}\",\"expires_at\":\"{ends}\",\"session_started_at\":\"{started}\",\"request_id\":\"{request_id}\"}}"
    );
    let encoded = Base64UrlUnpadded::encode_string(payload.as_bytes());
    let mut mac = <Hmac<Sha256>>::new_from_slice(auth_key.as_bytes()).ok()?;
    mac.update(encoded.as_bytes());
    let signature = Base64UrlUnpadded::encode_string(&mac.finalize().into_bytes());
    Some(format!(
        "{page}#guard-{}={SESSION_PREFIX}.{encoded}.{signature}",
        "token"
    ))
}

/// `handoff_code_expiry`: the signed expiry, in seconds, of a valid
/// `<expires>-<mac>` code for `request_id`.
fn handoff_code_expiry(
    request_id: &str,
    code: &str,
    auth_key: &str,
    now_micros: i64,
) -> Option<i64> {
    let (digits, presented) = code.split_once('-')?;
    if !(1..=12).contains(&digits.len())
        || !digits.bytes().all(|byte| byte.is_ascii_digit())
        || presented.len() != HANDOFF_MAC_HEX
        || !presented
            .bytes()
            .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
    {
        return None;
    }
    let expires: i64 = digits.parse().ok()?;
    let expires_micros = expires.checked_mul(1_000_000)?;
    let latest =
        now_micros.checked_add((HANDOFF_TTL_SECONDS + HANDOFF_CLOCK_SKEW_SECONDS) * 1_000_000)?;
    if expires_micros <= now_micros || expires_micros > latest {
        return None;
    }
    let mut mac = <Hmac<Sha256>>::new_from_slice(auth_key.as_bytes()).ok()?;
    mac.update(format!("{HANDOFF_VERSION}\n{request_id}\n{expires}").as_bytes());
    let digest = mac.finalize().into_bytes();
    let expected = hex::encode(digest.get(..HANDOFF_MAC_BYTES)?);
    crate::resident_transport::constant_time_eq(expected.as_bytes(), presented.as_bytes())
        .then_some(expires)
}

#[cfg(test)]
pub(crate) fn handoff_url_for_tests(url: &str, auth_key: &str, now_micros: i64) -> Option<String> {
    handoff_url(url, auth_key, now_micros)
}

/// Whether `reason` already carries `review_url` as a short signed link:
/// `<review_url>/<expires>-<32 hex mac>`, ending there. Any other path after
/// the review link is not one, and still needs signing.
pub(crate) fn carries_handoff_link(reason: &str, review_url: &str) -> bool {
    let prefix = format!("{review_url}/");
    reason
        .match_indices(&prefix)
        .any(|(at, _)| is_handoff_code(&reason.as_bytes()[at + prefix.len()..]))
}

fn is_handoff_code(rest: &[u8]) -> bool {
    let digits = rest.iter().take_while(|byte| byte.is_ascii_digit()).count();
    if !(1..=12).contains(&digits) || rest.get(digits) != Some(&b'-') {
        return false;
    }
    let mac = &rest[digits + 1..];
    mac.len() >= HANDOFF_MAC_HEX
        && mac[..HANDOFF_MAC_HEX]
            .iter()
            .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
        && !mac
            .get(HANDOFF_MAC_HEX)
            .is_some_and(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'/' | b'-' | b'_'))
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

/// The message with the raw review URL and its dangling separators removed.
pub(crate) fn without_raw_url(message: &str, review_url: &str) -> String {
    let removed = message.replace(review_url, "");
    let joined = colon_before_period(py_strip(&removed));
    let mut trimmed = joined.trim_end_matches(py_space).to_owned();
    if let Some(body) = trimmed.strip_suffix('.') {
        let body = body.trim_end_matches([' ', '\t', '\r', '\n', ':', ';', ',']);
        trimmed = format!("{body}.");
    }
    trimmed.trim_end_matches([' ', ':', ';', ',']).to_owned()
}

/// The reason with the review URL linked, signed for a loopback link when
/// `auth_token` holds the daemon auth token.
fn with_review_url(
    stripped: &str,
    link: &ApprovalLink<'_>,
    auth_token: Option<&str>,
    now_micros: i64,
) -> Option<String> {
    // A default-mode connector setup reason never carries a link.
    if crate::blocked_request_mode::is_unlinked_connector_setup_reason(stripped) {
        return Some(stripped.to_owned());
    }
    let review_url = link.url;
    let live_url = match auth_token {
        Some(token) if link.loopback => {
            browser_url(link, token, APPROVAL_CENTER_SURFACE, now_micros)?
        }
        _ => review_url.to_owned(),
    };
    // A short link already in the reason stays as written; prefixing a fresh
    // code onto it would leave a two-code path the daemon cannot redeem.
    if carries_handoff_link(stripped, review_url) {
        return Some(stripped.to_owned());
    }
    if live_url != review_url && stripped.contains(review_url) {
        return Some(stripped.replacen(review_url, &live_url, 1));
    }
    if stripped.contains(&live_url) {
        return Some(stripped.to_owned());
    }
    Some(format!("{stripped} {OPEN_GUARD} {live_url}."))
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
        (Some(link), Some(token)) if link.loopback => {
            browser_url(&link, token, APPROVAL_CENTER_SURFACE, now_micros)
        }
        (None, Some(_)) if maybe_loopback(url) => None,
        _ => Some(url.to_owned()),
    }
}

/// `authenticated_approval_review_url(url, guard_home=..., surface=...)` for
/// a link this module reproduces: an external link unchanged, a loopback link
/// signed for `surface`, and `None` when no safe link can be made (no token,
/// or a link shape this module does not reproduce).
pub(crate) fn approval_browser_url(
    url: &str,
    auth_token: impl FnOnce() -> Option<String>,
    surface: &str,
    now_micros: i64,
) -> Option<String> {
    let link = approval_link(url)?;
    if !link.loopback {
        return Some(url.to_owned());
    }
    browser_url(&link, &auth_token()?, surface, now_micros)
}

/// What `command_policy_repair_page_url` can answer for a repair page.
pub(crate) enum RepairPage {
    /// A loopback page this module reproduces, signed for the repair surface.
    Signed(String),
    /// No safe link: the page is not loopback, or no daemon auth token exists.
    Absent,
    /// A loopback page the client would sign whose shape this module does not
    /// reproduce, so the caller must leave the answer to the daemon.
    Unreproducible,
}

/// `command_policy_repair_page_url` from the page the locator's daemon URL
/// names, with `auth_token` what `load_guard_daemon_auth_token` would read.
/// Both of Python's `is_loopback_approval_url` checks fall out of the link
/// shape: signing leaves the host alone, so a loopback page stays loopback.
pub(crate) fn repair_page_url(
    page: &str,
    auth_token: impl FnOnce() -> Option<String>,
    now_micros: i64,
) -> RepairPage {
    let Some(link) = approval_link(page) else {
        return if maybe_loopback(page) {
            RepairPage::Unreproducible
        } else {
            RepairPage::Absent
        };
    };
    if !link.loopback {
        return RepairPage::Absent;
    }
    let Some(token) = auth_token() else {
        return RepairPage::Absent;
    };
    match browser_url(&link, &token, PROTECTION_REPAIR_SURFACE, now_micros) {
        Some(url) => RepairPage::Signed(url),
        None => RepairPage::Unreproducible,
    }
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
    let signed_url = browser_url(&link, token, APPROVAL_CENTER_SURFACE, now_micros)?;
    if stripped.contains(&signed_url) || carries_handoff_link(stripped, approval_url) {
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

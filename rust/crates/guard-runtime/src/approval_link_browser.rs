//! The link a blocked action opens in the browser: the review link for the
//! queued request, carrying the browser session's fragment (its local
//! approval token) when both point at the same approval center. Ported from
//! `surface_server.py` (`_browser_url_for_review`, `_merged_fragment`).
//!
//! The parsing follows CPython's `urlparse`/`urlunparse`: a URL `urlsplit`
//! refuses keeps the browser link, and the review link is rebuilt with its
//! scheme lowercased and an empty `;params`, `?query` or `#fragment` dropped.

use crate::consumer_url::{url_hostname, url_parses};
use crate::runner_sync_url::{parse_qsl, urlencode, urlsplit, urlunsplit, Split};

const LOCAL_HOSTS: [&str; 5] = ["0.0.0.0", "::", "127.0.0.1", "::1", "localhost"];
const USES_PARAMS: [&str; 16] = [
    "", "ftp", "hdl", "prospero", "http", "imap", "https", "shttp", "rtsp", "rtsps", "rtspu",
    "sip", "sips", "mms", "sftp", "tel",
];

/// `_browser_url_for_review(browser_url, review_url)`.
pub(super) fn browser_url_for_review(
    browser: Option<&str>,
    review: Option<&str>,
) -> Option<String> {
    let (Some(browser), Some(review)) = (browser, review) else {
        return review.or(browser).map(str::to_owned);
    };
    if !url_parses(browser) || !url_parses(review) {
        return Some(browser.to_owned());
    }
    let (browser_parts, review_parts) = (urlsplit(browser), urlsplit(review));
    if review_parts.scheme.is_empty() || review_parts.netloc.is_empty() {
        return Some(browser.to_owned());
    }
    if browser_parts.scheme.is_empty() || browser_parts.netloc.is_empty() {
        return Some(review.to_owned());
    }
    let same_origin = (&browser_parts.scheme, &browser_parts.netloc)
        == (&review_parts.scheme, &review_parts.netloc);
    if !same_origin && !same_local_approval_port(browser, &browser_parts, review, &review_parts) {
        return Some(review.to_owned());
    }
    let fragment = merged_fragment(&review_parts.fragment, &browser_parts.fragment);
    Some(urlunsplit(
        &review_parts.scheme,
        &review_parts.netloc,
        &unparsed_path(&review_parts),
        &review_parts.query,
        &fragment,
    ))
}

fn same_local_approval_port(browser: &str, left: &Split, review: &str, right: &Split) -> bool {
    let local =
        |url: &str| url_hostname(url).is_some_and(|host| LOCAL_HOSTS.contains(&host.as_str()));
    if !local(browser) || !local(review) {
        return false;
    }
    match (port(&left.netloc), port(&right.netloc)) {
        (Ok(left), Ok(right)) => left == right,
        _ => false,
    }
}

/// `SplitResult.port`: `Err` where Python raises `ValueError`.
fn port(netloc: &str) -> Result<Option<u32>, ()> {
    let hostinfo = netloc.rsplit_once('@').map_or(netloc, |(_, tail)| tail);
    let port = match hostinfo.split_once('[') {
        Some((_, bracketed)) => bracketed.split_once(']').map_or("", |(_, tail)| tail),
        None => hostinfo,
    };
    let port = port.split_once(':').map_or("", |(_, port)| port);
    if port.is_empty() {
        return Ok(None);
    }
    if !port.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(());
    }
    let digits = port.trim_start_matches('0');
    if digits.len() > 5 {
        return Err(());
    }
    let value = digits.parse::<u32>().unwrap_or(0);
    if value > 65_535 {
        return Err(());
    }
    Ok(Some(value))
}

/// The path `urlunparse` writes back: `urlparse` splits `;params` off the
/// last segment for these schemes and an empty one is not restored.
fn unparsed_path(parts: &Split) -> String {
    let path = parts.path.as_str();
    if !USES_PARAMS.contains(&parts.scheme.as_str()) || !path.contains(';') {
        return path.to_owned();
    }
    let at = match path.rfind('/') {
        Some(slash) => path[slash..].find(';').map(|at| slash + at),
        None => path.find(';'),
    };
    match at {
        Some(at) if at + 1 == path.len() => path[..at].to_owned(),
        _ => path.to_owned(),
    }
}

/// `_merged_fragment`: the review fragment's pairs, minus the keys the
/// browser fragment sets, then the browser fragment's pairs.
fn merged_fragment(primary: &str, extra: &str) -> String {
    let extra = parse_qsl(extra);
    let mut merged: Vec<(String, String)> = parse_qsl(primary)
        .into_iter()
        .filter(|(key, _)| !extra.iter().any(|(extra_key, _)| extra_key == key))
        .collect();
    merged.extend(extra);
    urlencode(&merged)
}

#[cfg(test)]
#[path = "approval_link_browser_tests.rs"]
mod tests;

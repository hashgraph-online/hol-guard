//! Python 3.12 `urllib.parse.urlsplit(url).hostname`, including every check
//! that makes `urlsplit` raise. A URL that would raise has no host.

use crate::python_netloc::{
    after_last_at, bracketed_netloc_valid, netloc_normalization_valid, valid_scheme,
};

/// The hostname Python reports for `url`, or `None` when it has none or
/// `urlsplit` rejects the URL.
pub(super) fn url_hostname(url: &str) -> Option<String> {
    let rest = url
        .split_once(':')
        .filter(|(scheme, _)| valid_scheme(scheme))
        .map_or(url, |(_, rest)| rest);
    let after_slashes = rest.strip_prefix("//")?;
    let netloc_end = after_slashes
        .find(['/', '?', '#'])
        .unwrap_or(after_slashes.len());
    let netloc = &after_slashes[..netloc_end];
    let open = netloc.contains('[');
    if open != netloc.contains(']') || (open && !bracketed_netloc_valid(netloc)) {
        return None;
    }
    if !netloc_normalization_valid(netloc) {
        return None;
    }
    let host_info = after_last_at(netloc);
    let hostname = match host_info.split_once('[') {
        Some((_, bracketed)) => bracketed.split(']').next().unwrap_or_default(),
        None => host_info.split(':').next().unwrap_or_default(),
    };
    if hostname.is_empty() {
        return None;
    }
    let (host, zone) = match hostname.split_once('%') {
        Some((host, zone)) => (host, Some(zone)),
        None => (hostname, None),
    };
    let mut joined = host.to_lowercase();
    if let Some(zone) = zone {
        joined.push('%');
        joined.push_str(zone);
    }
    Some(joined.to_lowercase())
}

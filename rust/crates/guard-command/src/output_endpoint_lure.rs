//! A fetched page that steers the agent's data to someone else's server.
//!
//! A page that tells the reader to send their telemetry, logs or other data
//! to an address on a different site than the page itself is how an attacker
//! gets an agent to wire a collection endpoint into the project: the agent
//! summarises the page, then writes the address into the code. A page that
//! names its own service's address (a vendor's documentation pointing at the
//! vendor's intake), or a local collector, is ordinary setup advice.

use std::sync::LazyLock;

use regex::Regex;

static STEERING: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(concat!(
        r"(?i)\b(?:point|send|route|forward|redirect|ship|pipe|post|report|stream|upload|export)",
        r"\s+(?:all\s+(?:of\s+)?)?(?:your|the|its|their|all)\s+(?:[a-z][a-z-]*\s+){0,2}?",
        r"(?:telemetry|analytics|logs?|metrics|events|traces|crash(?:\s+|-)reports?|",
        r"error\s+reports?|usage(?:\s+data)?|data|webhooks?)\b",
        r"[^.\n]{0,40}?\b(?:to|at)\s+<?(?P<url>https?://[^\s<>()\[\]`'\x22]+)",
    ))
    .expect("endpoint lure pattern compiles")
});

/// The host of an `http(s)` URL, lowercased, without user info, port or a
/// trailing dot.
fn host(url: &str) -> Option<String> {
    let rest = url.split_once("://")?.1;
    let authority = rest.split(['/', '?', '#']).next()?;
    let authority = authority
        .rsplit_once('@')
        .map_or(authority, |(_, host)| host);
    let host = if let Some(bracketed) = authority.strip_prefix('[') {
        bracketed.split(']').next()?
    } else {
        authority.split(':').next()?
    };
    let host = host.trim_end_matches('.').to_ascii_lowercase();
    (!host.is_empty()).then_some(host)
}

/// Whether `host` is this machine or a private network: a local collector
/// is not data leaving the user's hands.
fn local(host: &str) -> bool {
    if host == "localhost"
        || [".localhost", ".local", ".internal", ".lan"]
            .iter()
            .any(|suffix| host.ends_with(suffix))
    {
        return true;
    }
    if let Ok(address) = host.parse::<std::net::IpAddr>() {
        return match address {
            std::net::IpAddr::V4(v4) => {
                v4.is_loopback() || v4.is_private() || v4.is_link_local() || v4.is_unspecified()
            }
            std::net::IpAddr::V6(v6) => v6.is_loopback() || v6.is_unspecified(),
        };
    }
    false
}

/// The site a host belongs to: its last two labels, or three when the
/// second-to-last is a short public suffix label such as `co.uk`.
fn site(host: &str) -> &str {
    let labels: Vec<&str> = host.split('.').collect();
    let keep = if labels.len() >= 3
        && labels[labels.len() - 1].len() == 2
        && labels[labels.len() - 2].len() <= 3
    {
        3
    } else {
        2
    };
    if labels.len() <= keep {
        return host;
    }
    let skipped: usize = labels[..labels.len() - keep]
        .iter()
        .map(|label| label.len() + 1)
        .sum();
    &host[skipped..]
}

/// Whether text fetched from `page_url` tells the reader to send their data
/// to a server on another site. Without a page address there is nothing to
/// compare against, so nothing is found.
#[must_use]
pub fn outside_endpoint_lure(text: &str, page_url: Option<&str>) -> bool {
    let Some(page_site) = page_url.and_then(host) else {
        return false;
    };
    let page_site = site(&page_site).to_owned();
    STEERING.captures_iter(text).any(|found| {
        found
            .name("url")
            .and_then(|url| host(url.as_str()))
            .is_some_and(|target| !local(&target) && site(&target) != page_site)
    })
}

#[cfg(test)]
#[path = "output_endpoint_lure_tests.rs"]
mod tests;

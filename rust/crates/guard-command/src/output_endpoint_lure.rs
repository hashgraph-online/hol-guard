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
use url::{Host, Url};

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

/// Second-level labels under which a country code registers names, as in
/// `example.co.uk`. Any other two-letter top-level domain (`x.ai`, `fly.io`)
/// registers names directly under itself.
const COUNTRY_SECOND_LEVEL: [&str; 9] = ["co", "com", "org", "net", "ac", "gov", "edu", "ne", "or"];

/// Hosting domains that hand each customer their own subdomain. Two of
/// their subdomains belong to different owners, so each is its own site.
const SHARED_HOSTING: [&str; 21] = [
    "github.io",
    "gitlab.io",
    "vercel.app",
    "netlify.app",
    "pages.dev",
    "workers.dev",
    "herokuapp.com",
    "azurewebsites.net",
    "cloudfront.net",
    "appspot.com",
    "web.app",
    "firebaseapp.com",
    "blogspot.com",
    "onrender.com",
    "fly.dev",
    "glitch.me",
    "repl.co",
    "ngrok.io",
    "ngrok-free.app",
    "ngrok.app",
    "trycloudflare.com",
];

/// Where a URL sends its request, as the URL parser reads it. Reading the
/// raw text instead would let `https://drop.example\@localhost/` pass as
/// local, though the request goes to `drop.example`.
fn host(url: &str) -> Option<Host<String>> {
    let parsed = Url::parse(url).ok()?;
    if !matches!(parsed.scheme(), "http" | "https") {
        return None;
    }
    match parsed.host()? {
        Host::Domain(domain) => {
            let domain = domain.trim_end_matches('.').to_ascii_lowercase();
            (!domain.is_empty()).then_some(Host::Domain(domain))
        }
        Host::Ipv4(address) => Some(Host::Ipv4(address)),
        Host::Ipv6(address) => Some(Host::Ipv6(address)),
    }
}

/// Whether `host` is this machine or a private network: a local collector
/// is not data leaving the user's hands.
fn local(host: &Host<String>) -> bool {
    match host {
        Host::Domain(domain) => {
            domain == "localhost"
                || [".localhost", ".local", ".internal", ".lan"]
                    .iter()
                    .any(|suffix| domain.ends_with(suffix))
        }
        Host::Ipv4(v4) => {
            v4.is_loopback() || v4.is_private() || v4.is_link_local() || v4.is_unspecified()
        }
        Host::Ipv6(v6) => {
            let first = v6.segments()[0];
            v6.is_loopback()
                || v6.is_unspecified()
                // Unique local `fc00::/7` and link-local `fe80::/10`.
                || first & 0xfe00 == 0xfc00
                || first & 0xffc0 == 0xfe80
                || v6.to_ipv4_mapped().is_some_and(|v4| local(&Host::Ipv4(v4)))
        }
    }
}

/// The site a domain belongs to: its registered name, one label under a
/// country's second level (`shop.co.uk`) or under a shared hosting domain
/// (`project.github.io`), and otherwise its last two labels. Under
/// `amazonaws.com` each whole host is its own site: S3 names a bucket
/// before its service and region labels (`bucket.s3.us-east-1`), so no fixed
/// label count separates one customer from another.
fn site(domain: &str) -> &str {
    if domain.ends_with(".amazonaws.com") {
        return domain;
    }
    let labels: Vec<&str> = domain.split('.').collect();
    let count = labels.len();
    let shared = SHARED_HOSTING
        .iter()
        .find(|suffix| domain.ends_with(&format!(".{suffix}")))
        .map(|suffix| suffix.split('.').count() + 1);
    let keep = shared.unwrap_or(
        if count >= 3
            && labels[count - 1].len() == 2
            && COUNTRY_SECOND_LEVEL.contains(&labels[count - 2])
        {
            3
        } else {
            2
        },
    );
    if count <= keep {
        return domain;
    }
    let skipped: usize = labels[..count - keep]
        .iter()
        .map(|label| label.len() + 1)
        .sum();
    &domain[skipped..]
}

/// Whether two hosts belong to the same owner: the same site for names,
/// the same address for IP addresses.
fn same_owner(page: &Host<String>, target: &Host<String>) -> bool {
    match (page, target) {
        (Host::Domain(page), Host::Domain(target)) => site(page) == site(target),
        _ => page == target,
    }
}

/// Whether text fetched from `page_url` tells the reader to send their data
/// to a server on another site. Without a page address there is nothing to
/// compare against, so nothing is found.
#[must_use]
pub fn outside_endpoint_lure(text: &str, page_url: Option<&str>) -> bool {
    let Some(page) = page_url.and_then(host) else {
        return false;
    };
    STEERING.captures_iter(text).any(|found| {
        found
            .name("url")
            .and_then(|url| host(url.as_str()))
            .is_some_and(|target| !local(&target) && !same_owner(&page, &target))
    })
}

#[cfg(test)]
#[path = "output_endpoint_lure_tests.rs"]
mod tests;

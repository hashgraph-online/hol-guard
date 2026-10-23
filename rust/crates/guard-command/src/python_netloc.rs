//! The netloc half of CPython 3.12 `urllib.parse`, plus the `ipaddress`
//! predicates a redacted endpoint is classified with.
//!
//! `urlsplit` rejects a URL outright when its netloc fails one of these
//! checks, and `inventory_contract_redaction` turns that rejection into
//! `malformed_url_redacted`, so each check is a redaction decision:
//!
//! * a bracketed host must be an IPvFuture literal or an IPv6 address, and an
//!   IPv4 address in brackets is an error rather than a host;
//! * a non-ASCII netloc whose NFKC normalization introduces `/?#@:` is
//!   rejected, because IDNA would later resolve it to a different authority.
//!
//! The address validity rules are CPython's, not the platform resolver's:
//! `010.0.0.1` is not an IPv4 address, and an IPv6 literal is capped at 45
//! characters with at most one `::`.

use std::net::{Ipv4Addr, Ipv6Addr};

use unicode_normalization::UnicodeNormalization;

use crate::restricted_archive_address::{ipv4_is_private, ipv6_is_private};

/// `urllib.parse.scheme_chars`, minus the alphanumerics.
const SCHEME_PUNCTUATION: &str = "+-.";

/// `_NetlocResultMixinStr._hostinfo`: the host and the raw port text.
pub(crate) fn host_info(netloc: &str) -> (&str, Option<&str>) {
    let host_and_port = after_last_at(netloc);
    let (hostname, port) = match host_and_port.split_once('[') {
        Some((_, bracketed)) => {
            let (hostname, after) = bracketed.split_once(']').unwrap_or((bracketed, ""));
            (hostname, after.split_once(':').map_or("", |(_, port)| port))
        }
        None => host_and_port
            .split_once(':')
            .map_or((host_and_port, ""), |(host, port)| (host, port)),
    };
    (hostname, (!port.is_empty()).then_some(port))
}

pub(crate) fn starts_with_ascii_alphabetic(url: &str) -> bool {
    url.chars()
        .next()
        .is_some_and(|first| first.is_ascii_alphabetic())
}

/// Every character of a candidate scheme is in `scheme_chars`.
pub(crate) fn is_scheme(scheme: &str) -> bool {
    scheme
        .chars()
        .all(|value| value.is_ascii_alphanumeric() || SCHEME_PUNCTUATION.contains(value))
}

/// A scheme that also satisfies `urlsplit`'s leading-character rule.
pub(crate) fn valid_scheme(scheme: &str) -> bool {
    starts_with_ascii_alphabetic(scheme) && is_scheme(scheme)
}

/// `netloc.rpartition('@')[2]`.
pub(crate) fn after_last_at(netloc: &str) -> &str {
    netloc.rsplit('@').next().unwrap_or_default()
}

/// `_check_bracketed_netloc`.
pub(crate) fn bracketed_netloc_valid(netloc: &str) -> bool {
    let host_and_port = after_last_at(netloc);
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
        None => host_and_port.split(':').next().unwrap_or_default(),
    };
    bracketed_host_valid(hostname)
}

/// `_check_bracketed_host`: an IPvFuture literal or an IPv6 address.
fn bracketed_host_valid(hostname: &str) -> bool {
    match hostname.strip_prefix('v') {
        Some(future) => {
            let digits = future.chars().take_while(char::is_ascii_hexdigit).count();
            let tail = future[digits..].strip_prefix('.').unwrap_or_default();
            digits > 0 && !tail.is_empty() && !tail.contains('\n')
        }
        None => !ipv4_valid(hostname) && ipv6_valid(hostname),
    }
}

/// `_checknetloc`: no NFKC-normalized character may become a URL delimiter.
pub(crate) fn netloc_normalization_valid(netloc: &str) -> bool {
    if netloc.is_ascii() {
        return true;
    }
    let stripped = netloc.replace(['@', ':', '#', '?'], "");
    let normalized = stripped.nfkc().collect::<String>();
    normalized == stripped || !normalized.contains(['/', '?', '#', '@', ':'])
}

/// `ipaddress.ip_address(host).is_private`, or `None` when `host` is not an
/// address at all.
pub(crate) fn ip_address_is_private(host: &str) -> Option<bool> {
    // `ipv4_valid`/`ipv6_valid` decide acceptance, so the answer follows
    // `ipaddress` rather than whichever literals `std` happens to parse; the
    // `std` parsers only turn an accepted literal into its octets.
    if ipv4_valid(host) {
        return host.parse::<Ipv4Addr>().ok().map(ipv4_is_private);
    }
    if !ipv6_valid(host) {
        return None;
    }
    let literal = host.split_once('%').map_or(host, |(literal, _)| literal);
    let address = literal.parse::<Ipv6Addr>().ok()?;
    // `IPv6Address.is_private` defers to the mapped IPv4 address when there is
    // one, so `::ffff:10.0.0.1` is private and `::ffff:8.8.8.8` is not.
    Some(match address.to_ipv4_mapped() {
        Some(mapped) => ipv4_is_private(mapped),
        None => ipv6_is_private(address),
    })
}

/// `ipaddress.IPv4Address`.
fn ipv4_valid(address: &str) -> bool {
    let octets = address.split('.').collect::<Vec<&str>>();
    octets.len() == 4
        && octets.iter().all(|octet| {
            !octet.is_empty()
                && octet.len() <= 3
                && octet.bytes().all(|byte| byte.is_ascii_digit())
                && (*octet == "0" || !octet.starts_with('0'))
                && octet.parse::<u16>().is_ok_and(|value| value <= 255)
        })
}

/// `ipaddress.IPv6Address`, including the scope id and embedded IPv4 rules.
fn ipv6_valid(text: &str) -> bool {
    let address = match text.split_once('%') {
        Some((address, scope)) => {
            if scope.is_empty() || scope.contains('%') {
                return false;
            }
            address
        }
        None => text,
    };
    if address.is_empty() || address.chars().count() > 45 {
        return false;
    }
    let mut parts = address.splitn(10, ':').collect::<Vec<&str>>();
    if parts.len() < 3 {
        return false;
    }
    if parts.last().is_some_and(|last| last.contains('.')) {
        if !parts.pop().is_some_and(ipv4_valid) {
            return false;
        }
        parts.extend(["0", "0"]);
    }
    if parts.len() > 9 {
        return false;
    }
    let count = parts.len();
    let mut skip_index = None;
    for (index, part) in parts.iter().enumerate().take(count - 1).skip(1) {
        if part.is_empty() {
            if skip_index.is_some() {
                return false;
            }
            skip_index = Some(index);
        }
    }
    let (high, low) = match skip_index {
        Some(skip) => {
            let mut high = skip;
            let mut low = count - skip - 1;
            if parts[0].is_empty() {
                high -= 1;
                if high != 0 {
                    return false;
                }
            }
            if parts[count - 1].is_empty() {
                low -= 1;
                if low != 0 {
                    return false;
                }
            }
            if high + low >= 8 {
                return false;
            }
            (high, low)
        }
        None => {
            if count != 8 || parts[0].is_empty() || parts[count - 1].is_empty() {
                return false;
            }
            (count, 0)
        }
    };
    parts[..high]
        .iter()
        .chain(&parts[count - low..])
        .all(|hextet| {
            (1..=4).contains(&hextet.len()) && hextet.bytes().all(|byte| byte.is_ascii_hexdigit())
        })
}

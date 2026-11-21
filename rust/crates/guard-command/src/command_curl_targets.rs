//! The bounded authority/path subset consumed by the Python curl matcher.
//!
//! Mirrors CPython 3.12 urlsplit behavior for ASCII authorities, including
//! ports, credentials, IPv6 zones and IPvFuture. Non-ASCII authorities require
//! NFKC validation and remain an explicit unsupported result, never a no-match.

use std::collections::BTreeSet;
use std::net::Ipv6Addr;

pub(super) fn matches_target(
    target: &str,
    service_ports: &BTreeSet<u16>,
) -> Result<bool, &'static str> {
    let normalized = target.trim_matches(['\'', '"']);
    let lowered = normalized.to_lowercase();
    if lowered.starts_with("$elasticsearch_") || lowered.starts_with("${elasticsearch_") {
        return Ok(lowered.contains('/'));
    }
    let explicit = normalized.contains("://");
    let input = if explicit {
        normalized.to_owned()
    } else {
        format!("//{normalized}")
    };
    let input: String = input
        .trim_start_matches(|character: char| character <= '\u{0020}')
        .chars()
        .filter(|character| !matches!(character, '\t' | '\n' | '\r'))
        .collect();
    let mut rest = input.as_str();
    let mut scheme = String::new();
    if let Some(colon) = rest.find(':') {
        let candidate = &rest[..colon];
        if candidate
            .as_bytes()
            .first()
            .is_some_and(u8::is_ascii_alphabetic)
            && candidate
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b"+-.".contains(&byte))
        {
            scheme = candidate.to_ascii_lowercase();
            rest = &rest[colon + 1..];
        }
    }
    if (explicit && !matches!(scheme.as_str(), "http" | "https"))
        || (!explicit && !scheme.is_empty())
    {
        return Ok(false);
    }
    let (netloc, path) = if let Some(authority) = rest.strip_prefix("//") {
        let end = authority.find(['/', '?', '#']).unwrap_or(authority.len());
        (&authority[..end], &authority[end..])
    } else {
        ("", rest)
    };
    if !netloc.is_ascii() {
        return Err("unsupported_url_authority_normalization");
    }
    if netloc.contains('[') != netloc.contains(']') {
        return Ok(false);
    }
    let hostinfo = netloc.rsplit('@').next().unwrap_or("");
    let (hostname, port_text) = if netloc.contains('[') {
        if let Some(bracketed) = hostinfo.strip_prefix('[') {
            let Some((hostname, trailing)) = bracketed.split_once(']') else {
                return Ok(false);
            };
            if (!trailing.is_empty() && !trailing.starts_with(':'))
                || !valid_bracketed_host(hostname)
            {
                return Ok(false);
            }
            (hostname, trailing.strip_prefix(':').unwrap_or(""))
        } else {
            // Brackets only in user info still trigger CPython's host check.
            let (hostname, port) = hostinfo.split_once(':').unwrap_or((hostinfo, ""));
            if !valid_bracketed_host(hostname) {
                return Ok(false);
            }
            (hostname, port)
        }
    } else {
        hostinfo.split_once(':').unwrap_or((hostinfo, ""))
    };
    let port = if port_text.is_empty() {
        None
    } else {
        // CPython's default integer conversion limit also applies to a port.
        if port_text.len() > 4_300 || !port_text.bytes().all(|byte| byte.is_ascii_digit()) {
            return Ok(false);
        }
        let Ok(port) = port_text.parse::<u16>() else {
            return Ok(false);
        };
        Some(port)
    };
    let hostname = if let Some((host, zone)) = hostname.split_once('%') {
        format!("{}%{zone}", host.to_ascii_lowercase())
    } else {
        hostname.to_ascii_lowercase()
    };
    let path = path.split(['?', '#']).next().unwrap_or("");
    let recognizable = port.is_some_and(|port| service_ports.contains(&port))
        || hostname.split('.').any(|label| label == "elasticsearch");
    Ok(recognizable && !matches!(path, "" | "/"))
}

fn valid_bracketed_host(hostname: &str) -> bool {
    if let Some(future) = hostname.strip_prefix('v') {
        return future.split_once('.').is_some_and(|(version, address)| {
            !version.is_empty()
                && version.bytes().all(|byte| byte.is_ascii_hexdigit())
                && !address.is_empty()
        });
    }
    let address = if let Some((address, zone)) = hostname.split_once('%') {
        if zone.is_empty() || zone.contains('%') {
            return false;
        }
        address
    } else {
        hostname
    };
    address.parse::<Ipv6Addr>().is_ok()
}

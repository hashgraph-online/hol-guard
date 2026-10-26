//! `urllib.parse.urlsplit` hostname and scheme extraction.
//!
//! Capability extraction reads hosts and schemes from artifact text and from
//! the declared URL. Where `urlsplit` raises (`ValueError`) the candidate is
//! skipped, so malformed bracketed hosts and netlocs that normalize into a
//! delimiter yield nothing rather than a guessed host.

use std::net::Ipv6Addr;

use unicode_normalization::UnicodeNormalization;

const SCHEME_CHARS: &str = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789+-.";

struct Split {
    scheme: String,
    netloc: String,
}

fn split(url: &str) -> Option<Split> {
    let trimmed = url.trim_start_matches(|character: char| character <= ' ');
    let cleaned: String = trimmed
        .chars()
        .filter(|character| !matches!(character, '\t' | '\r' | '\n'))
        .collect();
    let mut rest = cleaned.as_str();
    let mut scheme = String::new();
    if let Some(index) = rest.find(':').filter(|index| *index > 0) {
        let head = &rest[..index];
        let first = head.chars().next().unwrap_or('0');
        if first.is_ascii_alphabetic()
            && head
                .chars()
                .all(|character| SCHEME_CHARS.contains(character))
        {
            scheme = head.to_lowercase();
            rest = &rest[index + 1..];
        }
    }
    let mut netloc = String::new();
    if let Some(after) = rest.strip_prefix("//") {
        let end = after.find(['/', '?', '#']).unwrap_or(after.len());
        netloc = after[..end].to_owned();
        if netloc.contains('[') != netloc.contains(']') {
            return None;
        }
        if let Some(inner) = netloc
            .split_once('[')
            .and_then(|(_, tail)| tail.split_once(']'))
        {
            if !valid_bracketed_host(inner.0) {
                return None;
            }
        }
    }
    netloc_normalizes_safely(&netloc).then_some(Split { scheme, netloc })
}

fn valid_bracketed_host(host: &str) -> bool {
    let future = host.strip_prefix('v');
    if let Some(tail) = future {
        return tail.split_once('.').is_some_and(|(version, body)| {
            !version.is_empty()
                && version
                    .chars()
                    .all(|character| character.is_ascii_hexdigit())
                && !body.is_empty()
        });
    }
    let address = host.split('%').next().unwrap_or(host);
    address.parse::<Ipv6Addr>().is_ok()
}

fn netloc_normalizes_safely(netloc: &str) -> bool {
    if netloc.is_ascii() {
        return true;
    }
    let stripped: String = netloc
        .chars()
        .filter(|c| !matches!(c, '@' | ':' | '#' | '?'))
        .collect();
    let normalized: String = stripped.nfkc().collect();
    stripped == normalized || !normalized.contains(['/', '?', '#', '@', ':'])
}

/// Lowercased `SplitResult.hostname`, or `None` when absent or unparsable.
pub(crate) fn url_hostname(url: &str) -> Option<String> {
    let netloc = split(url)?.netloc;
    let info = netloc
        .rsplit_once('@')
        .map_or(netloc.as_str(), |(_, tail)| tail);
    let host = match info.split_once('[') {
        Some((_, bracketed)) => bracketed.split(']').next().unwrap_or(""),
        None => info.split(':').next().unwrap_or(""),
    };
    if host.is_empty() {
        return None;
    }
    let (name, zone) = host
        .split_once('%')
        .map_or((host, None), |(n, z)| (n, Some(z)));
    Some(match zone {
        Some(zone) => format!("{}%{zone}", name.to_lowercase()),
        None => name.to_lowercase(),
    })
}

/// Lowercased `SplitResult.scheme`, or `None` when absent or unparsable.
pub(crate) fn url_scheme(url: &str) -> Option<String> {
    let scheme = split(url)?.scheme;
    (!scheme.is_empty()).then_some(scheme)
}

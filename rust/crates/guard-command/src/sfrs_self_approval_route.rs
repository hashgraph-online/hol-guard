//! A raw HTTP request to a local Guard approval route, found in the command
//! text whatever client sends it.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::LazyLock;

use percent_encoding::percent_decode_str;
use regex::Regex;

/// An authority followed by a path, with or without a scheme. The leading
/// class keeps a match from starting inside another host or path, and the
/// path stops at shell, quoting and argument punctuation so a URL inside
/// `python -c "..."` or a JSON body is still found.
static URL: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r#"(?i)(?:^|[^A-Za-z0-9._~%/:\[\]-])(?:https?://)?([A-Za-z0-9._~%:@\[\]-]+)(/[^\s'"`<>|;&()\\,]*)"#,
    )
    .expect("loopback URL pattern")
});

/// Whether the text names a loopback URL whose path is one of the local
/// Guard routes that resolve requests or save decisions. The raw text, the
/// text with shell quoting removed, and each shell word are all checked, so
/// `http://127.0.0.1:4781/v1/'requests'/x/approve` is found too.
pub(crate) fn names_guard_approval_route(command_text: &str, words: &[String]) -> bool {
    let unquoted: String = command_text
        .chars()
        .filter(|c| !matches!(c, '\'' | '"' | '\\'))
        .collect();
    std::iter::once(command_text)
        .chain(std::iter::once(unquoted.as_str()))
        .chain(words.iter().map(String::as_str))
        .any(text_names_route)
}

fn text_names_route(text: &str) -> bool {
    URL.captures_iter(text).any(|captures| {
        let (Some(authority), Some(path)) = (captures.get(1), captures.get(2)) else {
            return false;
        };
        is_loopback_authority(authority.as_str()) && is_approval_write_path(path.as_str())
    })
}

/// `user@host:port`, where the host is a loopback or unspecified address in
/// any spelling an HTTP client accepts.
fn is_loopback_authority(authority: &str) -> bool {
    let host_port = authority
        .rsplit_once('@')
        .map_or(authority, |(_, rest)| rest);
    let host_port = percent_decode_str(host_port).decode_utf8_lossy();
    if let Some(rest) = host_port.strip_prefix('[') {
        let Some((inner, _)) = rest.split_once(']') else {
            return false;
        };
        let inner = inner.split('%').next().unwrap_or_default();
        return inner.parse::<Ipv6Addr>().is_ok_and(|address| {
            let ip = IpAddr::V6(address);
            ip.is_loopback()
                || ip.is_unspecified()
                || address
                    .to_ipv4_mapped()
                    .is_some_and(|v4| v4.is_loopback() || v4.is_unspecified())
        });
    }
    let host = host_port.split(':').next().unwrap_or_default();
    let host = host.trim_end_matches('.').to_ascii_lowercase();
    host == "localhost"
        || host.ends_with(".localhost")
        || inet_aton(&host).is_some_and(|v4| v4.is_loopback() || v4.is_unspecified())
}

/// The BSD `inet_aton` forms clients accept: one to four parts, each decimal,
/// `0x` hex or leading-zero octal, the last part filling the remaining bytes
/// (`127.1`, `2130706433`, `0x7f.0.0.1`).
fn inet_aton(host: &str) -> Option<Ipv4Addr> {
    let parts: Vec<u64> = host
        .split('.')
        .map(|part| {
            let lower = part.to_ascii_lowercase();
            if let Some(hex) = lower.strip_prefix("0x") {
                u64::from_str_radix(hex, 16).ok()
            } else if lower.len() > 1 && lower.starts_with('0') {
                u64::from_str_radix(&lower[1..], 8).ok()
            } else {
                lower.parse::<u64>().ok()
            }
        })
        .collect::<Option<_>>()?;
    let (last, head) = parts.split_last()?;
    if head.len() > 3 || head.iter().any(|part| *part > 255) {
        return None;
    }
    let tail_bits = 8 * (4 - head.len() as u32);
    if tail_bits < 64 && *last >= 1u64 << tail_bits {
        return None;
    }
    let address = head
        .iter()
        .fold(0u64, |acc, part| (acc << 8) | part)
        .checked_shl(tail_bits)?
        | last;
    u32::try_from(address).ok().map(Ipv4Addr::from)
}

/// The path as the server sees it: percent-decoded, with `.` and `..`
/// resolved the way clients normalize before sending.
fn is_approval_write_path(path: &str) -> bool {
    let path = path.split(['?', '#']).next().unwrap_or_default();
    let decoded = percent_decode_str(path).decode_utf8_lossy();
    let mut parts: Vec<&str> = Vec::new();
    for part in decoded.split(['/', '\\']) {
        match part {
            "" | "." => {}
            ".." => {
                parts.pop();
            }
            _ => parts.push(part),
        }
    }
    matches!(
        parts.as_slice(),
        ["v1", "requests", _, "approve" | "block"]
            | ["approvals", _, "decision"]
            | ["v1", "approvals", _, "decision"]
            | ["v1", "requests", "bulk-allow-once" | "clear"]
            | ["v1", "policy", "decisions" | "clear"]
    )
}

//! Port of `normalized_remote_mcp_url` (`runtime/mcp_server_contribution.py`).
//!
//! Callers supply arbitrary identity commands, so this follows CPython's
//! `urlsplit` host/port rules (3.12 profile) rather than the stricter grammar
//! the packaged program is admitted with. Only the endpoint identity (the
//! normalized URL without its query) is returned; a query is still validated.

use std::net::{Ipv4Addr, Ipv6Addr};

use crate::native_command_program::{public_ipv4, public_ipv6};

/// `ipaddress` `is_global`: unlike the admission grammar, multicast is global.
fn global_ipv4(address: Ipv4Addr) -> bool {
    address.is_multicast() || public_ipv4(address)
}

fn global_ipv6(address: Ipv6Addr) -> bool {
    address.is_multicast() || public_ipv6(address)
}

const MAX_ENDPOINT_BYTES: usize = 260;

/// `remote_mcp_endpoint_identity`.
pub(crate) fn remote_mcp_endpoint_identity(value: &str) -> Option<String> {
    normalized_endpoint(value)
}

fn is_unreserved(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~')
}

fn is_component_char(byte: u8, query: bool) -> bool {
    is_unreserved(byte)
        || matches!(
            byte,
            b'!' | b'$'
                | b'&'
                | b'\''
                | b'('
                | b')'
                | b'*'
                | b'+'
                | b','
                | b';'
                | b'='
                | b':'
                | b'@'
                | b'/'
        )
        || (query && byte == b'?')
}

/// `_normalized_remote_component`; input is ASCII.
fn normalized_component(value: &str, query: bool, empty_default: &str) -> Option<String> {
    let candidate = if value.is_empty() {
        empty_default
    } else {
        value
    }
    .as_bytes();
    let mut output = String::with_capacity(candidate.len());
    let mut index = 0;
    while index < candidate.len() {
        let byte = candidate[index];
        if byte != b'%' {
            if !is_component_char(byte, query) {
                return None;
            }
            output.push(char::from(byte));
            index += 1;
            continue;
        }
        if index + 2 >= candidate.len() {
            return None;
        }
        let (high, low) = (candidate[index + 1], candidate[index + 2]);
        if !high.is_ascii_hexdigit() || !low.is_ascii_hexdigit() {
            return None;
        }
        let decoded = (char::from(high).to_digit(16)? * 16 + char::from(low).to_digit(16)?) as u8;
        if decoded < 0x20 || decoded == 0x7f {
            return None;
        }
        if is_unreserved(decoded) {
            output.push(char::from(decoded));
        } else {
            output.push_str(&format!("%{decoded:02X}"));
        }
        index += 3;
    }
    Some(output)
}

/// `_remove_remote_dot_segments`.
fn remove_dot_segments(path: &str) -> String {
    let segments: Vec<&str> = path.split('/').collect();
    let mut resolved: Vec<&str> = Vec::new();
    for segment in &segments {
        match *segment {
            ".." => {
                resolved.pop();
            }
            "." => {}
            other => resolved.push(other),
        }
    }
    if matches!(segments.last(), Some(&".") | Some(&"..")) {
        resolved.push("");
    }
    let joined = resolved.join("/");
    let mut normalized = if joined.is_empty() {
        "/".to_owned()
    } else {
        joined
    };
    if path.starts_with('/') && !normalized.starts_with('/') {
        normalized.insert(0, '/');
    }
    normalized
}

fn valid_dns_hostname(host: &str) -> bool {
    host.len() <= 253
        && host.split('.').all(|label| {
            let bytes = label.as_bytes();
            (1..=63).contains(&bytes.len())
                && bytes[0].is_ascii_alphanumeric()
                && bytes[bytes.len() - 1].is_ascii_alphanumeric()
                && bytes
                    .iter()
                    .all(|b| b.is_ascii_alphanumeric() || *b == b'-')
        })
}

/// `ipaddress.ip_address` for a host that may carry an IPv6 scope id.
enum Address {
    V4(Ipv4Addr),
    V6(Ipv6Addr, Option<String>),
}

fn parse_address(text: &str) -> Option<Address> {
    if let Ok(address) = text.parse::<Ipv4Addr>() {
        return Some(Address::V4(address));
    }
    let (addr, scope) = match text.split_once('%') {
        None => (text, None),
        Some((_, scope)) if scope.is_empty() || scope.contains('%') => return None,
        Some((addr, scope)) => (addr, Some(scope.to_owned())),
    };
    addr.parse::<Ipv6Addr>().ok().map(|a| Address::V6(a, scope))
}

/// `str(IPv6Address)`: RFC 5952 compression of the longest run of two or more
/// zero groups, first run on a tie, never the embedded-IPv4 form.
fn format_ipv6(address: Ipv6Addr) -> String {
    let groups = address.segments();
    let (mut best_start, mut best_len) = (0usize, 0usize);
    let (mut start, mut len) = (0usize, 0usize);
    for (index, group) in groups.iter().enumerate() {
        if *group == 0 {
            if len == 0 {
                start = index;
            }
            len += 1;
            if len > best_len {
                best_start = start;
                best_len = len;
            }
        } else {
            len = 0;
        }
    }
    let hex = |slice: &[u16]| {
        slice
            .iter()
            .map(|g| format!("{g:x}"))
            .collect::<Vec<_>>()
            .join(":")
    };
    if best_len > 1 {
        format!(
            "{}::{}",
            hex(&groups[..best_start]),
            hex(&groups[best_start + best_len..])
        )
    } else {
        hex(&groups)
    }
}

/// The `urlsplit` netloc plus the path/query remainder for an `https` URL.
struct Split<'a> {
    netloc: &'a str,
    path: &'a str,
    query: &'a str,
    fragment: &'a str,
}

fn split_https(value: &str) -> Option<Split<'_>> {
    let rest = value
        .get(..6)
        .filter(|scheme| scheme.eq_ignore_ascii_case("https:"))?;
    let rest = &value[rest.len()..];
    let rest = rest.strip_prefix("//")?;
    let delimiter = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    let (netloc, remainder) = rest.split_at(delimiter);
    let (remainder, fragment) = remainder.split_once('#').unwrap_or((remainder, ""));
    let (path, query) = remainder.split_once('?').unwrap_or((remainder, ""));
    Some(Split {
        netloc,
        path,
        query,
        fragment,
    })
}

fn ipv_future(host: &str) -> bool {
    let Some(rest) = host.strip_prefix('v') else {
        return false;
    };
    let hex = rest.bytes().take_while(u8::is_ascii_hexdigit).count();
    hex > 0
        && rest[hex..]
            .strip_prefix('.')
            .is_some_and(|tail| !tail.is_empty())
}

/// `urlsplit` bracket checks and `hostname`/`port` extraction. `None` stands
/// for a `ValueError`, a userinfo, or an absent hostname.
fn host_and_port(netloc: &str) -> Option<(String, Option<&str>)> {
    let (open, close) = (netloc.contains('['), netloc.contains(']'));
    if open != close || netloc.contains('@') {
        return None;
    }
    let (hostname, port) = if open {
        // No data before the bracket, and none between `]` and the port.
        let bracketed = netloc.strip_prefix('[')?;
        let (hostname, after) = bracketed.split_once(']')?;
        let port = match after {
            "" => "",
            _ => after.strip_prefix(':')?,
        };
        if hostname.starts_with('v') {
            if !ipv_future(hostname) {
                return None;
            }
        } else if !matches!(parse_address(hostname), Some(Address::V6(..))) {
            return None;
        }
        (hostname, port)
    } else {
        netloc.split_once(':').unwrap_or((netloc, ""))
    };
    if hostname.is_empty() {
        return None;
    }
    Some((
        hostname.to_ascii_lowercase(),
        (!port.is_empty()).then_some(port),
    ))
}

fn port_is_default(port: Option<&str>) -> bool {
    let Some(port) = port else {
        return true;
    };
    port.bytes().all(|b| b.is_ascii_digit()) && port.trim_start_matches('0') == "443"
}

fn normalized_endpoint(value: &str) -> Option<String> {
    if value.is_empty() || !value.is_ascii() || value.bytes().any(|b| b <= 0x20 || b == 0x7f) {
        return None;
    }
    let split = split_https(value)?;
    if !split.fragment.is_empty() {
        return None;
    }
    let (raw_host, port) = host_and_port(split.netloc)?;
    if !port_is_default(port) || raw_host.ends_with("..") {
        return None;
    }
    let host = raw_host.strip_suffix('.').unwrap_or(&raw_host);
    if host.is_empty() {
        return None;
    }
    let host = match parse_address(host) {
        None => {
            if host.bytes().all(|b| b.is_ascii_digit() || b == b'.') {
                return None;
            }
            if host == "localhost"
                || host.ends_with(".localhost")
                || !host.contains('.')
                || !valid_dns_hostname(host)
            {
                return None;
            }
            host.to_owned()
        }
        Some(Address::V4(address)) => global_ipv4(address).then(|| address.to_string())?,
        Some(Address::V6(address, scope)) => match address.to_ipv4_mapped() {
            Some(mapped) => global_ipv4(mapped).then(|| mapped.to_string())?,
            None => {
                if !global_ipv6(address) {
                    return None;
                }
                match scope {
                    Some(scope) => format!("{}%{scope}", format_ipv6(address)),
                    None => format_ipv6(address),
                }
            }
        },
    };
    let netloc = if host.contains(':') {
        format!("[{host}]")
    } else {
        host
    };
    let path = remove_dot_segments(&normalized_component(split.path, false, "/")?);
    normalized_component(split.query, true, "")?;
    let endpoint = format!("https://{netloc}{path}");
    (endpoint.len() <= MAX_ENDPOINT_BYTES).then_some(endpoint)
}

#[cfg(test)]
#[path = "contributed_mcp_url_tests.rs"]
mod tests;

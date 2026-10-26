//! Public HTTPS endpoint admission for packaged MCP metadata.

// No DNS lookup or HTTP request occurs here. The interpreter uses this metadata
// only for tightening controls; a future network client must independently
// validate resolved addresses and redirects before connecting. IP exclusions
// follow the CPython 3.12 reference profile used by the authoring validator.
// Multicast endpoints are also rejected because they are not HTTPS servers.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

pub(crate) fn public_ipv4(address: Ipv4Addr) -> bool {
    let [a, b, c, _] = address.octets();
    if address.is_multicast() {
        return false;
    }
    if matches!(address.octets(), [192, 0, 0, 9 | 10]) {
        return true;
    }
    !(matches!(a, 0 | 10 | 127)
        || (a == 100 && (64..=127).contains(&b))
        || (a == 169 && b == 254)
        || (a == 172 && (16..=31).contains(&b))
        || (a == 192 && ((b == 0 && matches!(c, 0 | 2)) || b == 168))
        || (a == 198 && (matches!(b, 18 | 19) || (b == 51 && c == 100)))
        || (a == 203 && b == 0 && c == 113)
        || a >= 240)
}

pub(crate) fn public_ipv6(address: Ipv6Addr) -> bool {
    if let Some(mapped) = address.to_ipv4_mapped() {
        return public_ipv4(mapped);
    }
    if address.is_unspecified() || address.is_loopback() || address.is_multicast() {
        return false;
    }
    let s = address.segments();
    if s[0] == 0x2001 && s[1] & 0xfe00 == 0 {
        return matches!(s, [0x2001, 1, 0, 0, 0, 0, 0, 1 | 2])
            || s[1] == 3
            || (s[1] == 4 && s[2] == 0x112)
            || matches!(s[1] & 0xfff0, 0x20 | 0x30);
    }
    !(s[..3] == [0x64, 0xff9b, 1]
        || s[..4] == [0x100, 0, 0, 0]
        || s[..2] == [0x2001, 0xdb8]
        || s[0] == 0x2002
        || (s[0] == 0x3fff && s[1] & 0xf000 == 0)
        || s[0] & 0xfe00 == 0xfc00
        || s[0] & 0xffc0 == 0xfe80)
}

fn valid_dns_host(host: &str) -> bool {
    !host.is_empty()
        && host.len() <= 253
        && host.contains('.')
        && !host.eq_ignore_ascii_case("localhost")
        && !host.to_ascii_lowercase().ends_with(".localhost")
        && !host.bytes().all(|b| b.is_ascii_digit() || b == b'.')
        && host.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && label.as_bytes()[0].is_ascii_alphanumeric()
                && label.as_bytes()[label.len() - 1].is_ascii_alphanumeric()
                && label
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-')
        })
}

fn public_authority(authority: &str) -> bool {
    if let Some(rest) = authority.strip_prefix('[') {
        let Some((host, suffix)) = rest.split_once(']') else {
            return false;
        };
        return matches!(suffix, "" | ":443") && host.parse::<Ipv6Addr>().is_ok_and(public_ipv6);
    }
    let host = match authority.split_once(':') {
        Some((host, "443")) => host,
        Some(_) => return false,
        None => authority,
    };
    let host = host.strip_suffix('.').unwrap_or(host);
    match host.parse::<IpAddr>() {
        Ok(IpAddr::V4(address)) => public_ipv4(address),
        Ok(IpAddr::V6(_)) => false, // IPv6 URL hosts must be bracketed.
        Err(_) => valid_dns_host(host),
    }
}

fn valid_component(value: &str, query: bool) -> bool {
    let bytes = value.as_bytes();
    let mut index = 0;
    while index < bytes.len() {
        let byte = bytes[index];
        if byte == b'%' {
            let Some(escape) = bytes.get(index + 1..index + 3) else {
                return false;
            };
            let Some(high) = char::from(escape[0]).to_digit(16) else {
                return false;
            };
            let Some(low) = char::from(escape[1]).to_digit(16) else {
                return false;
            };
            let decoded = high * 16 + low;
            if decoded <= 0x20 || decoded == 0x7f {
                return false;
            }
            index += 3;
        } else if byte.is_ascii_alphanumeric()
            || b"-._~!$&'()*+,;=:@/".contains(&byte)
            || (query && byte == b'?')
        {
            index += 1;
        } else {
            return false;
        }
    }
    true
}

pub(crate) fn valid_remote_mcp_url(value: &str) -> bool {
    // Retain the existing native metadata bound. This is not a network URL
    // parser: accept only the explicit public-HTTPS grammar the compiler emits.
    if value.len() > 260 || !value.is_ascii() || value.bytes().any(|b| b <= 0x20 || b == 0x7f) {
        return false;
    }
    let Some(rest) = value.strip_prefix("https://") else {
        return false;
    };
    let boundary = rest.find(['/', '?']).unwrap_or(rest.len());
    let (authority, remainder) = rest.split_at(boundary);
    if !public_authority(authority) {
        return false;
    }
    let (path, query) = remainder.split_once('?').unwrap_or((remainder, ""));
    valid_component(path, false) && valid_component(query, true)
}

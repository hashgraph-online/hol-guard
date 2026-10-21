//! Python 3.12 `urllib.parse.urlsplit(url).hostname`, including every check
//! that makes `urlsplit` raise. A URL that would raise has no host.

use unicode_normalization::UnicodeNormalization;

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

fn valid_scheme(scheme: &str) -> bool {
    scheme
        .chars()
        .next()
        .is_some_and(|first| first.is_ascii_alphabetic())
        && scheme
            .chars()
            .all(|value| value.is_ascii_alphanumeric() || "+-.".contains(value))
}

fn after_last_at(netloc: &str) -> &str {
    netloc.rsplit('@').next().unwrap_or_default()
}

/// `_check_bracketed_netloc`.
fn bracketed_netloc_valid(netloc: &str) -> bool {
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
fn netloc_normalization_valid(netloc: &str) -> bool {
    if netloc.is_ascii() {
        return true;
    }
    let stripped = netloc.replace(['@', ':', '#', '?'], "");
    let normalized = stripped.nfkc().collect::<String>();
    normalized == stripped || !normalized.contains(['/', '?', '#', '@', ':'])
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

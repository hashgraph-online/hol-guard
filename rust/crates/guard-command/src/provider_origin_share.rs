//! Which origins and site groups may be shared with a provider (BP-T102, PRD 6.4).
//!
//! A provider learns `target.origin` and `target.site_group` only for public hosts. Loopback,
//! private and link-local addresses, every IP literal, single-label hosts and the reserved or
//! local-only suffixes never leave the device, so an integration cannot learn the user's internal
//! hosts. Anything that is not plainly a public DNS name is refused: the check only decides when a
//! value may be shared, so refusing an odd spelling costs one provider answer, never a protection.

/// Suffixes that name local, private or reserved namespaces. A host equal to one of these or
/// ending in `.` plus one of these is never shared.
const LOCAL_SUFFIXES: &[&str] = &[
    "local",
    "internal",
    "test",
    "localhost",
    "localdomain",
    "lan",
    "home",
    "home.arpa",
    "corp",
    "intranet",
    "private",
    "example",
    "invalid",
    "onion",
    "arpa",
];

const HOST_MAX_BYTES: usize = 253;
const LABEL_MAX_BYTES: usize = 63;

/// True when `host` is a public DNS name that may be shared with a provider.
pub fn provider_host_is_shareable(host: &str) -> bool {
    let host = host.strip_suffix('.').unwrap_or(host);
    if host.is_empty() || host.len() > HOST_MAX_BYTES {
        return false;
    }
    let labels: Vec<&str> = host.split('.').collect();
    if labels.len() < 2 || !labels.iter().all(|label| is_dns_label(label)) {
        return false;
    }
    // A host whose last label looks numeric is an IPv4 address in some spelling (WHATWG URL
    // parsing reads `127.1`, `0x7f.0.0.1` and `2130706433` as addresses), never a public name.
    let last = labels[labels.len() - 1];
    if last.bytes().all(|byte| byte.is_ascii_digit()) || is_hex_number(last) {
        return false;
    }
    let lowered = host.to_ascii_lowercase();
    !LOCAL_SUFFIXES.iter().any(|suffix| {
        lowered == *suffix
            || lowered
                .strip_suffix(suffix)
                .is_some_and(|rest| rest.ends_with('.'))
    })
}

/// True when `origin` is `https://host[:port]` (or `http://`) on a shareable host, with nothing
/// else: no user info, path, query or fragment.
pub fn provider_origin_is_shareable(origin: &str) -> bool {
    let Some((scheme, rest)) = origin.split_once("://") else {
        return false;
    };
    if !scheme.eq_ignore_ascii_case("https") && !scheme.eq_ignore_ascii_case("http") {
        return false;
    }
    let rest = rest.strip_suffix('/').unwrap_or(rest);
    if rest.is_empty() || rest.contains(['/', '?', '#', '@', '\\', '[', ']']) {
        return false;
    }
    let host = match rest.rsplit_once(':') {
        Some((host, port)) => {
            if port.is_empty() || port.len() > 5 || !port.bytes().all(|byte| byte.is_ascii_digit())
            {
                return false;
            }
            if port.parse::<u16>().map_or(true, |port| port == 0) {
                return false;
            }
            host
        }
        None => rest,
    };
    provider_host_is_shareable(host)
}

fn is_dns_label(label: &str) -> bool {
    (1..=LABEL_MAX_BYTES).contains(&label.len())
        && !label.starts_with('-')
        && !label.ends_with('-')
        && label
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
}

fn is_hex_number(label: &str) -> bool {
    let lowered = label.to_ascii_lowercase();
    lowered
        .strip_prefix("0x")
        .is_some_and(|digits| digits.bytes().all(|byte| byte.is_ascii_hexdigit()))
}

#[cfg(test)]
#[path = "provider_origin_share_tests.rs"]
mod tests;

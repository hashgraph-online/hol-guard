//! Canonical archive source identity and redirect resolution.

use super::restricted_archive::{CanonicalDestination, RestrictedDownloadError};
use regex::Regex;
use std::fmt::Write as _;
use std::net::{IpAddr, Ipv6Addr};
use std::sync::LazyLock;

static HOSTNAME_LABEL_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$").unwrap());

/// `urllib.parse.quote(path, safe="/%")` for the URL path component.
fn quote_path(value: &str) -> String {
    quote_with_safe(value, b"/%:@-._~!$&'()*+,;=")
}

/// `urllib.parse.quote(query, safe="")` — fragment is dropped entirely by the
/// caller, so only `?query` participates.
fn quote_query(value: &str) -> String {
    quote_with_safe(value, b"/%?:@-._~!$&'()*+,;=")
}

fn quote_with_safe(value: &str, safe: &[u8]) -> String {
    let mut out = String::new();
    for &byte in value.as_bytes() {
        let ch = byte as char;
        if ch.is_ascii_alphanumeric() || matches!(ch, '.' | '-' | '_' | '~') || safe.contains(&byte)
        {
            out.push(ch);
        } else {
            let _ = write!(out, "%{byte:02X}");
        }
    }
    out
}

/// `urllib.parse.urlunsplit` reassembly for the canonical HTTPS destination.
fn build_canonical_url(host_header: &str, request_target: &str) -> String {
    format!("https://{host_header}{request_target}")
}

/// `hostname.encode("idna").decode("ascii")` — Python uses IDNA-2003.
fn idna_encode(hostname: &str) -> Result<String, RestrictedDownloadError> {
    if !hostname.is_ascii() {
        return Err(RestrictedDownloadError::new(
            "external_archive_destination_rejected",
            "External archive destination uses an ambiguous non-ASCII hostname.",
        ));
    }
    Ok(hostname.to_ascii_lowercase())
}

/// `_split_netloc` — split `netloc` into `(userinfo, host, port)` text.
/// Mirrors `urllib.parse._splitnetloc` semantics for the `https`-only inputs
/// `_canonical_destination` accepts: `userinfo@host[:port]`.
fn split_netloc(netloc: &str) -> (Option<&str>, &str, Option<&str>) {
    // `urlsplit` lowercases only the scheme; the netloc retains case here.
    let (userinfo, hostport) = match netloc.rfind('@') {
        Some(index) => (Some(&netloc[..index]), &netloc[index + 1..]),
        None => (None, netloc),
    };
    // Bracketed IPv6 literal — `]` terminates the host, optional `:port`.
    if let Some(rest) = hostport.strip_prefix('[') {
        match rest.find(']') {
            Some(close) => {
                let host = &hostport[..close + 2]; // include brackets
                let port = hostport[close + 2..].strip_prefix(':');
                return (userinfo, host, port);
            }
            None => return (userinfo, hostport, None),
        }
    }
    match hostport.rfind(':') {
        Some(index) => (userinfo, &hostport[..index], Some(&hostport[index + 1..])),
        None => (userinfo, hostport, None),
    }
}

/// `urllib.parse.urlsplit` reduced to what `_canonical_destination` consumes:
/// scheme, netloc, path, query (fragment discarded by the caller contract).
pub(super) fn urlsplit(url: &str) -> (String, String, String, String) {
    // Fragment — `urldefrag` strips at the first `#`.
    let without_fragment = match url.find('#') {
        Some(index) => &url[..index],
        None => url,
    };
    // Scheme — `ALPHA *(ALPHA|DIGIT|"+"|"-"|".")` followed by `:`.
    let (scheme, rest) = match without_fragment.find(':') {
        Some(index)
            if index > 0
                && without_fragment[..index].chars().enumerate().all(|(i, c)| {
                    if i == 0 {
                        c.is_ascii_alphabetic()
                    } else {
                        c.is_ascii_alphanumeric() || matches!(c, '+' | '-' | '.')
                    }
                }) =>
        {
            (
                without_fragment[..index].to_ascii_lowercase(),
                &without_fragment[index + 1..],
            )
        }
        _ => (String::new(), without_fragment),
    };
    // Netloc — `//` authority extends to the next `/`, `?`, or `#`.
    let (netloc, path_query) = if let Some(stripped) = rest.strip_prefix("//") {
        let end = stripped.find(['/', '?', '#']).unwrap_or(stripped.len());
        (stripped[..end].to_string(), &stripped[end..])
    } else {
        (String::new(), rest)
    };
    let (path, query) = match path_query.find('?') {
        Some(index) => (&path_query[..index], path_query[index + 1..].to_string()),
        None => (path_query, String::new()),
    };
    (scheme, netloc, path.to_string(), query)
}

/// `urllib.parse.urljoin` — only used to resolve a redirect `Location`
/// against the current destination URL.
pub(super) fn urljoin(base: &str, location: &str) -> String {
    if location.is_empty() {
        return base.to_string();
    }
    let (base_scheme, base_netloc, base_path, base_query) = urlsplit(base);
    let (scheme, netloc, path, query) = urlsplit(location);
    // Same-scheme references without authority inherit the current host.
    if (!scheme.is_empty() && scheme != base_scheme) || !netloc.is_empty() {
        if scheme.is_empty() {
            return format!("{base_scheme}:{location}");
        }
        return location.to_string();
    }
    let merged = if path.is_empty() {
        base_path
    } else if path.starts_with('/') {
        path
    } else {
        match base_path.rfind('/') {
            Some(index) => format!("{}{}", &base_path[..index + 1], path),
            None => format!("/{path}"),
        }
    };
    let mut parts = Vec::new();
    for segment in merged.split('/') {
        match segment {
            "." => {}
            ".." => {
                if parts.len() > 1 {
                    parts.pop();
                }
            }
            _ => parts.push(segment),
        }
    }
    if merged.ends_with("/.") || merged.ends_with("/..") {
        parts.push("");
    }
    let mut result = format!("{base_scheme}://{base_netloc}{}", parts.join("/"));
    let query = if location.starts_with('#') {
        base_query
    } else {
        query
    };
    if !query.is_empty() {
        result.push('?');
        result.push_str(&query);
    }
    if let Some((_, fragment)) = location.split_once('#') {
        result.push('#');
        result.push_str(fragment);
    }
    result
}

/// `_canonical_destination` (restricted_archive_destination.py:66).
pub fn canonical_destination(url: &str) -> Result<CanonicalDestination, RestrictedDownloadError> {
    let rejected = || {
        RestrictedDownloadError::new(
            "external_archive_destination_rejected",
            "External archive destination is not a canonical public HTTPS URL.",
        )
    };
    if url.is_empty()
        || url.bytes().any(|b| b <= 0x20 || b == 0x7f || b == b'\\')
        || url
            .split_once('#')
            .is_some_and(|(_, fragment)| !fragment.is_empty())
    {
        return Err(rejected());
    }
    let (scheme, netloc, path, query) = urlsplit(url);
    if scheme != "https" || netloc.is_empty() {
        return Err(rejected());
    }
    let (userinfo, host, port_text) = split_netloc(&netloc);
    if userinfo.is_some() {
        // `urllib.parse.urlsplit` treats `userinfo@` as credentials — the
        // download path must never smuggle them.
        return Err(rejected());
    }
    let bracketed = host.starts_with('[');
    let host = if bracketed {
        host.strip_prefix('[')
            .and_then(|h| h.strip_suffix(']'))
            .ok_or_else(rejected)?
    } else {
        host
    };
    let host = host.trim_end_matches('.');
    if host.is_empty() || host.contains('%') || (bracketed && host.parse::<Ipv6Addr>().is_err()) {
        return Err(rejected());
    }
    let port: u16 = match port_text {
        None => 443,
        Some("") => 443,
        Some(text) if text.bytes().all(|b| b.is_ascii_digit()) => match text.parse::<u16>() {
            Ok(0) => 443,
            Ok(value) => value,
            Err(_) => return Err(rejected()),
        },
        Some(_) => return Err(rejected()),
    };
    // `urlsplit` may hand back a port like `:abc` — `.parse` above rejects it.
    let hostname = host.to_ascii_lowercase();
    let idna_host = idna_encode(&hostname)?;
    if !is_ip_literal(&idna_host) {
        // Hostname validation — Python validates each DNS label.
        let labels: Vec<&str> = idna_host.split('.').collect();
        if idna_host.len() > 253
            || labels
                .iter()
                .any(|label| label.is_empty() || !HOSTNAME_LABEL_RE.is_match(label))
        {
            return Err(rejected());
        }
    }
    for component in [&path, &query] {
        let bytes = component.as_bytes();
        for (i, b) in bytes.iter().enumerate() {
            if *b == b'%'
                && (i + 2 >= bytes.len()
                    || !bytes[i + 1].is_ascii_hexdigit()
                    || !bytes[i + 2].is_ascii_hexdigit())
            {
                return Err(rejected());
            }
        }
    }
    let request_target = {
        let mut target = if path.is_empty() {
            "/".to_string()
        } else {
            quote_path(&path)
        };
        if !query.is_empty() {
            target.push('?');
            target.push_str(&quote_query(&query));
        }
        target
    };
    let rendered_host = if idna_host.parse::<Ipv6Addr>().is_ok() {
        format!("[{idna_host}]")
    } else {
        idna_host.clone()
    };
    let host_header = if port == 443 {
        rendered_host
    } else {
        format!("{rendered_host}:{port}")
    };
    Ok(CanonicalDestination {
        url: build_canonical_url(&host_header, &request_target),
        hostname: idna_host,
        port,
        request_target,
        host_header,
    })
}

fn is_ip_literal(host: &str) -> bool {
    host.parse::<IpAddr>().is_ok()
}

/// HTTPS-like npm spellings enter the restricted pipeline even if rejected by
/// strict parsing. Only the exact npm registry hostname is exempt.
pub fn is_external_https_archive_source(source_url: &str) -> bool {
    let normalized = source_url.trim();
    if !normalized.to_ascii_lowercase().starts_with("https:") {
        return false;
    }
    let (_, netloc, _, _) = urlsplit(normalized);
    let (_, host, _) = split_netloc(&netloc);
    !host
        .trim_end_matches('.')
        .eq_ignore_ascii_case("registry.npmjs.org")
}

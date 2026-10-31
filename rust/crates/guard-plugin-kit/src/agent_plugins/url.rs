//! §7.2.1: the endpoint URLs a remote MCP server may use.

/// Why `url` is not an MCP endpoint URL the specification allows.
pub(crate) fn url_problem(url: &str) -> Option<&'static str> {
    let Some((scheme, rest)) = url.split_once("://") else {
        return Some("`url` must be an absolute http or https URL.");
    };
    let scheme = scheme.to_ascii_lowercase();
    if scheme != "https" && scheme != "http" {
        return Some("`url` must be an absolute http or https URL.");
    }
    if url.contains('#') {
        return Some("`url` must not have a fragment.");
    }
    let authority = rest.split(['/', '?']).next().unwrap_or("");
    if authority.is_empty() {
        return Some("`url` must name a host.");
    }
    if authority.contains('@') {
        return Some("`url` must not carry user information.");
    }
    if !authority_valid(authority) {
        return Some("`url` must name a valid host and, if any, a numeric port.");
    }
    if scheme == "http" && !loopback(authority) {
        return Some("Only localhost and loopback addresses may use http; use https.");
    }
    None
}

/// A host name, IPv4 address or bracketed IPv6 address, with an optional
/// port of 1-65535.
fn authority_valid(authority: &str) -> bool {
    let (host_ok, port) = if let Some(rest) = authority.strip_prefix('[') {
        let Some((address, after)) = rest.split_once(']') else {
            return false;
        };
        let port = match after {
            "" => None,
            _ => match after.strip_prefix(':') {
                Some(port) => Some(port),
                None => return false,
            },
        };
        (address.parse::<std::net::Ipv6Addr>().is_ok(), port)
    } else {
        let (host, port) = match authority.split_once(':') {
            Some((host, port)) => (host, Some(port)),
            None => (authority, None),
        };
        let host_ok = !host.is_empty()
            && host.split('.').all(|label| {
                !label.is_empty()
                    && label.len() <= 63
                    && !label.starts_with('-')
                    && !label.ends_with('-')
                    && label
                        .bytes()
                        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
            });
        (host_ok, port)
    };
    host_ok
        && port.is_none_or(|port| {
            !port.is_empty()
                && port.len() <= 5
                && port.bytes().all(|byte| byte.is_ascii_digit())
                && port
                    .parse::<u32>()
                    .is_ok_and(|port| (1..=65_535).contains(&port))
        })
}

fn loopback(authority: &str) -> bool {
    let host = if let Some(rest) = authority.strip_prefix('[') {
        rest.split(']').next().unwrap_or("")
    } else {
        authority
            .rsplit_once(':')
            .map_or(authority, |(host, _)| host)
    };
    host == "localhost"
        || host
            .parse::<std::net::IpAddr>()
            .is_ok_and(|address| address.is_loopback())
}

#[cfg(test)]
mod tests {
    use super::url_problem;

    #[test]
    fn urls_follow_section_7_2_1() {
        assert_eq!(url_problem("https://deploy.example.com/mcp"), None);
        assert_eq!(url_problem("http://localhost:3000/mcp"), None);
        assert_eq!(url_problem("http://127.0.0.1/mcp"), None);
        assert_eq!(url_problem("http://[::1]:8080/mcp"), None);
        assert_eq!(
            url_problem("https://mcp.example.com:8443/mcp?price=$5"),
            None
        );
        assert_eq!(url_problem("https://my_host.internal/mcp"), None);
        for url in [
            "http://example.com/mcp",
            "https://user:pass@example.com/mcp",
            "https://example.com/mcp#frag",
            "ftp://example.com",
            "example.com/mcp",
            "https:///mcp",
            "https://mcp.example.com:bad/mcp",
            "https://mcp.example.com:/mcp",
            "https://mcp.example.com:70000/mcp",
            "https://mcp..example.com/mcp",
            "https://${HOST}/mcp",
            "https://[::1/mcp",
            "https://a:1:2/mcp",
        ] {
            assert!(url_problem(url).is_some(), "{url}");
        }
    }
}

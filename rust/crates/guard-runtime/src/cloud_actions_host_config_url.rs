//! The address an earlier entry pointed at, shown without its secrets.

/// Scheme, host and path of an address Guard did not write, as Python's
/// `urllib.parse.urlsplit` reads it; `None` when it cannot be read.
pub(super) fn display_url(value: &str) -> Option<String> {
    const USES_NETLOC: [&str; 27] = [
        "",
        "ftp",
        "http",
        "gopher",
        "nntp",
        "telnet",
        "imap",
        "wais",
        "file",
        "mms",
        "https",
        "shttp",
        "snews",
        "prospero",
        "rtsp",
        "rtsps",
        "rtspu",
        "rsync",
        "svn",
        "svn+ssh",
        "sftp",
        "nfs",
        "git",
        "git+ssh",
        "ws",
        "wss",
        "itms-services",
    ];
    let url: String = value
        .trim_start_matches(|c: char| c <= ' ')
        .chars()
        .filter(|c| !matches!(c, '\t' | '\r' | '\n'))
        .collect();
    let mut rest = url.as_str();
    let mut scheme = String::new();
    if let Some(colon) = rest.find(':') {
        let candidate = &rest[..colon];
        if candidate
            .chars()
            .next()
            .is_some_and(|c| c.is_ascii_alphabetic())
            && candidate
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '-' | '.'))
        {
            scheme = candidate.to_ascii_lowercase();
            rest = &rest[colon + 1..];
        }
    }
    let mut netloc = "";
    if let Some(after) = rest.strip_prefix("//") {
        let end = after.find(['/', '?', '#']).unwrap_or(after.len());
        netloc = &after[..end];
        rest = &after[end..];
        if netloc.contains('[') != netloc.contains(']') {
            return None;
        }
        if netloc.contains('[') {
            check_bracketed_netloc(netloc)?;
        }
    }
    if !netloc.is_ascii() {
        return None;
    }
    let path = rest.split(['#', '?']).next().unwrap_or("");
    let hostinfo = netloc.rsplit_once('@').map_or(netloc, |(_, host)| host);
    let (hostname, port) = match hostinfo.split_once('[') {
        Some((_, bracketed)) => {
            let (hostname, after) = bracketed.split_once(']').unwrap_or((bracketed, ""));
            (hostname, after.split_once(':').map_or("", |(_, port)| port))
        }
        None => hostinfo.split_once(':').unwrap_or((hostinfo, "")),
    };
    let port = match port {
        "" => None,
        digits if digits.bytes().all(|b| b.is_ascii_digit()) => {
            let number = digits.trim_start_matches('0');
            if number.len() > 5 {
                return None;
            }
            let number: u32 = if number.is_empty() {
                0
            } else {
                number.parse().ok()?
            };
            if number > 65535 {
                return None;
            }
            Some(number)
        }
        _ => return None,
    };
    let mut host = match hostname.split_once('%') {
        Some((name, zone)) => format!("{}%{zone}", name.to_lowercase()),
        None => hostname.to_lowercase(),
    };
    if host.contains(':') {
        host = format!("[{host}]");
    }
    if let Some(port) = port {
        host = format!("{host}:{port}");
    }
    let mut url = path.to_owned();
    if !host.is_empty()
        || (!scheme.is_empty() && USES_NETLOC.contains(&scheme.as_str()) && !url.starts_with("//"))
    {
        if !url.is_empty() && !url.starts_with('/') {
            url.insert(0, '/');
        }
        url = format!("//{host}{url}");
    }
    if !scheme.is_empty() {
        url = format!("{scheme}:{url}");
    }
    Some(url)
}

fn check_bracketed_netloc(netloc: &str) -> Option<()> {
    let hostinfo = netloc.rsplit_once('@').map_or(netloc, |(_, host)| host);
    let (before, bracketed) = hostinfo.split_once('[')?;
    if !before.is_empty() {
        return None;
    }
    let (hostname, port) = bracketed.split_once(']').unwrap_or((bracketed, ""));
    if !port.is_empty() && !port.starts_with(':') {
        return None;
    }
    if let Some(future) = hostname.strip_prefix('v') {
        let (version, address) = future.split_once('.')?;
        return (!version.is_empty()
            && version.bytes().all(|b| b.is_ascii_hexdigit())
            && !address.is_empty()
            && !address.contains('\n'))
        .then_some(());
    }
    let address = match hostname.split_once('%') {
        Some((address, zone)) if !zone.is_empty() && !zone.contains('%') => address,
        Some(_) => return None,
        None => hostname,
    };
    address.parse::<std::net::Ipv6Addr>().ok().map(|_| ())
}

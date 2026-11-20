//! The retired Python resolver's `_canonical_remote`: the host and path a
//! remote names, read through `urllib.parse.urlsplit` for a URL and through
//! `_SCP_REMOTE_PATTERN` for an scp-style remote.
//!
//! `Ok(None)` is a remote the Python function answers with `None`;
//! `Unmirrored` is one whose Python outcome this reader does not reproduce
//! exactly (a non-ASCII host, a non-ASCII path whose case the normalization
//! reads, a port only some Python versions reject, a bracketed netloc whose
//! `ValueError` the Python function raised instead of answering).

use crate::context_digest::{is_python_space, python_strip};
use crate::project_identity::{Mirror, Unmirrored};

const CASE_INSENSITIVE_PATH_HOSTS: [&str; 2] = ["github.com", "www.github.com"];
const CASE_INSENSITIVE_PATH_SUFFIX: &str = ".ghe.com";

/// `_DEFAULT_REMOTE_PORTS`.
fn default_port(scheme: &str) -> Option<u32> {
    match scheme {
        "git" => Some(9418),
        "http" => Some(80),
        "https" => Some(443),
        "ssh" => Some(22),
        _ => None,
    }
}

/// `urlsplit`'s scheme: the text before the first `:` when it starts with an
/// ASCII letter and holds only scheme characters. Releases before the
/// leading-letter check took any scheme characters, so a scheme that only
/// they accept is unmirrored.
fn split_scheme(url: &str) -> Mirror<(String, &str)> {
    if let Some(colon) = url.find(':').filter(|colon| *colon > 0) {
        let head = &url[..colon];
        let valid = head
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '+' | '-' | '.'));
        if valid && !head.starts_with(|ch: char| ch.is_ascii_alphabetic()) {
            return Err(Unmirrored);
        }
        if valid {
            return Ok((head.to_ascii_lowercase(), &url[colon + 1..]));
        }
    }
    Ok((String::new(), url))
}

/// The URL branch: `(host, path_case_host, path)`.
fn url_parts(value: &str) -> Mirror<Option<(String, String, String)>> {
    // Newer releases strip leading C0 controls (older ones keep them); every
    // supported release drops each tab and line break.
    if value.starts_with(|ch: char| ch <= ' ') {
        return Err(Unmirrored);
    }
    let url: String = value
        .chars()
        .filter(|ch| !matches!(ch, '\t' | '\r' | '\n'))
        .collect();
    let (scheme, rest) = split_scheme(&url)?;
    let (netloc, rest) = match rest.strip_prefix("//") {
        Some(after) => {
            let end = after.find(['/', '?', '#']).unwrap_or(after.len());
            (&after[..end], &after[end..])
        }
        None => ("", rest),
    };
    // A non-ASCII netloc is NFKC-checked by version-specific code, which is
    // not reproduced here.
    if !netloc.is_ascii() {
        return Err(Unmirrored);
    }
    let path = rest.split('#').next().unwrap_or_default();
    let path = path.split('?').next().unwrap_or_default();
    // `SplitResult._hostinfo`.
    let hostinfo = netloc.rsplit('@').next().unwrap_or_default();
    let (hostname, port) = if netloc.contains(['[', ']']) {
        // `urlsplit` raises for a bracket it cannot read as a host, and the
        // Python resolver let that ValueError out rather than answering.
        bracketed_netloc(netloc, hostinfo).ok_or(Unmirrored)?
    } else {
        match hostinfo.split_once(':') {
            Some((hostname, port)) => (hostname, Some(port)),
            None => (hostinfo, None),
        }
    };
    if scheme == "file" || hostname.is_empty() {
        // _canonical_remote: a file URL or a URL without
        // a hostname is None.
        return Ok(None);
    }
    // `SplitResult.hostname` keeps a zone's case after `%`, but
    // _canonical_remote lowercases all of it again.
    let hostname = hostname.to_ascii_lowercase();
    // _canonical_remote: an IPv6 host keeps its brackets,
    // so the port after it is never read as part of the address.
    let mut host = if hostname.contains(':') {
        format!("[{hostname}]")
    } else {
        hostname.clone()
    };
    // `_hostinfo` reads an empty port as no port.
    match port.filter(|port| !port.is_empty()) {
        None => {}
        Some(port) if port.contains(['+', '-', '_']) || port.contains(is_python_space) => {
            // Signs, underscores and spaces parse as a port in releases
            // that read it with `int(port, 10)`; newer ones reject them.
            return Err(Unmirrored);
        }
        Some(port) if !port.bytes().all(|byte| byte.is_ascii_digit()) => {
            // _canonical_remote: `parsed.port` raises
            // ValueError for a non-numeric port, answered with None.
            return Ok(None);
        }
        Some(port) => {
            let digits = port.trim_start_matches('0');
            let Some(number) = (digits.len() <= 5)
                .then(|| digits.parse::<u32>().unwrap_or(0))
                .filter(|number| *number <= 65_535)
            else {
                // _canonical_remote: a port out of range
                // raises ValueError, answered with None.
                return Ok(None);
            };
            if Some(number) != default_port(&scheme) {
                host = format!("{host}:{number}");
            }
        }
    }
    Ok(Some((host, hostname, path.to_owned())))
}

/// `_check_bracketed_netloc` and `SplitResult._hostinfo`, which split a
/// netloc holding a bracket the same way: the host and port, or `None` for a
/// netloc `urlsplit` rejects. Both read the text after the last `@`, so a
/// bracket in the userinfo is not the host's.
fn bracketed_netloc<'u>(netloc: &str, hostinfo: &'u str) -> Option<(&'u str, Option<&'u str>)> {
    if !netloc.contains('[') || !netloc.contains(']') {
        // One bracket without the other is "Invalid IPv6 URL".
        return None;
    }
    let (hostname, port) = match hostinfo.split_once('[') {
        Some((before, bracketed)) => {
            // No data is allowed before the bracket, nor between the closing
            // one and the port delimiter.
            if !before.is_empty() {
                return None;
            }
            let (hostname, after) = bracketed.split_once(']').unwrap_or((bracketed, ""));
            let port = match after.strip_prefix(':') {
                Some(port) => Some(port),
                None if after.is_empty() => None,
                None => return None,
            };
            (hostname, port)
        }
        // A bracket the host does not open still sends the host through the
        // bracketed check, which an ordinary hostname does not pass.
        None => match hostinfo.split_once(':') {
            Some((hostname, port)) => (hostname, Some(port)),
            None => (hostinfo, None),
        },
    };
    bracketed_host(hostname).then_some((hostname, port))
}

/// `_check_bracketed_host`: an IPvFuture literal, or an address `ip_address`
/// reads as IPv6. An IPv4 address in brackets is rejected.
fn bracketed_host(hostname: &str) -> bool {
    if let Some(literal) = hostname.strip_prefix('v') {
        // `\Av[a-fA-F0-9]+\..+\Z` over a netloc that holds no line break,
        // so the tail is any one character or more.
        let digits = literal
            .find(|character: char| !character.is_ascii_hexdigit())
            .unwrap_or(literal.len());
        let tail = &literal[digits..];
        return digits > 0 && tail.starts_with('.') && tail.len() > 1;
    }
    // `ip_address` reads a zone after a `%`; it must not be empty or hold a
    // second `%`.
    let (address, zone) = match hostname.split_once('%') {
        Some((address, zone)) => (address, Some(zone)),
        None => (hostname, None),
    };
    !zone.is_some_and(|zone| zone.is_empty() || zone.contains('%'))
        && address.parse::<std::net::Ipv6Addr>().is_ok()
}

/// `_SCP_REMOTE_PATTERN` (`^(?:[^@/]+@)?([^:/]+):(.+)$`): `(host, path)`.
fn scp_parts(value: &str) -> Option<(&str, &str)> {
    let from = |start: usize| -> Option<(&str, &str)> {
        let rest = &value[start..];
        let end = rest.find([':', '/'])?;
        let path = &rest[end + 1..];
        // `.+$` matches a non-empty tail without a line break.
        (end > 0 && rest[end..].starts_with(':') && !path.is_empty() && !path.contains('\n'))
            .then(|| (&rest[..end], path))
    };
    let user = value
        .find('@')
        .filter(|at| *at > 0 && !value[..*at].contains('/'));
    user.and_then(|at| from(at + 1)).or_else(|| from(0))
}

/// The canonical anchor `_canonical_remote` returns for `remote`.
pub(crate) fn canonical_remote(remote: &str) -> Mirror<Option<String>> {
    let value = python_strip(remote);
    if value.is_empty() {
        // _canonical_remote: a blank remote is None.
        return Ok(None);
    }
    let (host, path_case_host, path) = if value.contains("://") {
        match url_parts(value)? {
            Some(parts) => parts,
            None => return Ok(None),
        }
    } else {
        let Some((host, path)) = scp_parts(value) else {
            // _canonical_remote: no scp match is None.
            return Ok(None);
        };
        if !host.is_ascii() {
            // `str.lower` and Rust lowercase differ on some non-ASCII text.
            return Err(Unmirrored);
        }
        let host = host.to_ascii_lowercase();
        (host.clone(), host, path.to_owned())
    };
    let case_insensitive = CASE_INSENSITIVE_PATH_HOSTS.contains(&path_case_host.as_str())
        || path_case_host.ends_with(CASE_INSENSITIVE_PATH_SUFFIX);
    let mut normalized = python_strip(&path).trim_matches('/');
    let tail = normalized.chars().rev().take(4).collect::<String>();
    if !normalized.is_ascii() && (case_insensitive || !tail.is_ascii()) {
        // The suffix check and the path lowercase use `str.lower`.
        return Err(Unmirrored);
    }
    if normalized.len() >= 4
        && normalized.is_char_boundary(normalized.len() - 4)
        && normalized[normalized.len() - 4..].eq_ignore_ascii_case(".git")
    {
        normalized = &normalized[..normalized.len() - 4];
    }
    let normalized = if case_insensitive {
        normalized.to_ascii_lowercase()
    } else {
        normalized.to_owned()
    };
    if host.is_empty() || normalized.is_empty() {
        // _canonical_remote: an empty host or path is
        // None.
        return Ok(None);
    }
    Ok(Some(format!("remote:{host}/{normalized}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn anchor(remote: &str) -> Mirror<Option<String>> {
        canonical_remote(remote)
    }

    #[test]
    fn scp_remotes_split_like_the_pattern() {
        assert_eq!(scp_parts("git@h:o/r"), Some(("h", "o/r")));
        assert_eq!(scp_parts("h:p@x"), Some(("h", "p@x")));
        assert_eq!(scp_parts("a@b@c:d"), Some(("b@c", "d")));
        assert_eq!(scp_parts("h/o:r"), None);
        assert_eq!(scp_parts("h:"), None);
        assert_eq!(scp_parts("h:a\nb"), None);
    }

    #[test]
    fn ports_parse_as_urlsplit_reads_them() {
        let ok = |remote: &str, want: &str| assert_eq!(anchor(remote), Ok(Some(want.to_owned())));
        ok("https://H:0443/o/r.git", "remote:h/o/r");
        ok("https://h:0/o/r", "remote:h:0/o/r");
        ok("ssh://u@h:2201/o/r", "remote:h:2201/o/r");
        ok("ssh://git@Host%25Zone/o/r", "remote:host%25zone/o/r");
        assert_eq!(anchor("https://h:70000/o/r"), Ok(None));
        assert_eq!(anchor("https://h:abc/o/r"), Ok(None));
        ok("https://h:/o/r", "remote:h/o/r");
        assert_eq!(anchor("1h://h/o/r"), Err(Unmirrored));
        assert_eq!(anchor("\u{1}https://h/o/r"), Err(Unmirrored));
        assert_eq!(anchor("https://h:+1/o/r"), Err(Unmirrored));
    }

    #[test]
    fn ipv6_hosts_keep_their_brackets() {
        let ok = |remote: &str, want: &str| assert_eq!(anchor(remote), Ok(Some(want.to_owned())));
        ok("ssh://[::1]/o/r", "remote:[::1]/o/r");
        ok("ssh://git@[::1]:9418/o/r.git", "remote:[::1]:9418/o/r");
        ok("ssh://git@[::1:9418]/o/r.git", "remote:[::1:9418]/o/r");
        ok("ssh://git@[::1]:22/o/r", "remote:[::1]/o/r");
        ok("https://[FE80::AB]/o/r", "remote:[fe80::ab]/o/r");
        ok("ssh://[::1]:/o/r", "remote:[::1]/o/r");
        ok("ssh://[::ffff:1.2.3.4]/o/r", "remote:[::ffff:1.2.3.4]/o/r");
        assert_eq!(anchor("ssh://[::1]:2:3/o/r"), Ok(None));
    }

    #[test]
    fn scoped_and_ipvfuture_hosts_read_as_urlsplit_reads_them() {
        let ok = |remote: &str, want: &str| assert_eq!(anchor(remote), Ok(Some(want.to_owned())));
        ok("ssh://[fe80::1%25eth0]/o/r", "remote:[fe80::1%25eth0]/o/r");
        ok("ssh://[FE80::1%ETH0]/o/r", "remote:[fe80::1%eth0]/o/r");
        ok("ssh://[v1.x]/o/r", "remote:v1.x/o/r");
        ok("ssh://[vFF.a.b]/o/r", "remote:vff.a.b/o/r");
        ok("ssh://[v1.x]:22/o/r", "remote:v1.x/o/r");
        assert_eq!(anchor("ssh://[v1.x]:70000/o/r"), Ok(None));
        // `_check_bracketed_host` reads the host before `hostname` lowercases
        // it, so an uppercase `V` is not an IPvFuture literal.
        assert_eq!(anchor("ssh://[V1.x]/o/r"), Err(Unmirrored));
        assert_eq!(anchor("ssh://[v1.]/o/r"), Err(Unmirrored));
        assert_eq!(anchor("ssh://[vz.x]/o/r"), Err(Unmirrored));
        assert_eq!(anchor("ssh://[v.x]/o/r"), Err(Unmirrored));
        assert_eq!(anchor("ssh://[fe80::1%]/o/r"), Err(Unmirrored));
    }

    #[test]
    fn a_netloc_urlsplit_rejects_is_unmirrored() {
        // The Python resolver called `urlsplit` without catching its
        // `ValueError`, so these remotes raised rather than answering `None`.
        assert_eq!(anchor("ssh://[::1/o/r"), Err(Unmirrored));
        assert_eq!(anchor("ssh://::1]/o/r"), Err(Unmirrored));
        assert_eq!(anchor("ssh://[1.2.3.4]/o/r"), Err(Unmirrored));
        assert_eq!(anchor("ssh://[::1]x/o/r"), Err(Unmirrored));
        assert_eq!(anchor("ssh://h[::1]/o/r"), Err(Unmirrored));
        assert_eq!(anchor("ssh://[]/o/r"), Err(Unmirrored));
        // A bracket in the userinfo is not the host's, but it still sends the
        // host through the bracketed check.
        assert_eq!(anchor("ssh://u[s]@example.com/o/r"), Err(Unmirrored));
    }

    #[test]
    fn the_host_is_read_after_the_last_userinfo() {
        let ok = |remote: &str, want: &str| assert_eq!(anchor(remote), Ok(Some(want.to_owned())));
        ok("ssh://u[ser]@[::1]/o/r", "remote:[::1]/o/r");
        ok("ssh://[::1]@[::2]/o/r", "remote:[::2]/o/r");
    }

    #[test]
    fn paths_normalize_like_the_resolver() {
        let ok = |remote: &str, want: &str| assert_eq!(anchor(remote), Ok(Some(want.to_owned())));
        ok(
            "https://GitHub.com/Owner/Repo.GIT/",
            "remote:github.com/owner/repo",
        );
        ok("git@x.ghe.com:O/R.git", "remote:x.ghe.com/o/r");
        ok("git@other:O/R.git", "remote:other/O/R");
        ok("https://h/o/r#y?x=1", "remote:h/o/r");
        assert_eq!(anchor("https://h/.git"), Ok(None));
        assert_eq!(anchor("file:///o/r"), Ok(None));
        assert_eq!(anchor("https://:443/o/r"), Ok(None));
        assert_eq!(anchor("git@github.com:o/\u{e9}"), Err(Unmirrored));
    }
}

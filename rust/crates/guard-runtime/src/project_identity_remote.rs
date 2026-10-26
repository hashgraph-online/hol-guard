//! `_canonical_remote` (`project_identity.py`): the host and path a remote
//! names, read through `urllib.parse.urlsplit` for a URL and through
//! `_SCP_REMOTE_PATTERN` for an scp-style remote.
//!
//! `Ok(None)` is a remote the Python function answers with `None`;
//! `Unmirrored` is one whose Python outcome this reader does not reproduce
//! exactly (an IPv6 or non-ASCII host, a non-ASCII path whose case the
//! normalization reads, a port only some Python versions reject).

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
    // A bracketed (IPv6) host is validated, and a non-ASCII netloc is
    // NFKC-checked, by version-specific code; neither is reproduced here.
    if netloc.contains(['[', ']']) || !netloc.is_ascii() {
        return Err(Unmirrored);
    }
    let path = rest.split('#').next().unwrap_or_default();
    let path = path.split('?').next().unwrap_or_default();
    // `SplitResult._hostinfo`, unbracketed.
    let hostinfo = netloc.rsplit('@').next().unwrap_or_default();
    let (hostname, port) = match hostinfo.split_once(':') {
        Some((hostname, port)) => (hostname, Some(port)),
        None => (hostinfo, None),
    };
    if scheme == "file" || hostname.is_empty() {
        // project_identity.py:_canonical_remote: a file URL or a URL without
        // a hostname is None.
        return Ok(None);
    }
    // `SplitResult.hostname` keeps a zone's case after `%`, but
    // project_identity.py:_canonical_remote lowercases all of it again.
    let hostname = hostname.to_ascii_lowercase();
    let mut host = hostname.clone();
    // `_hostinfo` reads an empty port as no port.
    match port.filter(|port| !port.is_empty()) {
        None => {}
        Some(port) if port.contains(['+', '-', '_']) || port.contains(is_python_space) => {
            // Signs, underscores and spaces parse as a port in releases
            // that read it with `int(port, 10)`; newer ones reject them.
            return Err(Unmirrored);
        }
        Some(port) if !port.bytes().all(|byte| byte.is_ascii_digit()) => {
            // project_identity.py:_canonical_remote: `parsed.port` raises
            // ValueError for a non-numeric port, answered with None.
            return Ok(None);
        }
        Some(port) => {
            let digits = port.trim_start_matches('0');
            let Some(number) = (digits.len() <= 5)
                .then(|| digits.parse::<u32>().unwrap_or(0))
                .filter(|number| *number <= 65_535)
            else {
                // project_identity.py:_canonical_remote: a port out of range
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
        // project_identity.py:_canonical_remote: a blank remote is None.
        return Ok(None);
    }
    let (host, path_case_host, path) = if value.contains("://") {
        match url_parts(value)? {
            Some(parts) => parts,
            None => return Ok(None),
        }
    } else {
        let Some((host, path)) = scp_parts(value) else {
            // project_identity.py:_canonical_remote: no scp match is None.
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
        // project_identity.py:_canonical_remote: an empty host or path is
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
        assert_eq!(anchor("ssh://[::1]/o/r"), Err(Unmirrored));
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

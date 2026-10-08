//! Rust port of `runtime/npm_source_spec.py` — canonical, credential-free npm
//! source specification identities.
//!
//! Parity notes:
//! - `urllib.parse.urlsplit` → [`split_url`] (host-schemed inputs only;
//!   `port` accessor mirrors Python: raises on non-numeric/out-of-range →
//!   `npm_source_malformed_port`).
//! - `urllib.parse.unquote` → `percent_decode_str` strict UTF-8;
//!   `quote(s, safe="!$&'()+,;=@._~-")` → [`percent_encode_path`].
//! - `str.encode("idna")` → `idna::domain_to_ascii` — Python uses IDNA-2003,
//!   `idna` is UTS-46; divergence confined to exotic Unicode labels.
//! - `int(port_text)` accepts a leading `+`/`-` like Rust's `i64::parse`
//!   but NOT Python's surrounding whitespace — treated as malformed either way.
//!
//! Identity/redacted/reason strings match Python verbatim.

use std::sync::LazyLock;

use regex::Regex;
use sha2::{Digest, Sha256};

static SCP_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^(?P<user>[^@/:]+)@(?P<host>[^/:]+):(?P<path>[^#]+)(?:#(?P<fragment>.*))?$")
        .unwrap()
});
static COMMIT_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^(?:[0-9a-fA-F]{40}|[0-9a-fA-F]{64})$").unwrap());
static ENCODED_SEPARATOR_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)%(?:00|2f|5c)").unwrap());
static SCHEME_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^[A-Za-z][A-Za-z0-9+.-]*:").unwrap());

/// `_HOSTED` (:14).
const HOSTED: [(&str, &str); 3] = [
    ("github", "github.com"),
    ("gitlab", "gitlab.com"),
    ("bitbucket", "bitbucket.org"),
];

/// `_GIT_SCHEMES` (:19) / `_URL_SCHEMES` (:20).
const GIT_SCHEMES: [&str; 4] = ["git", "git+https", "git+ssh", "ssh"];
const URL_SCHEMES: [&str; 6] = ["http", "https", "git", "git+https", "git+ssh", "ssh"];

/// `_DEFAULT_PORTS` (:21).
fn default_port(scheme: &str) -> Option<u16> {
    Some(match scheme {
        "http" => 80,
        "https" | "git+https" => 443,
        "ssh" | "git+ssh" => 22,
        "git" => 9418,
        _ => return None,
    })
}

/// `SourceKind` (:11).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SourceKind {
    Git,
    Url,
    Local,
    Invalid,
}

impl SourceKind {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Git => "git",
            Self::Url => "url",
            Self::Local => "local",
            Self::Invalid => "invalid",
        }
    }
}

/// `RevisionKind` (:12).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RevisionKind {
    ImmutableCommit,
    MutableRef,
    Missing,
    NotApplicable,
}

impl RevisionKind {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ImmutableCommit => "immutable_commit",
            Self::MutableRef => "mutable_ref",
            Self::Missing => "missing",
            Self::NotApplicable => "not_applicable",
        }
    }
}

/// `NpmSourceSpec` (:28) — dataclass field order.
#[derive(Debug, Clone, PartialEq)]
pub struct NpmSourceSpec {
    pub source_kind: SourceKind,
    pub canonical_repository: Option<String>,
    pub revision: Option<String>,
    pub revision_kind: RevisionKind,
    pub identity: String,
    pub redacted: String,
    pub valid: bool,
    pub reason: Option<String>,
}

impl NpmSourceSpec {
    /// `is_git` (:39).
    pub fn is_git(&self) -> bool {
        self.source_kind == SourceKind::Git && self.valid
    }
}

/// `parse_npm_source_spec` (:44) — `None` for registry syntax.
pub fn parse_npm_source_spec(value: Option<&str>) -> Option<NpmSourceSpec> {
    let raw = value?;
    let mut source = raw.trim().to_string();
    if source.is_empty() {
        return None;
    }
    let mut lowered = source.to_lowercase();
    let mut alias_depth = 0u32;
    while lowered.starts_with("npm:") {
        alias_depth += 1;
        if alias_depth > 32 {
            return Some(invalid(&source, "npm_source_alias_depth_exceeded"));
        }
        source = source[4..].trim().to_string();
        if source.is_empty() {
            return Some(invalid(raw, "npm_source_alias_invalid"));
        }
        lowered = source.to_lowercase();
    }
    if lowered.starts_with("file:") {
        let parsed_file = split_url(&source);
        if !parsed_file.netloc.is_empty()
            || !parsed_file.query.is_empty()
            || !parsed_file.fragment.is_empty()
        {
            return Some(invalid(&source, "npm_source_local_url_invalid"));
        }
        return Some(non_git_source(
            SourceKind::Local,
            &source,
            "file:<local-source>",
        ));
    }
    for (prefix, host) in HOSTED {
        let marker = format!("{prefix}:");
        if lowered.starts_with(&marker) {
            return Some(git_from_host_path(host, &source[marker.len()..], None));
        }
    }
    if let Some(scp) = SCP_RE.captures(&source) {
        if scp.name("user").unwrap().as_str().to_lowercase() != "git" {
            return Some(invalid(&source, "npm_source_ambiguous_userinfo"));
        }
        return Some(git_from_host_path(
            scp.name("host").unwrap().as_str(),
            scp.name("path").unwrap().as_str(),
            scp.name("fragment").map(|m| m.as_str()),
        ));
    }
    if source.contains("://") || SCHEME_RE.is_match(&source) {
        return Some(url_source(&source));
    }
    if source.starts_with('@')
        || source.starts_with("./")
        || source.starts_with("../")
        || source.starts_with('/')
        || source.starts_with('~')
        || source.starts_with('\\')
        || source.contains(':')
    {
        return None;
    }
    let mut parts = source.splitn(2, '#');
    let path = parts.next().unwrap_or("");
    let fragment = parts.next();
    if path.matches('/').count() == 1 && path.split('/').all(|part| !part.trim().is_empty()) {
        return Some(git_from_host_path("github.com", path, fragment));
    }
    None
}

/// `_url_source` (:85).
fn url_source(source: &str) -> NpmSourceSpec {
    let parsed = split_url(source);
    // `parsed.port` raises ValueError on malformed/out-of-range →
    // `npm_source_malformed_port` before any other validation (:87-90).
    let port = match parsed.port {
        Ok(p) => p,
        Err(()) => return invalid(source, "npm_source_malformed_port"),
    };
    let scheme = parsed.scheme.to_lowercase();
    if !URL_SCHEMES.contains(&scheme.as_str()) {
        return invalid(source, "npm_source_protocol_unsupported");
    }
    let parsed_hostname = match parsed.hostname.as_deref() {
        Some(h) => h,
        None => return invalid(source, "npm_source_host_missing"),
    };
    if !parsed.password.is_empty() || !(parsed.username.is_empty() || parsed.username == "git") {
        return invalid(source, "npm_source_ambiguous_userinfo");
    }
    if parsed.username == "git" && !["ssh", "git+ssh"].contains(&scheme.as_str()) {
        return invalid(source, "npm_source_ambiguous_userinfo");
    }
    let host = match canonical_host(parsed_hostname) {
        Some(h) => h,
        None => return invalid(source, "npm_source_url_host_invalid"),
    };
    let rendered_host = host_with_port(&host, &scheme, port);
    let git_hosted = HOSTED.iter().any(|(_, h)| *h == host);
    if GIT_SCHEMES.contains(&scheme.as_str()) {
        return git_from_host_path(
            &rendered_host,
            &parsed.path,
            if parsed.fragment.is_empty() {
                None
            } else {
                Some(parsed.fragment.as_str())
            },
        );
    }
    if git_hosted {
        let git_source = git_from_host_path(
            &rendered_host,
            &parsed.path,
            if parsed.fragment.is_empty() {
                None
            } else {
                Some(parsed.fragment.as_str())
            },
        );
        if git_source.valid || git_source.reason.as_deref() != Some("npm_source_path_invalid") {
            return git_source;
        }
    }
    let normalized_path = match canonical_path(&parsed.path, 1) {
        Some(p) => p,
        None => return invalid(source, "npm_source_path_invalid"),
    };
    let canonical = format!("{scheme}://{rendered_host}/{normalized_path}");
    NpmSourceSpec {
        source_kind: SourceKind::Url,
        canonical_repository: None,
        revision: None,
        revision_kind: RevisionKind::NotApplicable,
        identity: format!("url:{}", digest(&canonical)),
        redacted: canonical,
        valid: true,
        reason: None,
    }
}

/// `_git_from_host_path` (:126).
fn git_from_host_path(host_value: &str, path_value: &str, fragment: Option<&str>) -> NpmSourceSpec {
    let mut path_value = path_value.to_string();
    let mut fragment = fragment.map(|s| s.to_string());
    if fragment.is_none() && path_value.contains('#') {
        // Borrowing split: clone the tail before reassigning the owned string.
        let (head, tail) = match path_value.split_once('#') {
            Some((h, t)) => (h.to_string(), Some(t.to_string())),
            None => (path_value.clone(), None),
        };
        path_value = head;
        fragment = tail;
    }
    let source_label = format!("{host_value}/{path_value}");
    let (host_part, separator, port_text) = {
        let mut it = host_value.splitn(2, ':');
        let h = it.next().unwrap_or("");
        match it.next() {
            Some(p) => (h, true, p),
            None => (h, false, ""),
        }
    };
    let canonical_host = match canonical_host(host_part) {
        Some(h) => h,
        None => return invalid(&source_label, "npm_source_host_invalid"),
    };
    let rendered_host = if separator {
        // Python `int(port_text)` allows a leading sign; whitespace forms are
        // rejected identically by both parsers.
        match port_text.parse::<i64>() {
            Ok(port) if (1..=65535).contains(&port) => format!("{canonical_host}:{port}"),
            _ => return invalid(&source_label, "npm_source_malformed_port"),
        }
    } else {
        canonical_host.clone()
    };
    if path_value.contains('?')
        || path_value.contains('\\')
        || ENCODED_SEPARATOR_RE.is_match(&path_value)
    {
        return invalid(&source_label, "npm_source_path_invalid");
    }
    let (path, archive_revision) = match repository_path(&canonical_host, &path_value) {
        (Some(p), r) => (p, r),
        (None, _) => return invalid(&source_label, "npm_source_path_invalid"),
    };
    let revision = match fragment.as_deref().map(str::trim) {
        Some(f) if !f.is_empty() => Some(f.to_string()),
        _ => archive_revision,
    };
    let (revision, revision_kind, revision_identity, revision_display) = match revision {
        None => (
            None,
            RevisionKind::Missing,
            "missing".to_string(),
            String::new(),
        ),
        Some(rev) => match canonical_revision(&rev) {
            None => return invalid(&source_label, "npm_source_revision_invalid"),
            Some(rev) if COMMIT_RE.is_match(&rev) => {
                let rev = rev.to_lowercase();
                (
                    Some(rev.clone()),
                    RevisionKind::ImmutableCommit,
                    format!("commit:{rev}"),
                    "#<immutable-commit>".to_string(),
                )
            }
            Some(rev) => (
                Some(rev.clone()),
                RevisionKind::MutableRef,
                format!("mutable:{}", digest(&rev)),
                "#<mutable-ref>".to_string(),
            ),
        },
    };
    let repository = format!("git:{rendered_host}/{path}");
    NpmSourceSpec {
        source_kind: SourceKind::Git,
        canonical_repository: Some(repository.clone()),
        revision,
        revision_kind,
        identity: format!("{repository}#{revision_identity}"),
        redacted: format!("{repository}{revision_display}"),
        valid: true,
        reason: None,
    }
}

/// `_repository_path` (:178) — `(path, revision)`; host-aware archive/`get`
/// revision extraction, then re-check `minimum_parts`, lowercase hosted parts,
/// strip trailing `.git`.
fn repository_path(host: &str, raw_path: &str) -> (Option<String>, Option<String>) {
    let hosted = HOSTED.iter().any(|(_, h)| *h == host);
    let minimum_parts = if hosted { 2 } else { 1 };
    let normalized = match canonical_path(raw_path, minimum_parts) {
        Some(p) => p,
        None => return (None, None),
    };
    let mut parts: Vec<String> = normalized.split('/').map(|s| s.to_string()).collect();
    let mut revision: Option<String> = None;
    if host == "github.com" && parts.len() > 2 {
        let marker = parts[2].to_lowercase();
        if ["archive", "tarball", "zipball"].contains(&marker.as_str()) {
            let rev = parts[3..].join("/");
            if !rev.is_empty() {
                revision = Some(strip_archive_suffix(&rev));
            }
            parts.truncate(2);
        } else {
            return (None, None);
        }
    } else if host == "gitlab.com" && parts.iter().any(|p| p == "-") {
        let marker_index = parts.iter().position(|p| p == "-").unwrap();
        if marker_index + 1 < parts.len() && parts[marker_index + 1].to_lowercase() == "archive" {
            let mut revision_parts: Vec<String> = parts[marker_index + 2..].to_vec();
            if revision_parts
                .last()
                .map(|p| looks_like_archive_filename(p))
                .unwrap_or(false)
            {
                revision_parts.pop();
            }
            let rev = revision_parts.join("/");
            if !rev.is_empty() {
                revision = Some(rev);
            }
            parts.truncate(marker_index);
        }
    } else if host == "bitbucket.org" && parts.len() > 2 {
        if parts[2].to_lowercase() != "get" {
            return (None, None);
        }
        let rev = strip_archive_suffix(&parts[3..].join("/"));
        if !rev.is_empty() {
            revision = Some(rev);
        }
        parts.truncate(2);
    }
    if parts.len() < minimum_parts {
        return (None, None);
    }
    if hosted {
        parts = parts.iter().map(|p| p.to_lowercase()).collect();
    }
    if parts
        .last()
        .map(|p| p.to_lowercase().ends_with(".git"))
        .unwrap_or(false)
    {
        let last = parts.last_mut().unwrap();
        *last = last[..last.len() - 4].to_string();
    }
    if parts.last().map(|p| p.is_empty()).unwrap_or(true) {
        return (None, None);
    }
    (Some(parts.join("/")), revision)
}

/// `_strip_archive_suffix` (:218).
fn strip_archive_suffix(value: &str) -> String {
    let lowered = value.to_lowercase();
    for suffix in [".tar.gz", ".tgz", ".tar", ".zip"] {
        if lowered.ends_with(suffix) {
            return value[..value.len() - suffix.len()].to_string();
        }
    }
    value.to_string()
}

/// `_looks_like_archive_filename` (:226).
fn looks_like_archive_filename(value: &str) -> bool {
    let lowered = value.to_lowercase();
    [".tar.gz", ".tgz", ".tar", ".zip"]
        .iter()
        .any(|s| lowered.ends_with(s))
}

/// `_canonical_path` (:231) — reject encoded separators/backslash, per-part
/// unquote+validate+re-quote, minimum part count.
fn canonical_path(raw_path: &str, minimum_parts: usize) -> Option<String> {
    if ENCODED_SEPARATOR_RE.is_match(raw_path) || raw_path.contains('\\') {
        return None;
    }
    let raw_parts: Vec<&str> = raw_path
        .trim_matches('/')
        .split('/')
        .filter(|p| !p.is_empty())
        .collect();
    if raw_parts.len() < minimum_parts {
        return None;
    }
    let mut normalized = Vec::with_capacity(raw_parts.len());
    for part in raw_parts {
        normalized.push(canonical_path_part(part)?);
    }
    Some(normalized.join("/"))
}

/// One `_canonical_path` part (:238-245): `unquote(errors="strict")` → reject
/// `.`/`..`/empty/`/`/`\`/NUL → `quote(decoded, safe="!$&'()+,;=@._~-")`.
fn canonical_path_part(part: &str) -> Option<String> {
    let decoded = percent_encoding::percent_decode_str(part)
        .decode_utf8()
        .ok()?
        .into_owned();
    if decoded == "."
        || decoded == ".."
        || decoded.is_empty()
        || decoded.contains('/')
        || decoded.contains('\\')
        || decoded.contains('\x00')
    {
        return None;
    }
    Some(percent_encode_path(&decoded))
}

/// `_canonical_revision` (:249).
fn canonical_revision(raw_revision: &str) -> Option<String> {
    if ENCODED_SEPARATOR_RE.is_match(raw_revision)
        || raw_revision.contains('\\')
        || raw_revision.contains('?')
    {
        return None;
    }
    let revision = percent_encoding::percent_decode_str(raw_revision)
        .decode_utf8()
        .ok()?
        .trim()
        .to_string();
    if revision.is_empty()
        || revision.contains('\x00')
        || revision.chars().any(|c| c.is_whitespace())
    {
        return None;
    }
    Some(revision)
}

/// `_canonical_host` (:261) — `rstrip(".")` → IDNA → lowercase.
fn canonical_host(host: &str) -> Option<String> {
    let trimmed = host.trim_end_matches('.');
    let ascii = idna::domain_to_ascii(trimmed).ok()?;
    let lowered = ascii.to_lowercase();
    if lowered.is_empty() {
        None
    } else {
        Some(lowered)
    }
}

/// `_host_with_port` (:268) — elide the scheme's default port.
fn host_with_port(host: &str, scheme: &str, port: Option<u16>) -> String {
    match port {
        Some(p) if default_port(scheme) != Some(p) => format!("{host}:{p}"),
        _ => host.to_string(),
    }
}

/// `_non_git_source` (:272).
fn non_git_source(kind: SourceKind, source: &str, redacted: &str) -> NpmSourceSpec {
    NpmSourceSpec {
        source_kind: kind,
        canonical_repository: None,
        revision: None,
        revision_kind: RevisionKind::NotApplicable,
        identity: format!("{}:{}", kind.as_str(), digest(source)),
        redacted: redacted.to_string(),
        valid: true,
        reason: None,
    }
}

/// `_invalid` (:283).
fn invalid(source: &str, reason: &str) -> NpmSourceSpec {
    NpmSourceSpec {
        source_kind: SourceKind::Invalid,
        canonical_repository: None,
        revision: None,
        revision_kind: RevisionKind::NotApplicable,
        identity: format!("invalid:{reason}:{}", digest(source)),
        redacted: "<invalid-source>".to_string(),
        valid: false,
        reason: Some(reason.to_string()),
    }
}

/// `_digest` (:296).
fn digest(value: &str) -> String {
    let mut h = Sha256::new();
    h.update(value.as_bytes());
    h.finalize().iter().map(|b| format!("{b:02x}")).collect()
}

// ─── urlsplit + percent helpers ─────────────────────────────────────────────

/// Minimal `urllib.parse.urlsplit` for the host-schemed sources this module
/// feeds it. `port` mirrors Python's `SplitResult.port` — `Err(())` on
/// non-numeric or out-of-range so callers emit `npm_source_malformed_port`.
/// No WHATWG host normalization; `_canonical_host` handles IDNA/case.
#[derive(Debug)]
/// `pub(crate)`: `package_intent_common::redact_url` (models.py `_redact_url`)
/// round-trips through urlsplit/urlunsplit.
pub(crate) struct SplitUrl {
    pub(crate) scheme: String,
    pub(crate) netloc: String,
    pub(crate) username: String,
    pub(crate) password: String,
    pub(crate) hostname: Option<String>,
    pub(crate) port: Result<Option<u16>, ()>,
    pub(crate) path: String,
    pub(crate) query: String,
    pub(crate) fragment: String,
}

impl Default for SplitUrl {
    fn default() -> Self {
        Self {
            scheme: String::new(),
            netloc: String::new(),
            username: String::new(),
            password: String::new(),
            hostname: None,
            port: Ok(None),
            path: String::new(),
            query: String::new(),
            fragment: String::new(),
        }
    }
}

pub(crate) fn split_url(url: &str) -> SplitUrl {
    let mut out = SplitUrl::default();
    let (before_frag, frag) = match url.split_once('#') {
        Some((b, f)) => (b, f),
        None => (url, ""),
    };
    out.fragment = frag.to_string();
    let (before_query, query) = match before_frag.split_once('?') {
        Some((b, q)) => (b, q),
        None => (before_frag, ""),
    };
    out.query = query.to_string();
    // scheme — `[A-Za-z][A-Za-z0-9+.-]*:` like Python.
    let (rest, scheme) = match before_query.find(':') {
        Some(i) if is_python_scheme(&before_query[..i]) => {
            (&before_query[i + 1..], &before_query[..i])
        }
        _ => (before_query, ""),
    };
    out.scheme = scheme.to_string();
    // netloc only when `//` follows.
    if let Some(after_slashes) = rest.strip_prefix("//") {
        let netloc_end = after_slashes
            .find(['/', '?', '#'])
            .unwrap_or(after_slashes.len());
        out.netloc = after_slashes[..netloc_end].to_string();
        out.path = after_slashes[netloc_end..].to_string();
        let (userinfo, hostport) = match out.netloc.rsplit_once('@') {
            Some((u, h)) => (u, h),
            None => ("", out.netloc.as_str()),
        };
        if !userinfo.is_empty() {
            match userinfo.split_once(':') {
                Some((u, p)) => {
                    out.username = u.to_string();
                    out.password = p.to_string();
                }
                None => out.username = userinfo.to_string(),
            }
        }
        if let Some(hs) = hostport.strip_prefix('[') {
            if let Some(close) = hs.find(']') {
                out.hostname = Some(hs[..close].to_string());
                let tail = &hs[close + 1..];
                if let Some(port_text) = tail.strip_prefix(':') {
                    out.port = parse_urlsplit_port(port_text);
                }
            } else {
                out.hostname = Some(hostport.to_string());
            }
        } else if let Some(colon) = hostport.rfind(':') {
            out.hostname = Some(hostport[..colon].to_string());
            out.port = parse_urlsplit_port(&hostport[colon + 1..]);
        } else {
            out.hostname = Some(hostport.to_string());
        }
    } else {
        out.path = rest.to_string();
    }
    out
}

/// Python `SplitResult.port`: digits only (urlsplit rejects non-numeric via
/// `ValueError`), `int()` range 0–65535, empty → `None`.
fn parse_urlsplit_port(text: &str) -> Result<Option<u16>, ()> {
    if text.is_empty() {
        return Ok(None);
    }
    if !text.bytes().all(|b| b.is_ascii_digit()) {
        return Err(());
    }
    text.parse::<u16>().map(Some).map_err(|_| ())
}

/// `[A-Za-z][A-Za-z0-9+.-]*` — Python's scheme character class.
fn is_python_scheme(text: &str) -> bool {
    let mut chars = text.chars();
    match chars.next() {
        Some(c) if c.is_ascii_alphabetic() => {}
        _ => return false,
    }
    chars.all(|c| c.is_ascii_alphanumeric() || c == '+' || c == '-' || c == '.')
}

/// `urllib.parse.quote(value, safe="!$&'()+,;=@._~-")` — the module's explicit
/// safe set (already contains the always-safe `._-~` and alnum range).
fn percent_encode_path(value: &str) -> String {
    const SAFE: &percent_encoding::AsciiSet = &percent_encoding::NON_ALPHANUMERIC
        .remove(b'!')
        .remove(b'$')
        .remove(b'&')
        .remove(b'\'')
        .remove(b'(')
        .remove(b')')
        .remove(b'+')
        .remove(b',')
        .remove(b';')
        .remove(b'=')
        .remove(b'@')
        .remove(b'.')
        .remove(b'_')
        .remove(b'~')
        .remove(b'-');
    percent_encoding::utf8_percent_encode(value, SAFE).to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hosted_github_shorthand() {
        let spec = parse_npm_source_spec(Some("github:owner/repo")).unwrap();
        assert!(spec.is_git());
        assert_eq!(
            spec.canonical_repository.as_deref(),
            Some("git:github.com/owner/repo")
        );
        assert_eq!(spec.redacted, "git:github.com/owner/repo");
        assert!(spec
            .identity
            .starts_with("git:github.com/owner/repo#missing"));
    }

    #[test]
    fn bare_owner_repo_is_github() {
        let spec = parse_npm_source_spec(Some("owner/repo")).unwrap();
        assert!(spec.is_git());
        assert_eq!(
            spec.canonical_repository.as_deref(),
            Some("git:github.com/owner/repo")
        );
    }

    #[test]
    fn registry_spec_returns_none() {
        assert!(parse_npm_source_spec(Some("lodash@^4.0.0")).is_none());
        assert!(parse_npm_source_spec(Some("lodash")).is_none());
        assert!(parse_npm_source_spec(None).is_none());
    }

    #[test]
    fn github_archive_revision() {
        let spec = parse_npm_source_spec(Some("github:owner/repo/archive/v1.2.3.tar.gz")).unwrap();
        assert_eq!(spec.revision.as_deref(), Some("v1.2.3"));
        assert_eq!(spec.revision_kind, RevisionKind::MutableRef);
        assert_eq!(
            spec.canonical_repository.as_deref(),
            Some("git:github.com/owner/repo")
        );
    }

    #[test]
    fn scp_userinfo_gate() {
        let spec = parse_npm_source_spec(Some("git@github.com:owner/repo.git")).unwrap();
        assert!(spec.is_git());
        let bad = parse_npm_source_spec(Some("root@github.com:owner/repo")).unwrap();
        assert_eq!(bad.reason.as_deref(), Some("npm_source_ambiguous_userinfo"));
    }
}

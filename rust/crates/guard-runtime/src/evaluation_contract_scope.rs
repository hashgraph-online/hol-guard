//! Path, endpoint and timestamp rules for the `evaluation_contract` kind.
//! Ported from `evaluation_contracts.py` (`_validate_local_path`,
//! `_portable_path_style`, `_path_is_within`, `_validate_local_endpoint`,
//! `_endpoint_identity` and `_record_timestamp`).
//!
//! Portable checks read a recorded path by its spelling alone, with the
//! `posixpath` or `ntpath` rules its style names, so another host's evidence
//! can be verified. Host checks resolve paths as `os.path.realpath` does and
//! require them under the caller's `tempfile.gettempdir()`.

use std::net::Ipv6Addr;
use std::path::Path;

use serde_json::Value;

use crate::cloud_request_text::py_isspace;
use crate::consumer_url::{url_hostname, url_splits};
use crate::guard_paths::python_realpath_lax;
use crate::runner_sync_url::urlsplit;

pub(super) type Check<T> = Result<T, String>;

const UNC_PREFIX: &str = "\\\\?\\UNC\\";

#[derive(Clone, Copy, PartialEq, Eq)]
enum Style {
    Posix,
    Windows,
}

pub(super) struct Scope<'a> {
    pub(super) portable: bool,
    pub(super) temp_root: &'a str,
}

impl Scope<'_> {
    /// `_validate_record_path`: the recorded path, or why it is refused.
    pub(super) fn record_path<'v>(&self, value: &'v Value, name: &str) -> Check<&'v str> {
        if self.portable {
            return match value.as_str() {
                Some(text) if portable_style(text).is_some() => Ok(text),
                _ => Err(format!("{name} must be an absolute local path")),
            };
        }
        let text = match value.as_str() {
            Some(text) if !text.is_empty() && !has_outer_space(text) => text,
            _ => return Err(format!("{name} must be an absolute temporary path")),
        };
        let windows = cfg!(windows) && windows_temporary(text, self.temp_root, &host_realpath);
        if !(self.posix_temporary(text) || windows) {
            return Err(format!("{name} must remain under a temporary test root"));
        }
        Ok(text)
    }

    /// `_path_is_within`: whether `path` is `root` or lies below it.
    pub(super) fn within(&self, path: &str, root: &str) -> bool {
        if self.portable {
            let Some(style) = portable_style(path) else {
                return false;
            };
            if portable_style(root) != Some(style) {
                return false;
            }
            return match style {
                Style::Posix => posix_within(path, root),
                Style::Windows => nt_within(&nt_normcase(path), &nt_normcase(root)),
            };
        }
        let (Some(candidate), Some(root)) = (host_realpath(path), host_realpath(root)) else {
            return false;
        };
        if cfg!(windows) {
            return nt_within(&nt_normcase(&candidate), &nt_normcase(&root));
        }
        posix_within(&candidate, &root)
    }

    /// `_is_posix_temp_path`: a string prefix test on the resolved paths.
    fn posix_temporary(&self, path: &str) -> bool {
        if path.contains('\0') || !Path::new(path).is_absolute() {
            return false;
        }
        let (Some(candidate), Some(root)) = (host_realpath(path), host_realpath(self.temp_root))
        else {
            return false;
        };
        candidate.starts_with(&format!("{root}{}", std::path::MAIN_SEPARATOR))
    }
}

fn host_realpath(path: &str) -> Option<String> {
    let resolved = python_realpath_lax(Path::new(path)).ok()?;
    resolved.to_str().map(str::to_owned)
}

fn has_outer_space(text: &str) -> bool {
    text.starts_with(py_isspace) || text.ends_with(py_isspace)
}

/// `_portable_path_style`.
fn portable_style(value: &str) -> Option<Style> {
    if value.is_empty() || value.contains('\0') || has_outer_space(value) {
        return None;
    }
    if value.starts_with('/') && !value.starts_with("//") && !value.contains('\\') {
        return (!value.split('/').any(|part| part == "..")).then_some(Style::Posix);
    }
    let (drive, _, _) = nt_splitroot(value);
    if !drive.is_empty() && nt_isabs(value) && !value.starts_with("\\\\") {
        let spelled = value.replace('/', "\\");
        return (!spelled.split('\\').any(|part| part == "..")).then_some(Style::Windows);
    }
    None
}

/// `posixpath.commonpath((path, root)) == root` for absolute spellings.
fn posix_within(path: &str, root: &str) -> bool {
    let parts = |text: &'_ str| -> Vec<String> {
        text.split('/')
            .filter(|part| !part.is_empty() && *part != ".")
            .map(str::to_owned)
            .collect()
    };
    let (path, root) = (parts(path), parts(root));
    path.len() >= root.len() && path[..root.len()] == root[..]
}

/// `_is_windows_temp_path` with the resolver passed in, so its junction rule
/// is testable on every host. Only a Windows host asks it.
pub(super) fn windows_temporary(
    path: &str,
    temp_root: &str,
    realpath: &dyn Fn(&str) -> Option<String>,
) -> bool {
    if path.contains('\0') || !nt_isabs(path) || path.starts_with("\\\\") {
        return false;
    }
    let (Some(candidate), Some(root)) = (realpath(path), realpath(temp_root)) else {
        return false;
    };
    let candidate = nt_normcase(&nt_normpath(&candidate));
    let root = nt_normcase(&nt_normpath(&root));
    candidate != root && nt_within(&candidate, &root)
}

/// `ntpath.isabs` (CPython 3.12): a UNC, device or drive-rooted spelling.
fn nt_isabs(path: &str) -> bool {
    let head: Vec<char> = path
        .chars()
        .take(3)
        .map(|c| if c == '/' { '\\' } else { c })
        .collect();
    head.first() == Some(&'\\') || head.get(1..3) == Some(&[':', '\\'][..])
}

/// `ntpath.splitroot` (CPython 3.12): drive, root and the rest.
fn nt_splitroot(path: &str) -> (String, String, String) {
    let chars: Vec<char> = path.chars().collect();
    let normal: Vec<char> = chars
        .iter()
        .map(|c| if *c == '/' { '\\' } else { *c })
        .collect();
    let text = |range: std::ops::Range<usize>| chars[range].iter().collect::<String>();
    let length = chars.len();
    if normal.first() == Some(&'\\') {
        if normal.get(1) != Some(&'\\') {
            return (String::new(), text(0..1), text(1..length));
        }
        let head: String = normal
            .iter()
            .take(8)
            .collect::<String>()
            .to_ascii_uppercase();
        let start = if head == UNC_PREFIX { 8 } else { 2 };
        let find = |from: usize| (from..length).find(|index| normal[*index] == '\\');
        let Some(first) = find(start) else {
            return (path.to_owned(), String::new(), String::new());
        };
        let Some(second) = find(first + 1) else {
            return (path.to_owned(), String::new(), String::new());
        };
        return (
            text(0..second),
            text(second..second + 1),
            text(second + 1..length),
        );
    }
    if normal.get(1) == Some(&':') {
        if normal.get(2) == Some(&'\\') {
            return (text(0..2), text(2..3), text(3..length));
        }
        return (text(0..2), String::new(), text(2..length));
    }
    (String::new(), String::new(), path.to_owned())
}

/// `ntpath.normcase` as CPython spells it off Windows.
fn nt_normcase(path: &str) -> String {
    path.replace('/', "\\").to_lowercase()
}

/// `ntpath.normpath` (CPython 3.12).
fn nt_normpath(path: &str) -> String {
    let (drive, root, rest) = nt_splitroot(&path.replace('/', "\\"));
    let mut parts: Vec<&str> = Vec::new();
    for part in rest.split('\\') {
        match part {
            "" | "." => {}
            ".." if parts.last().is_some_and(|last| *last != "..") => {
                parts.pop();
            }
            ".." if parts.is_empty() && !root.is_empty() => {}
            _ => parts.push(part),
        }
    }
    let prefix = format!("{drive}{root}");
    if prefix.is_empty() && parts.is_empty() {
        return ".".to_owned();
    }
    format!("{prefix}{}", parts.join("\\"))
}

/// `ntpath.commonpath((path, root)) == root` for normalized, case-folded
/// spellings; a drive or root mismatch is Python's `ValueError`.
fn nt_within(path: &str, root: &str) -> bool {
    let (path_drive, path_root, path_rest) = nt_splitroot(path);
    let (root_drive, root_root, root_rest) = nt_splitroot(root);
    if path_drive != root_drive || path_root != root_root {
        return false;
    }
    let parts = |rest: &str| -> Vec<String> {
        rest.split('\\')
            .filter(|part| !part.is_empty() && *part != ".")
            .map(str::to_owned)
            .collect()
    };
    let (path_parts, root_parts) = (parts(&path_rest), parts(&root_rest));
    path_parts.len() >= root_parts.len() && path_parts[..root_parts.len()] == root_parts[..]
}

/// What `urlsplit` reports about an endpoint, or `None` where it or
/// `SplitResult.port` raises `ValueError`.
struct Endpoint {
    scheme: String,
    hostname: Option<String>,
    port: Option<u16>,
    path: String,
    query: String,
    fragment: String,
    userinfo: bool,
}

fn parse_endpoint(text: &str) -> Option<Endpoint> {
    if !url_splits(text) {
        return None;
    }
    let split = urlsplit(text);
    let info = split
        .netloc
        .rsplit_once('@')
        .map_or(split.netloc.as_str(), |(_, tail)| tail);
    let port_text = match info.split_once('[') {
        Some((_, bracketed)) => bracketed
            .split_once(']')
            .and_then(|(_, tail)| tail.split_once(':'))
            .map_or("", |(_, port)| port),
        None => info.split_once(':').map_or("", |(_, port)| port),
    };
    let port = if port_text.is_empty() {
        None
    } else {
        if !port_text.bytes().all(|byte| byte.is_ascii_digit()) {
            return None;
        }
        Some(u16::try_from(port_text.parse::<u32>().ok()?).ok()?)
    };
    Some(Endpoint {
        userinfo: split.netloc.contains('@'),
        hostname: url_hostname(text),
        scheme: split.scheme,
        port,
        path: split.path,
        query: split.query,
        fragment: split.fragment,
    })
}

/// `_validate_local_endpoint`: a numeric loopback HTTP(S) URL.
pub(super) fn local_endpoint<'v>(value: &'v Value, name: &str) -> Check<&'v str> {
    let invalid = || format!("{name} must be a loopback HTTP(S) endpoint");
    let text = match value.as_str() {
        Some(text) if !text.is_empty() && !text.chars().any(py_isspace) => text,
        _ => return Err(invalid()),
    };
    let endpoint = parse_endpoint(text).ok_or_else(invalid)?;
    let Some(hostname) = endpoint.hostname.as_deref() else {
        return Err(invalid());
    };
    if !matches!(endpoint.scheme.as_str(), "http" | "https") {
        return Err(invalid());
    }
    if endpoint.userinfo || !endpoint.fragment.is_empty() {
        return Err(format!("{name} must not contain credentials or a fragment"));
    }
    if endpoint.port == Some(0) {
        return Err(format!("{name} has an invalid port"));
    }
    if !ip_is_loopback(&hostname.trim_end_matches('.').to_lowercase()) {
        return Err(format!("{name} must use a numeric loopback IP"));
    }
    Ok(text)
}

/// Scheme, hostname, effective port, path without a trailing slash, query.
pub(super) type EndpointIdentity = (String, Option<String>, u16, String, String);

/// `_endpoint_identity` for an endpoint `local_endpoint` accepted.
pub(super) fn endpoint_identity(text: &str) -> Option<EndpointIdentity> {
    let endpoint = parse_endpoint(text)?;
    let default_port = if endpoint.scheme == "https" { 443 } else { 80 };
    let path = endpoint.path.trim_end_matches('/');
    Some((
        endpoint.scheme,
        endpoint.hostname,
        endpoint
            .port
            .filter(|port| *port != 0)
            .unwrap_or(default_port),
        if path.is_empty() {
            "/".to_owned()
        } else {
            path.to_owned()
        },
        endpoint.query,
    ))
}

/// `ipaddress.ip_address(host).is_loopback` as current CPython answers it: an
/// IPv4-mapped IPv6 address is loopback when its IPv4 address is.
fn ip_is_loopback(host: &str) -> bool {
    if let Some(octets) = ipv4_octets(host) {
        return octets[0] == 127;
    }
    let (address, scope) = match host.split_once('%') {
        Some((address, scope)) => (address, Some(scope)),
        None => (host, None),
    };
    if scope.is_some_and(|scope| scope.is_empty() || scope.contains('%')) {
        return false;
    }
    if let Some((_, tail)) = address.rsplit_once(':') {
        if tail.contains('.') && ipv4_octets(tail).is_none() {
            return false;
        }
    }
    address.parse::<Ipv6Addr>().is_ok_and(|address| {
        address
            .to_ipv4_mapped()
            .map_or(address == Ipv6Addr::LOCALHOST, |mapped| {
                mapped.octets()[0] == 127
            })
    })
}

/// `IPv4Address`'s strict dotted-quad parser: no leading zeros.
fn ipv4_octets(text: &str) -> Option<[u8; 4]> {
    let parts: Vec<&str> = text.split('.').collect();
    if parts.len() != 4 {
        return None;
    }
    let mut octets = [0u8; 4];
    for (slot, part) in octets.iter_mut().zip(parts) {
        if part.is_empty()
            || part.len() > 3
            || !part.bytes().all(|byte| byte.is_ascii_digit())
            || (part.len() > 1 && part.starts_with('0'))
        {
            return None;
        }
        *slot = u8::try_from(part.parse::<u16>().ok()?).ok()?;
    }
    Some(octets)
}

/// `_record_timestamp`: microseconds since the epoch of a zoned RFC 3339
/// timestamp, with any fraction cut to microseconds.
pub(super) fn record_timestamp(value: &Value, name: &str) -> Check<i128> {
    value
        .as_str()
        .and_then(parse_timestamp)
        .ok_or_else(|| format!("{name} must be a zoned RFC3339 timestamp"))
}

fn number(text: Option<&str>) -> Option<i64> {
    let text = text?;
    if text.is_empty() || !text.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    text.parse().ok()
}

fn parse_timestamp(text: &str) -> Option<i128> {
    let bytes = text.as_bytes();
    if bytes.len() < 20 || [4, 7, 10, 13, 16].map(|index| bytes[index]) != *b"--T::" {
        return None;
    }
    let year = number(text.get(0..4))?;
    let month = number(text.get(5..7))?;
    let day = number(text.get(8..10))?;
    let hour = number(text.get(11..13))?;
    let minute = number(text.get(14..16))?;
    let second = number(text.get(17..19))?;
    let mut rest = text.get(19..)?;
    let mut micros = 0;
    if let Some(after) = rest.strip_prefix('.') {
        let digits = after.bytes().take_while(u8::is_ascii_digit).count();
        if digits == 0 {
            return None;
        }
        micros = number(Some(format!("{:0<6}", &after[..digits.min(6)]).as_str()))?;
        rest = &after[digits..];
    }
    let offset_minutes = if rest == "Z" {
        0
    } else {
        let sign = match rest.as_bytes().first() {
            Some(b'+') => 1,
            Some(b'-') => -1,
            _ => return None,
        };
        if rest.len() != 6 || rest.as_bytes()[3] != b':' {
            return None;
        }
        let total = number(rest.get(1..3))? * 60 + number(rest.get(4..6))?;
        if total >= 24 * 60 {
            return None;
        }
        sign * total
    };
    if !(1..=9999).contains(&year)
        || !(1..=12).contains(&month)
        || day < 1
        || day > days_in_month(year, month)
        || hour > 23
        || minute > 59
        || second > 59
    {
        return None;
    }
    let seconds = days_from_civil(year, month, day) * 86_400 + hour * 3_600 + minute * 60 + second
        - offset_minutes * 60;
    Some(i128::from(seconds) * 1_000_000 + i128::from(micros))
}

fn days_in_month(year: i64, month: i64) -> i64 {
    match month {
        2 if year % 4 == 0 && (year % 100 != 0 || year % 400 == 0) => 29,
        2 => 28,
        4 | 6 | 9 | 11 => 30,
        _ => 31,
    }
}

/// Days from 1970-01-01 to a proleptic Gregorian date.
fn days_from_civil(year: i64, month: i64, day: i64) -> i64 {
    let year = if month <= 2 { year - 1 } else { year };
    let era = year.div_euclid(400);
    let year_of_era = year - era * 400;
    let month_index = (month + 9) % 12;
    let day_of_year = (153 * month_index + 2) / 5 + day - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    era * 146_097 + day_of_era - 719_468
}

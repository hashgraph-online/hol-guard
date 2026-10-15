//! Query, daemon-state path and loopback URL checks for the native Claude
//! hook bridge, ported from `adapters/claude_daemon_hook_bridge.py` and the
//! `urllib.parse` behaviour it relies on.

use std::path::{Path, PathBuf};

use crate::claude_hook_bridge_auth::LOOPBACK_HOSTS;
use crate::claude_hook_bridge_transport::py_repr;
use crate::daemon_policy_authority::load_authenticated_daemon_state;
#[cfg(not(windows))]
use crate::oci_path::resolve_lenient;

const STATE_FILE_NAME: &str = "daemon-state.json";

/// `urllib.parse.unquote(text)`: each ASCII run is percent-decoded to bytes
/// and then decoded as UTF-8 with replacement; other characters pass through
/// and malformed escapes stay literal.
pub(crate) fn py_unquote(text: &str) -> String {
    if !text.contains('%') {
        return text.to_owned();
    }
    let mut out = String::with_capacity(text.len());
    let mut run = Vec::new();
    for character in text.chars() {
        if character.is_ascii() {
            run.push(character as u8);
        } else {
            flush_ascii_run(&mut run, &mut out);
            out.push(character);
        }
    }
    flush_ascii_run(&mut run, &mut out);
    out
}

fn flush_ascii_run(run: &mut Vec<u8>, out: &mut String) {
    if run.is_empty() {
        return;
    }
    let mut bytes = Vec::with_capacity(run.len());
    let mut index = 0;
    while index < run.len() {
        let escaped = run.get(index + 1..index + 3).and_then(|digits| {
            let digits = std::str::from_utf8(digits).ok()?;
            if !digits.bytes().all(|byte| byte.is_ascii_hexdigit()) {
                return None;
            }
            u8::from_str_radix(digits, 16).ok()
        });
        match (run[index], escaped) {
            (b'%', Some(byte)) => {
                bytes.push(byte);
                index += 3;
            }
            (byte, _) => {
                bytes.push(byte);
                index += 1;
            }
        }
    }
    out.push_str(&String::from_utf8_lossy(&bytes));
    run.clear();
}

/// `urllib.parse.parse_qs(query)` values for one name: `&`-separated
/// fields, blank values and fields without `=` dropped, `+` as a space.
pub(crate) fn query_values(query: &str, name: &str) -> Vec<String> {
    query
        .split('&')
        .filter_map(|field| field.split_once('='))
        .filter(|(_, value)| !value.is_empty())
        .filter(|(key, _)| py_unquote(&key.replace('+', " ")) == name)
        .map(|(_, value)| py_unquote(&value.replace('+', " ")))
        .collect()
}

/// `canonical_daemon_state_path`.
fn canonical_daemon_state_path(raw: &str) -> Result<PathBuf, String> {
    if raw.is_empty() || raw.contains('\0') {
        return Err("daemon state path must be a non-empty filesystem path".to_owned());
    }
    let path = Path::new(raw);
    if !path.is_absolute()
        || path.file_name().and_then(|name| name.to_str()) != Some(STATE_FILE_NAME)
    {
        return Err("daemon state path must be an absolute daemon-state.json path".to_owned());
    }
    Ok(path.to_path_buf())
}

fn state_parent(path: &Path) -> &Path {
    path.parent().unwrap_or_else(|| Path::new("/"))
}

fn resolved_text(path: &Path) -> String {
    resolve_absolute(&path.to_string_lossy())
}

/// `str(Path(path).resolve())` for an absolute path: CPython's POSIX
/// `realpath` walk on Unix.
#[cfg(not(windows))]
pub(crate) fn resolve_absolute(path: &str) -> String {
    resolve_lenient(path)
}

/// `str(Path(path).resolve())` for an absolute path on Windows: `ntpath`
/// normalizes the path, resolves the longest existing prefix to its final
/// name, keeps the rest lexically, and drops the `\\?\` prefix.
#[cfg(windows)]
pub(crate) fn resolve_absolute(path: &str) -> String {
    let Ok(absolute) = std::path::absolute(path) else {
        return path.to_owned();
    };
    let mut existing = absolute.as_path();
    let mut rest = Vec::new();
    loop {
        if let Ok(canonical) = std::fs::canonicalize(existing) {
            let mut resolved = PathBuf::from(strip_verbatim(&canonical.to_string_lossy()));
            resolved.extend(rest.iter().rev());
            return resolved.to_string_lossy().into_owned();
        }
        match (existing.parent(), existing.file_name()) {
            (Some(parent), Some(name)) => {
                rest.push(name.to_owned());
                existing = parent;
            }
            _ => return absolute.to_string_lossy().into_owned(),
        }
    }
}

#[cfg(windows)]
fn strip_verbatim(path: &str) -> String {
    if let Some(unc) = path.strip_prefix(r"\\?\UNC\") {
        format!(r"\\{unc}")
    } else {
        path.strip_prefix(r"\\?\").unwrap_or(path).to_owned()
    }
}

/// `state_path_for_query`: the state path, bound to the query's Guard home.
pub(crate) fn state_path_for_query(raw: &str, query: &str) -> Result<PathBuf, String> {
    let path = canonical_daemon_state_path(raw)?;
    let homes = query_values(query, "guard-home");
    let [home] = homes.as_slice() else {
        return Err("daemon hook query must bind one Guard home".to_owned());
    };
    if home.contains('\0') {
        return Err("daemon hook query contains an invalid Guard home".to_owned());
    }
    if !Path::new(home).is_absolute()
        || resolved_text(state_parent(&path)) != resolve_absolute(home)
    {
        return Err("daemon state path does not match the hook Guard home".to_owned());
    }
    Ok(path)
}

/// `daemon_port_from_state` reduced to whether it finds a port: the
/// transport always reconnects to the authenticated state's own address.
pub(crate) fn state_names_loopback_port(path: &Path) -> bool {
    let parent = state_parent(path);
    let Some(payload) = load_authenticated_daemon_state(parent) else {
        return false;
    };
    let expected_home = resolved_text(parent);
    let home_matches =
        payload.get("guard_home").and_then(|value| value.as_str()) == Some(expected_home.as_str());
    let host_is_loopback = payload
        .get("host")
        .and_then(|value| value.as_str())
        .is_some_and(|host| LOOPBACK_HOSTS.contains(&host));
    let port_is_valid = payload
        .get("port")
        .and_then(|value| value.as_u64())
        .is_some_and(|port| (1..=65_535).contains(&port));
    home_matches && host_is_loopback && port_is_valid
}

const SCHEME_EXTRA: [char; 3] = ['+', '-', '.'];

/// Whether `urlsplit` accepts a bracketed host as an IPv6 address
/// (`ipaddress.ip_address`, scope id allowed).
fn is_ipv6_literal(hostname: &str) -> bool {
    let address = hostname
        .split_once('%')
        .map_or(hostname, |(address, _)| address);
    address.parse::<std::net::Ipv6Addr>().is_ok()
}

/// `_assert_loopback_http_url` over CPython's `urlsplit`. A bracketed
/// host `ipaddress` rejects is reported as a non-loopback host rather than
/// with `ipaddress`'s wording; both refuse the URL.
pub(crate) fn assert_loopback_http_url(url: &str) -> Result<(), String> {
    let url = url.trim_start_matches(|character| character <= ' ');
    let url: String = url
        .chars()
        .filter(|character| !matches!(character, '\t' | '\r' | '\n'))
        .collect();
    let mut scheme = String::new();
    let mut rest = url.as_str();
    if let Some(index) = url.find(':') {
        let candidate = &url[..index];
        let starts_alpha = candidate
            .chars()
            .next()
            .is_some_and(|first| first.is_ascii_alphabetic());
        if starts_alpha
            && candidate.chars().all(|character| {
                character.is_ascii_alphanumeric() || SCHEME_EXTRA.contains(&character)
            })
        {
            scheme = candidate.to_ascii_lowercase();
            rest = &url[index + 1..];
        }
    }
    let netloc = match rest.strip_prefix("//") {
        Some(after) => {
            let end = after.find(['/', '?', '#']).unwrap_or(after.len());
            &after[..end]
        }
        None => "",
    };
    if netloc.contains('[') != netloc.contains(']') {
        return Err("Invalid IPv6 URL".to_owned());
    }
    let hostinfo = netloc.rsplit_once('@').map_or(netloc, |(_, host)| host);
    let (hostname, port, bracketed) = match hostinfo.split_once('[') {
        Some((before, bracketed)) => {
            let (hostname, after) = bracketed.split_once(']').unwrap_or((bracketed, ""));
            if !before.is_empty() || (!after.is_empty() && !after.starts_with(':')) {
                return Err("Invalid IPv6 URL".to_owned());
            }
            let port = after.split_once(':').map_or("", |(_, port)| port);
            (hostname, port, true)
        }
        None => {
            let (hostname, port) = hostinfo.split_once(':').unwrap_or((hostinfo, ""));
            (hostname, port, false)
        }
    };
    let host = hostname.to_lowercase();
    if bracketed && !hostname.starts_with('v') && !is_ipv6_literal(hostname) {
        return Err(format!(
            "daemon URL must target loopback, not {}",
            py_repr(&host)
        ));
    }
    if scheme != "http" {
        return Err(format!(
            "daemon URL must use http, not {}",
            py_repr(&scheme)
        ));
    }
    if !LOOPBACK_HOSTS.contains(&host.as_str()) {
        return Err(format!(
            "daemon URL must target loopback, not {}",
            py_repr(&host)
        ));
    }
    if port.is_empty() {
        return Err("daemon URL must include an explicit port".to_owned());
    }
    if !port.chars().all(|character| character.is_ascii_digit()) {
        return Err(format!(
            "Port could not be cast to integer value as {}",
            py_repr(port)
        ));
    }
    if port.trim_start_matches('0').len() > 5
        || port.parse::<u32>().is_ok_and(|value| value > 65_535)
    {
        return Err("Port out of range 0-65535".to_owned());
    }
    Ok(())
}

/// The query `urlparse(urljoin(base, "/v1/hooks/claude-code?" + query))`
/// yields: tab and newline characters removed, cut at any fragment.
pub(crate) fn endpoint_query(query: &str) -> String {
    let cleaned: String = query
        .chars()
        .filter(|character| !matches!(character, '\t' | '\r' | '\n'))
        .collect();
    match cleaned.split_once('#') {
        Some((before, _)) => before.to_owned(),
        None => cleaned,
    }
}

#[cfg(all(test, windows))]
mod windows_tests {
    use super::*;

    fn guard_home(label: &str) -> PathBuf {
        let home = std::env::temp_dir().join(format!("hol-bridge-{label}-{}", std::process::id()));
        std::fs::create_dir_all(&home).unwrap();
        home
    }

    #[test]
    fn drive_guard_home_binds_its_own_state_path() {
        let home = guard_home("binds");
        let state = home.join(STATE_FILE_NAME);
        let query = format!("guard-home={}", home.display()).replace('\\', "%5C");
        assert_eq!(
            state_path_for_query(&state.to_string_lossy(), &query),
            Ok(state.clone())
        );
        let forward = home.to_string_lossy().replace('\\', "/");
        assert_eq!(
            state_path_for_query(&state.to_string_lossy(), &format!("guard-home={forward}")),
            Ok(state)
        );
        let _ = std::fs::remove_dir_all(home);
    }

    #[test]
    fn resolve_absolute_matches_python_resolve() {
        let home = guard_home("resolve");
        let resolved = resolve_absolute(&home.to_string_lossy());
        assert!(!resolved.starts_with(r"\\?\"), "{resolved}");
        assert!(Path::new(&resolved).is_absolute(), "{resolved}");
        assert_eq!(
            resolve_absolute(&format!("{}\\missing\\..\\next", home.display())),
            format!("{resolved}\\next")
        );
        let _ = std::fs::remove_dir_all(home);
    }

    #[test]
    fn another_guard_home_does_not_bind_the_state_path() {
        let home = guard_home("other");
        let state = home.join(STATE_FILE_NAME);
        assert_eq!(
            state_path_for_query(&state.to_string_lossy(), "guard-home=C:%5Cother-home"),
            Err("daemon state path does not match the hook Guard home".to_owned())
        );
        let _ = std::fs::remove_dir_all(home);
    }
}

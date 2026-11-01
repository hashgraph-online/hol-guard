//! `system-proxies --stdin`: the operating system's proxy settings for a
//! managed `proxy_mode = "system"` policy (`mdm/network_transport.py`'s
//! `platform_system_proxies` before it moved here).
//!
//! macOS reads `/usr/sbin/scutil --proxy`. Windows reads `ProxyEnable` and
//! `ProxyServer` under the Internet Settings key, the current user first and
//! the machine second. Environment variables never count, and any other
//! platform, or a probe that fails, has no system proxy.

use std::collections::BTreeMap;
use std::io::Read;
use std::path::Path;
use std::time::{Duration, Instant};

use regex::Regex;
use serde::Deserialize;
use serde_json::{json, Map, Value};

use crate::github_workflow_context_io::run_bounded;

const SCHEMA: &str = "system-proxies.v1";
const MAX_REQUEST_BYTES: u64 = 4 * 1024;
const SCUTIL_TIMEOUT: Duration = Duration::from_secs(5);
#[cfg_attr(not(windows), allow(dead_code))]
const INTERNET_SETTINGS: &str = r"Software\Microsoft\Windows\CurrentVersion\Internet Settings";
#[cfg_attr(not(windows), allow(dead_code))]
const MAX_REGISTRY_VALUE_BYTES: usize = 64 * 1024;
const REG_SZ: u32 = 1;
const REG_EXPAND_SZ: u32 = 2;
const REG_DWORD: u32 = 4;
const REG_DWORD_BIG_ENDIAN: u32 = 5;
const REG_MULTI_SZ: u32 = 7;
const REG_QWORD: u32 = 11;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Request {
    schema: String,
}

/// The registry hive a Windows read opens.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Hive {
    CurrentUser,
    LocalMachine,
}

pub(crate) fn is_command(command: &str) -> bool {
    command == "system-proxies"
}

pub(crate) fn run_command(reader: impl Read) -> Result<Vec<u8>, String> {
    let mut bytes = Vec::new();
    reader
        .take(MAX_REQUEST_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| "system_proxies_request_unreadable".to_owned())?;
    if bytes.len() as u64 > MAX_REQUEST_BYTES {
        return Err("system_proxies_request_too_large".to_owned());
    }
    let request: Request =
        serde_json::from_slice(&bytes).map_err(|_| "system_proxies_request_invalid".to_owned())?;
    if request.schema != SCHEMA {
        return Err("system_proxies_request_invalid".to_owned());
    }
    let proxies = if cfg!(target_os = "macos") {
        macos_proxies(scutil_output().as_deref().unwrap_or_default())
    } else if cfg!(windows) {
        windows_proxies(registry_value)
    } else {
        Map::new()
    };
    serde_json::to_vec(&json!({"ok": true, "proxies": proxies}))
        .map_err(|_| "system_proxies_response_encode_failed".to_owned())
}

fn scutil_output() -> Option<String> {
    let arguments = ["/usr/sbin/scutil".to_owned(), "--proxy".to_owned()];
    let stdout = run_bounded(
        &arguments,
        Path::new("/"),
        &BTreeMap::new(),
        Instant::now() + SCUTIL_TIMEOUT,
    )?;
    String::from_utf8(stdout).ok()
}

/// The `HTTP`/`HTTPS` proxies `scutil --proxy` reports as enabled, each as
/// `http://host:port` with the scheme's default port when none is set.
fn macos_proxies(stdout: &str) -> Map<String, Value> {
    let Ok(pattern) = Regex::new(r"(?m)^\s*([A-Za-z]+)\s*:\s*(.+?)\s*$") else {
        return Map::new();
    };
    let values: BTreeMap<&str, &str> = pattern
        .captures_iter(stdout)
        .filter_map(|found| Some((found.get(1)?.as_str(), found.get(2)?.as_str())))
        .collect();
    let mut proxies = Map::new();
    for (scheme, prefix, default_port) in [("http", "HTTP", "80"), ("https", "HTTPS", "443")] {
        let field = |name: &str| values.get(format!("{prefix}{name}").as_str()).copied();
        let Some(host) = field("Proxy").filter(|host| !host.is_empty()) else {
            continue;
        };
        if field("Enable") == Some("1") {
            let port = field("Port").unwrap_or(default_port);
            proxies.insert(scheme.to_owned(), json!(format!("http://{host}:{port}")));
        }
    }
    proxies
}

/// The proxies the first hive with an enabled, textual `ProxyServer` names.
/// A hive whose values cannot both be read is skipped.
fn windows_proxies(
    mut read: impl FnMut(Hive, &str) -> Option<(u32, Vec<u8>)>,
) -> Map<String, Value> {
    let server = [Hive::CurrentUser, Hive::LocalMachine]
        .into_iter()
        .find_map(|hive| {
            let (enable_kind, enable) = read(hive, "ProxyEnable")?;
            let (server_kind, server) = read(hive, "ProxyServer")?;
            if !registry_truthy(enable_kind, &enable) {
                return None;
            }
            registry_text(server_kind, &server)
        });
    let Some(server) = server else {
        return Map::new();
    };
    let mut proxies = Map::new();
    if !server.contains('=') {
        for scheme in ["http", "https"] {
            proxies.insert(scheme.to_owned(), json!(format!("http://{server}")));
        }
        return proxies;
    }
    for item in server.split(';') {
        if let Some((scheme, address)) = item.split_once('=') {
            if matches!(scheme, "http" | "https") && !address.is_empty() {
                proxies.insert(scheme.to_owned(), json!(format!("http://{address}")));
            }
        }
    }
    proxies
}

/// Whether `winreg` would hand back a truthy Python value for this data.
fn registry_truthy(kind: u32, bytes: &[u8]) -> bool {
    match kind {
        REG_SZ | REG_EXPAND_SZ | REG_MULTI_SZ => {
            bytes.len() >= 2 && (bytes[0] != 0 || bytes[1] != 0)
        }
        REG_DWORD | REG_DWORD_BIG_ENDIAN => bytes.iter().take(4).any(|&byte| byte != 0),
        REG_QWORD => bytes.iter().take(8).any(|&byte| byte != 0),
        _ => !bytes.is_empty(),
    }
}

/// A string value's text up to its first NUL, the way `winreg` reads it.
fn registry_text(kind: u32, bytes: &[u8]) -> Option<String> {
    if !matches!(kind, REG_SZ | REG_EXPAND_SZ) {
        return None;
    }
    let units: Vec<u16> = bytes
        .chunks_exact(2)
        .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
        .take_while(|&unit| unit != 0)
        .collect();
    Some(String::from_utf16_lossy(&units))
}

#[cfg(windows)]
fn registry_value(hive: Hive, name: &str) -> Option<(u32, Vec<u8>)> {
    use guard_runtime_windows_process::{read_registry_value, RegistryHive, RegistryValue};

    let hive = match hive {
        Hive::CurrentUser => RegistryHive::CurrentUser,
        Hive::LocalMachine => RegistryHive::LocalMachine,
    };
    match read_registry_value(hive, INTERNET_SETTINGS, name, MAX_REGISTRY_VALUE_BYTES) {
        RegistryValue::Data { kind, bytes } => Some((kind, bytes)),
        _ => None,
    }
}

#[cfg(not(windows))]
fn registry_value(_hive: Hive, _name: &str) -> Option<(u32, Vec<u8>)> {
    None
}

#[cfg(test)]
#[path = "system_proxies_tests.rs"]
mod tests;

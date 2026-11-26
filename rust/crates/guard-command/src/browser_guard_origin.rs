//! R-SELF: whether a browser target is Guard's own approval center.
//!
//! The daemon serves pending approvals on loopback. A browser driver that opens or acts on that
//! page could read or settle the agent's own approval, so every browser action on it is blocked.
//! The URL is parsed the way a browser parses it, so decimal, hex and short IPv4 forms, IPv6
//! loopback, upper case and a trailing dot all resolve to the same host.
//!
//! The daemon may answer on several ports, and every one of them counts:
//!
//! - the port `GUARD_DAEMON_PORT` names;
//! - the port its state file records;
//! - its default port;
//! - while no state file records a port, the candidate window it would pick from: a start port
//!   derived from the resolved Guard home and the next ports after it, the same derivation
//!   `daemon_lifecycle_ports.rs` uses.
//!
//! The Guard home is the one the runtime was started with (`--guard-home`, `HOL_GUARD_HOME`, or
//! the home it is installed in), so a non-default home is checked against its own state file.

use std::net::{Ipv4Addr, Ipv6Addr};
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

use sha2::{Digest, Sha256};
use url::{Host, Url};

use crate::pretool::{daemon_env_port, daemon_state_port, GUARD_DAEMON_DEFAULT_PORT};

/// The width of the daemon's fallback port range and of the window it tries from its start port.
const PORT_RANGE: u32 = 1000;
const CANDIDATE_WINDOW: u32 = 25;

static PROCESS_GUARD_HOME: OnceLock<PathBuf> = OnceLock::new();

/// Record the Guard home this process decides for. The first call wins.
pub fn set_process_guard_home(guard_home: PathBuf) {
    let _ = PROCESS_GUARD_HOME.set(guard_home);
}

/// Whether `target` points at a port Guard's daemon may answer on, on a loopback host, for the
/// process Guard home.
pub fn is_guard_origin(target: &str) -> bool {
    #[cfg(test)]
    if let Some(home) = tests::override_home() {
        return is_guard_origin_in(target, Some(&home), None);
    }
    is_guard_origin_in(target, process_guard_home().as_deref(), daemon_env_port())
}

/// [`is_guard_origin`] for an explicit Guard home and `GUARD_DAEMON_PORT` value.
pub fn is_guard_origin_in(target: &str, guard_home: Option<&Path>, env_port: Option<u16>) -> bool {
    match loopback_port(target) {
        Some((true, port)) => guard_daemon_ports(guard_home, env_port).contains(&port),
        _ => false,
    }
}

/// Every port the daemon for `guard_home` may answer on.
pub fn guard_daemon_ports(guard_home: Option<&Path>, env_port: Option<u16>) -> Vec<u16> {
    let mut ports = vec![GUARD_DAEMON_DEFAULT_PORT];
    ports.extend(env_port);
    match guard_home.and_then(daemon_state_port) {
        Some(recorded) => ports.push(recorded),
        None if env_port.is_none() => {
            ports.extend(guard_home.map(candidate_window).unwrap_or_default())
        }
        None => {}
    }
    ports.sort_unstable();
    ports.dedup();
    ports
}

/// The daemon's start port for `guard_home` and the window after it, wrapping in its range.
fn candidate_window(guard_home: &Path) -> Vec<u16> {
    let resolved = std::fs::canonicalize(guard_home).unwrap_or_else(|_| guard_home.to_path_buf());
    let text = resolved.to_string_lossy();
    let text = text.strip_prefix(r"\\?\").unwrap_or(&text);
    let digest = Sha256::digest(text.as_bytes());
    let offset = u32::from_be_bytes([digest[0], digest[1], digest[2], digest[3]]) % PORT_RANGE;
    (0..CANDIDATE_WINDOW)
        .filter_map(|step| {
            u16::try_from(u32::from(GUARD_DAEMON_DEFAULT_PORT) + (offset + step) % PORT_RANGE).ok()
        })
        .collect()
}

fn process_guard_home() -> Option<PathBuf> {
    if let Some(home) = PROCESS_GUARD_HOME.get() {
        return Some(home.clone());
    }
    if let Some(home) = std::env::var_os("HOL_GUARD_HOME").filter(|value| !value.is_empty()) {
        return Some(PathBuf::from(home));
    }
    std::env::var_os("HOME")
        .or_else(|| std::env::var_os("USERPROFILE"))
        .filter(|value| !value.is_empty())
        .map(|home| PathBuf::from(home).join(".hol-guard"))
}

fn loopback_port(target: &str) -> Option<(bool, u16)> {
    let url = Url::parse(target.trim()).ok()?;
    if !matches!(url.scheme(), "http" | "https" | "ws" | "wss") {
        return None;
    }
    let port = url.port_or_known_default()?;
    let loopback = match url.host()? {
        Host::Domain(domain) => loopback_name(domain),
        Host::Ipv4(address) => address.is_loopback() || address == Ipv4Addr::UNSPECIFIED,
        Host::Ipv6(address) => loopback_v6(address),
    };
    Some((loopback, port))
}

fn loopback_name(domain: &str) -> bool {
    let name = domain.trim_end_matches('.').to_ascii_lowercase();
    name == "localhost" || name.ends_with(".localhost")
}

fn loopback_v6(address: Ipv6Addr) -> bool {
    address.is_loopback()
        || address.is_unspecified()
        || address
            .to_ipv4_mapped()
            .is_some_and(|mapped| mapped.is_loopback() || mapped == Ipv4Addr::UNSPECIFIED)
}

#[cfg(test)]
#[path = "browser_guard_origin_tests.rs"]
pub(crate) mod tests;

//! R-SELF: whether a browser target is Guard's own approval center.
//!
//! The daemon serves pending approvals on loopback. A browser driver that opens or acts on that
//! page could read or settle the agent's own approval, so every browser action on it is blocked.
//! The URL is parsed the way a browser parses it, so decimal, hex and short IPv4 forms, IPv6
//! loopback, upper case and a trailing dot all resolve to the same host.

use std::net::{Ipv4Addr, Ipv6Addr};

use url::{Host, Url};

use crate::pretool::{known_daemon_port, GUARD_DAEMON_DEFAULT_PORT};

/// Whether `target` points at the port Guard's daemon answers on, on a loopback host. Without a
/// recorded or configured port, the daemon's default port counts. `home_dir` defaults to the
/// process home directory.
pub fn is_guard_origin(target: &str, home_dir: Option<&str>) -> bool {
    let Some((host_is_loopback, port)) = loopback_port(target) else {
        return false;
    };
    let process_home = std::env::var("HOME")
        .or_else(|_| std::env::var("USERPROFILE"))
        .ok();
    let home = home_dir.or(process_home.as_deref());
    let daemon = known_daemon_port(home).unwrap_or(GUARD_DAEMON_DEFAULT_PORT);
    host_is_loopback && port == daemon
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
mod tests;

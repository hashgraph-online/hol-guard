//! Loopback ports a command may reach on its own machine: the conventional
//! ports of local development servers, and ports an agent chose for a server
//! it started itself; never a port one of the local services in
//! [`LOCAL_SERVICE_PORTS`] holds, and never a port Guard's own daemon may
//! answer on.
//!
//! The daemon serves pending approvals on loopback, so a request to it from
//! an agent could read or settle its own approval. It listens on a port in
//! [`GUARD_DAEMON_PORTS`] by default, on `GUARD_DAEMON_PORT`, or on an
//! ephemeral port recorded in its state file. A port outside the dev-server
//! list, such as an ephemeral one, is never reachable here; a listed port in
//! the daemon's range is reachable only while the daemon's state file names
//! another port.

use std::path::{Path, PathBuf};

/// Ports that frameworks and static servers bind by default: web (`80`,
/// `443`, `8443`), Parcel (`1234`), Node, Next.js, Rails and Express
/// (`3000`-`3010`), Jekyll and Phoenix (`4000`), Vite preview (`4173`,
/// `4174`), Angular (`4200`), Astro (`4321`), Flask (`5000`), Vite
/// (`5173`-`5180`), Live Server (`5500`), Storybook (`6006`), Django and
/// `http.server` (`8000`-`8010`), alternate HTTP (`8080`, `8081`), ad hoc
/// static servers (`8765`) and Wrangler (`8787`).
const DEV_SERVER_PORTS: [(u16, u16); 17] = [
    (80, 80),
    (443, 443),
    (1234, 1234),
    (3000, 3010),
    (4000, 4000),
    (4173, 4174),
    (4200, 4200),
    (4321, 4321),
    (5000, 5000),
    (5173, 5180),
    (5500, 5500),
    (6006, 6006),
    (8000, 8010),
    (8080, 8081),
    (8443, 8443),
    (8765, 8765),
    (8787, 8787),
];

/// Loopback ports a request must never reach: container and cluster control
/// planes, service meshes, debuggers, Guard's own approval center, message
/// brokers, data stores that accept local clients without credentials, local
/// proxies that would carry traffic off this host, browser and device
/// automation drivers, remote desktops, and local model and notebook servers.
///
/// A port here answers a plain local request with credentials, stored data or
/// control of another process, so naming one is never the dev server an agent
/// just started.
pub(in crate::pretool) const LOCAL_SERVICE_PORTS: &[u16] = &[
    1080, 1086, 1087, 1433, 1521, 2019, 2049, 2181, 2375, 2376, 2379, 2380, 3128, 3306, 3389, 4001,
    4243, 4444, 4646, 4723, 4781, 5037, 5432, 5433, 5555, 5672, 5984, 6379, 6380, 6443, 6463, 7474,
    7687, 7890, 7891, 7897, 8001, 8086, 8118, 8123, 8200, 8384, 8500, 8888, 8889, 9000, 9001, 9042,
    9050, 9090, 9092, 9150, 9200, 9222, 9229, 9300, 9515, 10000, 10808, 10809, 11211, 11434, 15000,
    15672, 26257, 33060,
];

/// Services whose components bind a whole block of loopback ports: VNC and
/// X11 displays, the kubelet, and MongoDB.
const LOCAL_SERVICE_RANGES: &[std::ops::RangeInclusive<u16>] =
    &[5900..=5910, 6000..=6063, 10248..=10256, 27017..=27019];

/// Whether `port` belongs to one of those services.
pub(in crate::pretool) fn local_service_port(port: u16) -> bool {
    LOCAL_SERVICE_PORTS.contains(&port)
        || LOCAL_SERVICE_RANGES
            .iter()
            .any(|range| range.contains(&port))
}

/// The approval center's default port and the range it falls back through.
const GUARD_DAEMON_PORTS: std::ops::RangeInclusive<u16> = 4781..=5780;

const STATE_FILE: &str = "daemon-state.json";

/// Whether a loopback request to `port` reaches a development server rather
/// than another local service. `admin` lists ports that answer a plain
/// request with credentials or control, which stay excluded even when a
/// framework also uses them.
pub(in crate::pretool) fn dev_server_port(
    port: u16,
    admin: &[u16],
    home_dir: Option<&str>,
) -> bool {
    DEV_SERVER_PORTS
        .iter()
        .any(|(low, high)| (*low..=*high).contains(&port))
        && !admin.contains(&port)
        && !daemon_may_listen(port, home_dir)
}

/// Whether a server the agent started on a port of its own choosing, such as
/// `PORT=3147 npm start`, may answer on `port`: an unprivileged port below the
/// ephemeral ranges (Linux from 32768, macOS and Windows from 49152) that
/// none of the `admin` services holds, while the daemon's state file records
/// that Guard listens on another port. Without that record the daemon may sit
/// on any fixed port, so only the dev-server list stays reachable.
pub(in crate::pretool) fn chosen_server_port(
    port: u16,
    admin: &[u16],
    home_dir: Option<&str>,
) -> bool {
    (1024..32768).contains(&port)
        && !admin.contains(&port)
        && fixed_port() != Some(port)
        && guard_home(home_dir)
            .and_then(|home| state_port(&home))
            .is_some_and(|recorded| recorded != port)
}

fn fixed_port() -> Option<u16> {
    std::env::var("GUARD_DAEMON_PORT")
        .ok()
        .and_then(|value| value.trim().parse::<u16>().ok())
}

fn daemon_may_listen(port: u16, home_dir: Option<&str>) -> bool {
    if fixed_port() == Some(port) {
        return true;
    }
    match guard_home(home_dir).and_then(|home| state_port(&home)) {
        Some(recorded) => recorded == port,
        None => GUARD_DAEMON_PORTS.contains(&port),
    }
}

fn guard_home(home_dir: Option<&str>) -> Option<PathBuf> {
    match std::env::var_os("HOL_GUARD_HOME").filter(|value| !value.is_empty()) {
        Some(home) => Some(PathBuf::from(home)),
        None => home_dir.map(|home| Path::new(home).join(".hol-guard")),
    }
}

/// The port the daemon's state file records, or `None` when it is missing,
/// oversized or unreadable.
fn state_port(guard_home: &Path) -> Option<u16> {
    let path = guard_home.join(STATE_FILE);
    if std::fs::metadata(&path).ok()?.len() > 64 * 1024 {
        return None;
    }
    let state: serde_json::Value = serde_json::from_slice(&std::fs::read(path).ok()?).ok()?;
    u16::try_from(state.get("port")?.as_u64()?).ok()
}

#[cfg(test)]
#[path = "loopback_ports_tests.rs"]
mod tests;

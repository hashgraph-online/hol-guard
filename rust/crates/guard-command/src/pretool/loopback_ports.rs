//! Loopback ports a command may reach on its own machine: the conventional
//! ports of local development servers, never a port Guard's own daemon may
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

fn daemon_may_listen(port: u16, home_dir: Option<&str>) -> bool {
    if std::env::var("GUARD_DAEMON_PORT")
        .ok()
        .and_then(|value| value.trim().parse::<u16>().ok())
        == Some(port)
    {
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

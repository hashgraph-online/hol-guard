//! Stable codes for why `daemon-manage` returned no daemon URL, so callers
//! can name the cause (port conflict, missing runtime, still starting, ...)
//! instead of reporting an unknown failure.

use std::io::ErrorKind;
use std::net::{Ipv4Addr, SocketAddrV4, TcpListener};

const PORTS_IN_USE: &str =
    "Guard daemon could not start: every port it can use is held by another program.";

/// Message substrings, most specific first, and the code each one maps to.
const RUNTIME_CODES: [(&str, &str); 7] = [
    (PORTS_IN_USE, "port_conflict"),
    ("requires the native runtime", "native_runtime_unavailable"),
    (
        "launch configuration is invalid",
        "daemon_launch_config_invalid",
    ),
    ("start lock", "daemon_start_lock_unavailable"),
    ("could not be retired", "daemon_stale_generation"),
    ("process could not be started", "daemon_process_failed"),
    ("did not start", "daemon_start_failed"),
];

/// The code for a failure message. Every failure gets a named code;
/// `daemon_unavailable` covers the rest.
pub(super) fn code(timeout: bool, message: &str) -> &'static str {
    if timeout {
        return if message.starts_with("Guard daemon is still starting") {
            "daemon_still_starting"
        } else {
            "daemon_start_timeout"
        };
    }
    RUNTIME_CODES
        .iter()
        .find(|(needle, _)| message.contains(needle))
        .map_or("daemon_unavailable", |(_, code)| code)
}

/// The port-conflict message, naming the ports tried.
pub(super) fn ports_in_use_message(ports: &[i64]) -> String {
    let listed: Vec<String> = ports.iter().map(i64::to_string).collect();
    format!("{PORTS_IN_USE} Ports tried: {}.", listed.join(", "))
}

/// Whether another listener holds every candidate port on the loopback
/// address, which is why no launch could bind.
pub(super) fn all_ports_in_use(ports: &[i64]) -> bool {
    !ports.is_empty() && ports.iter().all(|port| port_in_use(*port))
}

fn port_in_use(port: i64) -> bool {
    let Some(port) = u16::try_from(port).ok().filter(|port| *port != 0) else {
        return false;
    };
    match TcpListener::bind(SocketAddrV4::new(Ipv4Addr::LOCALHOST, port)) {
        Ok(_) => false,
        Err(error) => {
            error.kind() == ErrorKind::AddrInUse
                || (cfg!(windows) && error.kind() == ErrorKind::PermissionDenied)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_known_failure_has_a_named_code() {
        for (timeout, message, want) in [
            (
                true,
                "Guard daemon is still starting; retry shortly.",
                "daemon_still_starting",
            ),
            (
                true,
                "Guard daemon start timed out.",
                "daemon_start_timeout",
            ),
            (
                false,
                "Guard daemon requires the native runtime.",
                "native_runtime_unavailable",
            ),
            (
                false,
                "Guard daemon launch configuration is invalid.",
                "daemon_launch_config_invalid",
            ),
            (
                false,
                "Guard daemon start lock could not be opened.",
                "daemon_start_lock_unavailable",
            ),
            (
                false,
                "Stale Guard daemon could not be retired safely.",
                "daemon_stale_generation",
            ),
            (
                false,
                "Guard daemon process could not be started.",
                "daemon_process_failed",
            ),
            (
                false,
                "Guard approval center did not start. Expected state file at x.",
                "daemon_start_failed",
            ),
            (
                false,
                "Guard daemon state could not be cleared safely.",
                "daemon_unavailable",
            ),
        ] {
            assert_eq!(code(timeout, message), want, "{message}");
        }
        assert_eq!(
            code(false, &ports_in_use_message(&[4781, 4782])),
            "port_conflict"
        );
    }

    #[test]
    fn a_held_port_is_a_conflict_and_a_free_one_is_not() {
        let held = TcpListener::bind(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0)).unwrap();
        let held_port = i64::from(held.local_addr().unwrap().port());
        assert!(all_ports_in_use(&[held_port]));
        let free_port = {
            let probe = TcpListener::bind(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0)).unwrap();
            i64::from(probe.local_addr().unwrap().port())
        };
        assert!(!all_ports_in_use(&[held_port, free_port]));
        assert!(!all_ports_in_use(&[]));
        assert!(!all_ports_in_use(&[0]));
    }
}

//! D10: routine browser actions on a loopback development origin settle with no card.
//!
//! A coding agent starts a dev server and checks the page. The shell side already relieves a
//! loopback read of a dev server (`pretool/curl_reads.rs`); the browser quiet set has the same
//! shape and the same exclusions. An action is quiet only when every one of these holds:
//!
//! - it is routine: navigation, inspection or interaction, and nothing else Guard flagged, so a
//!   sensitive surface, a shared profile, transfer or a privileged action is never quiet;
//! - its target URL is known, from its own arguments or the page the driver reports, and is an
//!   `http` or `https` URL on a loopback host;
//! - the port is one development servers bind by default, not one in
//!   [`LOCAL_ADMIN_PORTS`](crate::pretool::curl_reads::LOCAL_ADMIN_PORTS), and not one the
//!   server's launch arguments name for remote debugging;
//! - the target is not Guard's own approval center (R-SELF);
//! - the browser runs in an `isolated` or `dedicated` profile. `shared`, `remote-debugging` and
//!   an unknown profile are never quiet.
//!
//! The function decides from facts alone. It never grants, saves or answers anything, and it
//! never lowers a stricter action the user configured.

use guard_contracts::BrowserProfileModeV1;
use url::Url;

use crate::browser_guard_origin::{is_guard_origin, loopback_port};
use crate::pretool::conventional_dev_port;
use crate::pretool::curl_reads::LOCAL_ADMIN_PORTS;

/// The risk categories a quiet action may carry. Anything else Guard flagged keeps its review.
const ROUTINE: [&str; 3] = [
    "browser_navigation",
    "browser_inspection",
    "browser_interaction",
];

/// Launch flags whose value names a remote-debugging port or endpoint.
const DEBUGGING_FLAGS: [&str; 7] = [
    "--remote-debugging-port",
    "--cdp-endpoint",
    "--cdp-port",
    "--ws-endpoint",
    "--wsEndpoint",
    "--browser-url",
    "--browserUrl",
];

/// The facts the quiet set decides from.
pub(crate) struct LoopbackQuietFacts<'a> {
    pub categories: &'a [String],
    pub target: Option<&'a str>,
    pub profile: BrowserProfileModeV1,
    pub debugging_ports: &'a [u16],
}

/// Whether the action these facts describe is in the loopback development quiet set.
pub(crate) fn loopback_dev_quiet(facts: &LoopbackQuietFacts<'_>) -> bool {
    if !matches!(
        facts.profile,
        BrowserProfileModeV1::Isolated | BrowserProfileModeV1::Dedicated
    ) {
        return false;
    }
    if facts.categories.is_empty()
        || !facts
            .categories
            .iter()
            .all(|category| ROUTINE.contains(&category.as_str()))
    {
        return false;
    }
    let Some(target) = facts.target else {
        return false;
    };
    let web = Url::parse(target.trim()).is_ok_and(|url| matches!(url.scheme(), "http" | "https"));
    let Some((true, port)) = loopback_port(target).filter(|_| web) else {
        return false;
    };
    conventional_dev_port(port)
        && !LOCAL_ADMIN_PORTS.contains(&port)
        && !facts.debugging_ports.contains(&port)
        && !is_guard_origin(target)
}

/// The remote-debugging ports a server's launch arguments name, as `--flag=value` or
/// `--flag value`, where the value is a port or a URL with a port.
pub(crate) fn debugging_ports<'a>(arguments: impl Iterator<Item = &'a str>) -> Vec<u16> {
    let mut ports = Vec::new();
    let mut pending = false;
    for argument in arguments {
        let value = if pending {
            pending = false;
            Some(argument)
        } else {
            match argument.split_once('=') {
                Some((flag, value)) if DEBUGGING_FLAGS.contains(&flag) => Some(value),
                None if DEBUGGING_FLAGS.contains(&argument) => {
                    pending = true;
                    None
                }
                _ => None,
            }
        };
        ports.extend(value.and_then(port_of));
    }
    ports.sort_unstable();
    ports.dedup();
    ports
}

fn port_of(value: &str) -> Option<u16> {
    let value = value.trim();
    if let Ok(port) = value.parse::<u16>() {
        return Some(port);
    }
    Url::parse(value).ok()?.port_or_known_default()
}

#[cfg(test)]
#[path = "browser_loopback_quiet_tests.rs"]
mod tests;

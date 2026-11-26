//! D10: routine browser actions on a loopback development origin settle with no card.
//!
//! A coding agent starts a dev server and checks the page. The shell side already relieves a
//! loopback read of a dev server (`pretool/curl_reads.rs`); the browser quiet set has the same
//! shape and the same exclusions. An action is quiet only when every one of these holds:
//!
//! - it is routine: navigation, inspection or interaction, and nothing else Guard flagged, so a
//!   sensitive surface, a shared profile, transfer or a privileged action is never quiet;
//! - its target URL is known, from its own arguments or the page the driver reports, and is an
//!   `http` or `https` URL on a loopback host, with no user name or password and no
//!   secret-shaped path, query or fragment (the shell check's URL screen);
//! - the port is one development servers bind by default and not one in
//!   [`LOCAL_ADMIN_PORTS`](crate::pretool::curl_reads::LOCAL_ADMIN_PORTS);
//! - Guard's daemon cannot be on that port: not its own approval center (R-SELF), and, while no
//!   state file records the daemon's port, nowhere in its fallback range;
//! - the browser runs in an `isolated` or `dedicated` profile, and no launch argument names a
//!   remote-debugging or shared-profile flag beside it. `shared`, `remote-debugging` and an
//!   unknown profile are never quiet.
//!
//! The function decides from facts alone. It never grants, saves or answers anything, and it
//! never lowers a stricter action the user configured.

use guard_contracts::BrowserProfileModeV1;
use url::Url;

use crate::browser_guard_origin::{daemon_port_possible, loopback_port};
use crate::pretool::conventional_dev_port;
use crate::pretool::curl_reads::url_secrets::carries_secret;
use crate::pretool::curl_reads::LOCAL_ADMIN_PORTS;

/// The risk categories a quiet action may carry. Anything else Guard flagged keeps its review.
const ROUTINE: [&str; 3] = [
    "browser_navigation",
    "browser_inspection",
    "browser_interaction",
];

/// The facts the quiet set decides from.
pub(crate) struct LoopbackQuietFacts<'a> {
    pub categories: &'a [String],
    pub target: Option<&'a str>,
    pub profile: BrowserProfileModeV1,
    /// A launch argument names a remote-debugging or shared-profile flag.
    pub debugging_or_shared_launch: bool,
}

/// Whether the action these facts describe is in the loopback development quiet set.
pub(crate) fn loopback_dev_quiet(facts: &LoopbackQuietFacts<'_>) -> bool {
    if facts.debugging_or_shared_launch
        || !matches!(
            facts.profile,
            BrowserProfileModeV1::Isolated | BrowserProfileModeV1::Dedicated
        )
    {
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
    let Ok(url) = Url::parse(target.trim()) else {
        return false;
    };
    if !matches!(url.scheme(), "http" | "https")
        || !url.username().is_empty()
        || url.password().is_some()
        || carries_secret(&url)
    {
        return false;
    }
    let Some((true, port)) = loopback_port(target) else {
        return false;
    };
    conventional_dev_port(port) && !LOCAL_ADMIN_PORTS.contains(&port) && !daemon_port_possible(port)
}

#[cfg(test)]
#[path = "browser_loopback_quiet_tests.rs"]
mod tests;

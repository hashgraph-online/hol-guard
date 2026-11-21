//! A stale bounded bridge hands its hook to the runtime the home's resident
//! runs now, as `hook_bridge_successor` describes for every bridge.
//!
//! The harnesses this bridge serves, such as ZCode, read their hook commands
//! when a session starts. A session that outlives a Guard update keeps launching the
//! durable copy its hooks named then, which the resident never answers, so
//! every hook from it missed the resident and went to the daemon.

use std::path::Path;
use std::time::Instant;

use super::{BridgeConfig, Prepared, Route, BRIDGE_COMMAND};
use crate::codex_hook_bridge_direct::STATE_DIRECTORY;
use crate::hook_bridge_successor::{self, HandOff};

/// The route the newer bridge the home's resident runs gave the hook, when
/// this bridge is an older durable copy a long-lived session still
/// launches. `None` keeps the hook here; a newer bridge that ran but gave
/// no answer in time fails closed, as this bridge would past its deadline.
pub(super) fn successor_route(
    config: &BridgeConfig,
    prepared: &Prepared,
    python_argv: &[String],
    raw: &[u8],
    deadline: Instant,
) -> Option<Route> {
    let successor = hook_bridge_successor::successor(&config.guard_home.join(STATE_DIRECTORY))?;
    handed_off(&successor, prepared, python_argv, raw, deadline)
}

/// Run `successor`'s bridge on the hook with this bridge's own command.
/// `None` means it never started, so the hook is still this bridge's.
fn handed_off(
    successor: &Path,
    prepared: &Prepared,
    python_argv: &[String],
    raw: &[u8],
    deadline: Instant,
) -> Option<Route> {
    let arguments: Vec<String> = std::iter::once(BRIDGE_COMMAND.to_owned())
        .chain(python_argv.iter().cloned())
        .collect();
    let handed = hook_bridge_successor::hand_off(successor, &arguments, raw, deadline)?;
    Some(handed_off_route(prepared, handed))
}

/// What this bridge writes for the newer bridge's answer: its stdout and
/// exit code as they stand, since it rendered them for the same harness.
/// Its stderr already reached the harness. Output that is not UTF-8, or no
/// answer at all, fails closed.
fn handed_off_route(prepared: &Prepared, handed: HandOff) -> Route {
    match handed {
        HandOff::Answered(stdout, exit_code) => match String::from_utf8(stdout) {
            Ok(stdout) => Route::Respond {
                stdout,
                stderr: String::new(),
                exit_code,
            },
            Err(_) => prepared.failed(),
        },
        HandOff::Failed => prepared.failed(),
    }
}

#[cfg(test)]
#[path = "bounded_hook_bridge_successor_tests.rs"]
mod tests;

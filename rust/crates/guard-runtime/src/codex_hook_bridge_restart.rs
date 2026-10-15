//! How the native Codex bridge gets a daemon answer: the live resident
//! first, then the authenticated daemon, then, when the daemon is down, did
//! not answer or reported a process failure, the daemon again after the
//! install-time `start_command` ran. Python's bridge started the daemon the
//! same way and waited for it with `await_started_daemon`.
//!
//! An overloaded daemon is never restarted. After the start the bridge asks
//! again only while the daemon looks not yet up before the hook was sent,
//! so the hook reaches the daemon at most once more. Anything else is
//! `None`, which the bridge answers with the fail-closed answer.

use std::path::Path;
use std::time::{Duration, Instant};

use super::{clear_start_failure, guard_home, route_response, BridgeConfig, Prepared, Route};
use crate::claude_hook_bridge_http::remaining;
use crate::codex_hook_bridge_direct::{direct_answer, CODEX};
use crate::codex_hook_bridge_transport::{authenticated_codex_hook_response, HookFailure};
use crate::hook_bridge_daemon_start::{await_daemon, start_daemon, Attempt, TRANSPORT_FAILURE};

const OVERLOAD: &str = "overload";

/// One authenticated exchange capped at `cap`, inside `deadline`.
fn ask_daemon(
    config: &BridgeConfig,
    prepared: &Prepared,
    deadline: Instant,
    cap: Duration,
) -> Result<String, HookFailure> {
    let rpc_deadline = Instant::now() + remaining(deadline).min(cap);
    authenticated_codex_hook_response(
        Path::new(&config.state_path),
        &config.query,
        &prepared.data,
        rpc_deadline,
    )
}

/// The route for the answer to `prepared`, or `None` to fail it closed.
pub(super) fn daemon_route(
    config: &BridgeConfig,
    prepared: &Prepared,
    deadline: Instant,
    cap: Duration,
) -> Option<Route> {
    let rpc_deadline = Instant::now() + remaining(deadline).min(cap);
    let direct = guard_home(&config.state_path).and_then(|home| {
        direct_answer(
            CODEX,
            &home,
            &config.query,
            &prepared.event_name,
            &prepared.data,
            rpc_deadline,
        )
    });
    let first = match direct {
        // A resident answer never touched the daemon, so its start-failure
        // marker stays as it was.
        Some(text) => match route_response(&text, &prepared.event_name) {
            Route::Restart => TRANSPORT_FAILURE,
            route => return Some(route),
        },
        None => match ask_daemon(config, prepared, deadline, cap) {
            Ok(text) => match route_response(&text, &prepared.event_name) {
                Route::Restart => TRANSPORT_FAILURE,
                route => return Some(answered(config, route)),
            },
            Err(failure) => failure.error.failure_kind(),
        },
    };
    if first == OVERLOAD {
        return None;
    }
    restarted_route(config, prepared, deadline, cap, first)
}

/// A daemon answered: its start-failure marker is cleared, as Python does.
fn answered(config: &BridgeConfig, route: Route) -> Route {
    clear_start_failure(&config.state_path);
    route
}

/// Start the daemon with `failure_kind` and ask it once more while it comes
/// up. A second process failure is not restarted again.
fn restarted_route(
    config: &BridgeConfig,
    prepared: &Prepared,
    deadline: Instant,
    cap: Duration,
    failure_kind: &str,
) -> Option<Route> {
    if !start_daemon(&config.start_command, failure_kind, deadline) {
        return None;
    }
    let text = await_daemon(deadline, || {
        match ask_daemon(config, prepared, deadline, cap) {
            Ok(text) => Attempt::Settled(Some(text)),
            Err(failure) if failure.not_up => Attempt::NotUp,
            Err(_) => Attempt::Settled(None),
        }
    })??;
    match route_response(&text, &prepared.event_name) {
        Route::Restart => None,
        route => Some(answered(config, route)),
    }
}

//! Live-daemon verification for the native Claude SessionStart lane.
//!
//! A read-only port of the gates `_live_guard_daemon_identity` in
//! `daemon/manager.py` applies before it trusts a running daemon, run in
//! process: the HMAC-authenticated `daemon-state.json`, a daemon of this
//! package version on the IPv4 loopback, the private auth token bound to it
//! (`identity_binding`), the state and pid gate (`live_state_gate`), a
//! signed identity challenge for `SessionStart` on the daemon's own
//! listener, a current `/healthz` (`healthz_current`) on that same
//! listener, and an unchanged daemon generation afterwards. It never mints
//! the token, never writes daemon state and never starts a daemon.
//!
//! The version gate is stricter than `daemon_state_matches_current_runtime`:
//! a daemon left running from another package version is never accepted,
//! so the Python hook restarts it. Python also compares the daemon's
//! runtime tree signature with the installed source. This lane does not, so
//! the one remaining gap is a same-version tree change: a developer
//! editable install where only Python files changed keeps the running
//! daemon until the next session start that hands off to Python.

use std::collections::BTreeMap;
use std::path::Path;
use std::time::Instant;

use guard_contracts::{
    DaemonHealthzCurrentQueryV1, DaemonIdentityBindingQueryV1, DaemonPayloadQueryV1,
    DaemonPlatformV1,
};
use serde_json::{json, Map, Value};

use crate::claude_hook_bridge_auth::{
    authenticated_state, private_file_text, verify_challenge_response, AuthenticatedState,
};
use crate::claude_hook_bridge_http::{LoopbackConnection, MAX_DAEMON_RESPONSE_BYTES};
use crate::claude_hook_bridge_transport::{new_nonce, request_identity_challenge};
use crate::daemon_lifecycle_facts::Ctx;
use crate::daemon_lifecycle_state::{healthz_current, identity_binding, live_state_gate};

const AUTH_TOKEN_FILE: &str = "daemon-auth-token";
const HEALTH_LABEL: &str = "daemon health check exceeded the session start deadline";
const LOOPBACK: &str = "127.0.0.1";

/// The live daemon's loopback URL, `http://127.0.0.1:{port}`.
pub(crate) type DaemonUrl = String;

/// `_native_fields`: the named fields, `null` when absent.
fn fields(state: &AuthenticatedState, names: &[&str]) -> Value {
    let mut payload = Map::new();
    for name in names {
        let value = state.payload.get(*name).cloned().unwrap_or(Value::Null);
        payload.insert((*name).to_owned(), value);
    }
    Value::Object(payload)
}

#[cfg(unix)]
fn pid_running(pid: i64) -> bool {
    let Ok(pid) = i32::try_from(pid) else {
        return false;
    };
    pid > 0 && nix::sys::signal::kill(nix::unistd::Pid::from_raw(pid), None).is_ok()
}

/// `_guard_daemon_pid_is_running` on Windows: anything but a proven exit
/// counts as running, so a probe error never passes the live gate as stopped.
#[cfg(windows)]
fn pid_running(pid: i64) -> bool {
    windows_liveness(pid).is_some_and(|liveness| liveness != Some(false))
}

#[cfg(not(any(unix, windows)))]
fn pid_running(_pid: i64) -> bool {
    false
}

/// `windows_process_liveness` for a positive pid; `None` when the pid is out
/// of range.
#[cfg(windows)]
fn windows_liveness(pid: i64) -> Option<Option<bool>> {
    let pid = u32::try_from(pid).ok().filter(|pid| *pid > 0)?;
    Some(guard_runtime_windows_process::process_liveness(pid))
}

#[cfg(windows)]
const DAEMON_PLATFORM: DaemonPlatformV1 = DaemonPlatformV1::Nt;
#[cfg(not(windows))]
const DAEMON_PLATFORM: DaemonPlatformV1 = DaemonPlatformV1::Posix;

/// `identity_binding` with the token read from the private token file.
fn token_bound(state_path: &Path, state: &AuthenticatedState) -> Result<(), String> {
    let parent = state_path.parent().unwrap_or_else(|| Path::new("."));
    let token = private_file_text(&parent.join(AUTH_TOKEN_FILE), "daemon auth token")?;
    let query = DaemonIdentityBindingQueryV1 {
        payload: fields(state, &["auth_token_id", "state_id"]),
        auth_token: Some(token),
    };
    if identity_binding(&query)["bound"] == json!(true) {
        Ok(())
    } else {
        Err("daemon auth token does not bind the daemon state".to_owned())
    }
}

/// `live_state_gate` with the pid fact gathered here; the validated port.
fn live_port(state: &AuthenticatedState) -> Result<u16, String> {
    let mut facts = BTreeMap::new();
    if let Some(pid) = state.payload.get("pid").and_then(Value::as_i64) {
        facts.insert(format!("pid_running:{pid}"), Value::Bool(pid_running(pid)));
    }
    let ctx = Ctx::new(DAEMON_PLATFORM, &facts);
    let query = DaemonPayloadQueryV1 {
        payload: fields(state, &["compatibility_version", "port", "pid"]),
    };
    let gate = live_state_gate(&ctx, &query);
    let gate = ctx.finish(gate);
    if gate["ok"] != json!(true) {
        return Err("daemon state is not live".to_owned());
    }
    gate["port"]
        .as_u64()
        .and_then(|port| u16::try_from(port).ok())
        .filter(|port| *port != 0 && *port == state.port())
        .ok_or_else(|| "daemon port is invalid".to_owned())
}

/// A daemon of this package version, listening on the IPv4 loopback the
/// installed hook URL names, so the challenge and the health check reach
/// the listener the hook entries point at.
fn current_daemon(state: &AuthenticatedState) -> Result<(), String> {
    if state.payload.get("package_version").and_then(Value::as_str) != Some(crate::PACKAGE_VERSION)
    {
        return Err("daemon runs another package version".to_owned());
    }
    if state.text("host") != LOOPBACK {
        return Err("daemon host is not the IPv4 loopback".to_owned());
    }
    Ok(())
}

/// A signed identity challenge for `SessionStart` on the daemon listener.
fn challenge_verified(
    state: &AuthenticatedState,
    port: u16,
    hook_event: &str,
    deadline: Instant,
) -> Result<(), String> {
    let mut connection = LoopbackConnection::new(LOOPBACK, port);
    let nonce = new_nonce().map_err(|error| error.to_string())?;
    let challenge = request_identity_challenge(
        &mut connection,
        state.text("state_id"),
        &nonce,
        hook_event,
        deadline,
    )
    .map_err(|error| error.to_string())?;
    verify_challenge_response(&challenge, state, &nonce, hook_event).map(|_| ())
}

/// `GET /healthz` is 200 and `healthz_current` accepts its body.
fn health_current(port: u16, deadline: Instant) -> Result<(), String> {
    let mut connection = LoopbackConnection::new(LOOPBACK, port);
    let head = connection
        .get("/healthz", &[("Connection", "close")], deadline)
        .map_err(|error| error.to_string())?;
    let body = connection
        .read_body(&head, deadline, HEALTH_LABEL, HEALTH_LABEL)
        .map_err(|error| error.to_string())?;
    if head.status != 200 || body.len() > MAX_DAEMON_RESPONSE_BYTES {
        return Err("daemon health check failed".to_owned());
    }
    let raw_payload =
        String::from_utf8(body).map_err(|_| "daemon health is not UTF-8".to_owned())?;
    let verdict = healthz_current(&DaemonHealthzCurrentQueryV1 { raw_payload });
    if verdict["result"] == json!(true) {
        Ok(())
    } else {
        Err("daemon health is not current".to_owned())
    }
}

/// The verified live daemon's URL, or why it could not be verified.
pub(crate) fn verified_daemon_url(
    state_path: &Path,
    hook_event: &str,
    deadline: Instant,
) -> Result<DaemonUrl, String> {
    let state = authenticated_state(state_path)?;
    current_daemon(&state)?;
    token_bound(state_path, &state)?;
    let port = live_port(&state)?;
    challenge_verified(&state, port, hook_event, deadline)?;
    health_current(port, deadline)?;
    let current = authenticated_state(state_path)?;
    if !current.same_generation(&state) {
        return Err("daemon state changed during verification".to_owned());
    }
    Ok(format!("http://{LOOPBACK}:{port}"))
}

/// The loopback URL of a daemon that is provably down: its authenticated
/// state names a daemon of this package version on `127.0.0.1` whose pid no
/// longer runs, as after a reboot or a crash. A running pid, even one that
/// does not answer, is not down, so the caller hands it to Python.
pub(crate) fn stopped_daemon_url(state_path: &Path) -> Result<DaemonUrl, String> {
    let state = authenticated_state(state_path)?;
    current_daemon(&state)?;
    let pid = state
        .payload
        .get("pid")
        .and_then(Value::as_i64)
        .filter(|pid| *pid > 0)
        .ok_or("daemon state names no pid")?;
    if pid_running(pid) {
        return Err("daemon process is still running".to_owned());
    }
    match state.port() {
        0 => Err("daemon port is invalid".to_owned()),
        port => Ok(format!("http://{LOOPBACK}:{port}")),
    }
}

#[cfg(all(test, unix))]
#[path = "claude_session_start_live_tests.rs"]
pub(crate) mod tests;

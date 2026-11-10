//! Live daemon checks for recovery: the authenticated identity probe a
//! dashboard relies on, and the dashboard update reservation.

use std::fs::{self, File};
use std::io::Read;
use std::path::Path;
use std::time::{Duration, Instant, SystemTime};

use serde_json::{json, Map, Value};

use super::host;
use crate::daemon_policy_authority::{load_authenticated_daemon_identity, loopback_json};
use crate::native_review_link::{now_micros, session_token};

const COMPATIBILITY_VERSION: i64 = 2;
const DASHBOARD_PROTOCOL_VERSIONS: [&str; 2] = ["1.1", "1.0"];
const UPDATE_LOCK_FILE: &str = "dashboard-update.lock";
const UPDATE_LOCK_MAX_BYTES: u64 = 64 * 1024;
const UPDATE_STALE: Duration = Duration::from_secs(30 * 60);

/// `probe_live_guard_daemon_identity`: health details prove the process
/// and home; a dashboard session proves the normal surface accepts one.
pub(super) fn probe_live(home: &Path, timeout: f64) -> (Option<Map<String, Value>>, &'static str) {
    if !timeout.is_finite() || timeout <= 0.0 {
        return (None, "service_unresponsive");
    }
    let deadline = Instant::now() + Duration::from_secs_f64(timeout);
    let remaining = || deadline.saturating_duration_since(Instant::now());
    let Some((state, auth)) = load_authenticated_daemon_identity(home) else {
        return (None, "identity_unverified");
    };
    let Some(port) = daemon_port(&state) else {
        return (None, "identity_unverified");
    };
    if !details_match(
        health_details(port, &auth, remaining()).as_ref(),
        &state,
        home,
    ) {
        return (None, "service_unresponsive");
    }
    let mut identity = state.clone();
    identity.insert(
        "daemon_url".into(),
        json!(format!("http://127.0.0.1:{port}")),
    );
    if remaining().is_zero() || !dashboard_session(port, &auth, deadline) {
        return (Some(identity), "session_invalid");
    }
    let Some((refreshed, refreshed_auth)) = load_authenticated_daemon_identity(home) else {
        return (Some(identity), "identity_unverified");
    };
    if !same_generation(&state, &refreshed) {
        return (Some(identity), "identity_unverified");
    }
    let Some(refreshed_port) = daemon_port(&refreshed) else {
        return (Some(identity), "identity_unverified");
    };
    if !details_match(
        health_details(refreshed_port, &refreshed_auth, remaining()).as_ref(),
        &refreshed,
        home,
    ) {
        return (Some(identity), "identity_unverified");
    }
    (Some(identity), "healthy")
}

/// The loopback port of a current-compatibility state, or `None`.
fn daemon_port(state: &Map<String, Value>) -> Option<u16> {
    let text = |key: &str| state.get(key).and_then(Value::as_str);
    if text("host") != Some("127.0.0.1")
        || text("package_version").is_none()
        || text("runtime_fingerprint").is_none_or(str::is_empty)
        || state.get("compatibility_version").and_then(Value::as_i64) != Some(COMPATIBILITY_VERSION)
        || state
            .get("pid")
            .and_then(Value::as_i64)
            .is_none_or(|pid| pid <= 0)
    {
        return None;
    }
    let port = state.get("port").and_then(Value::as_i64)?;
    u16::try_from(port).ok().filter(|port| *port > 0)
}

fn health_details(port: u16, auth: &str, timeout: Duration) -> Option<Map<String, Value>> {
    let header = format!("X-Guard-{}", "Token");
    loopback_json(
        "GET",
        port,
        "/v1/healthz/details",
        &[(header.as_str(), auth)],
        None,
        timeout,
    )
}

/// `_health_details_match`.
fn details_match(
    details: Option<&Map<String, Value>>,
    state: &Map<String, Value>,
    home: &Path,
) -> bool {
    let Some(details) = details else {
        return false;
    };
    let Some(details_home) = details.get("guard_home").and_then(Value::as_str) else {
        return false;
    };
    details.get("ok") == Some(&Value::Bool(true))
        && !details_home.is_empty()
        && [
            "package_version",
            "compatibility_version",
            "runtime_fingerprint",
            "pid",
        ]
        .iter()
        .all(|field| details.get(*field) == state.get(*field))
        && host::resolve_lenient(Path::new(details_home)) == host::resolve_lenient(home)
}

/// `_state_identity_matches(..., require_markers=True)`.
fn same_generation(expected: &Map<String, Value>, current: &Map<String, Value>) -> bool {
    let marker = |state: &Map<String, Value>, keys: [&str; 2]| {
        keys.iter()
            .find_map(|key| {
                state
                    .get(*key)
                    .and_then(Value::as_str)
                    .filter(|text| !text.trim().is_empty())
            })
            .map(str::to_owned)
    };
    let homes = |state: &Map<String, Value>| {
        state
            .get("guard_home")
            .and_then(Value::as_str)
            .map(|raw| host::resolve_lenient(Path::new(raw)))
    };
    if homes(expected).is_none() || homes(expected) != homes(current) {
        return false;
    }
    if [
        "package_version",
        "compatibility_version",
        "pid",
        "host",
        "port",
    ]
    .iter()
    .any(|key| expected.get(*key) != current.get(*key))
    {
        return false;
    }
    [
        ["runtime_fingerprint", "runtime"],
        ["generation", "state_id"],
        ["user", "uid"],
        ["start_marker", "process_start_marker"],
    ]
    .into_iter()
    .all(|keys| {
        let left = marker(expected, keys);
        left.is_some() && left == marker(current, keys)
    })
}

/// The browser's local handoff: seed a dashboard session, initialize the
/// surface, then read capabilities with only the refreshed session.
fn dashboard_session(port: u16, auth: &str, deadline: Instant) -> bool {
    let header = "X-Guard-Dashboard-Session";
    let field = format!("dashboard_session_{}", "token");
    let Some(seed) = now_micros().and_then(|now| session_token(auth, "dashboard", now)) else {
        return false;
    };
    let body = json!({
        "client_name": "guard-dashboard-web",
        "surface": "dashboard",
        "supported_protocol_versions": DASHBOARD_PROTOCOL_VERSIONS,
    });
    let Some(initialized) = loopback_json(
        "POST",
        port,
        "/v1/initialize",
        &[
            ("Content-Type", "application/json"),
            (header, seed.as_str()),
        ],
        Some(&body),
        deadline.saturating_duration_since(Instant::now()),
    ) else {
        return false;
    };
    let Some(refreshed) = initialized
        .get(&field)
        .and_then(Value::as_str)
        .filter(|text| !text.is_empty())
    else {
        return false;
    };
    loopback_json(
        "GET",
        port,
        "/v1/capabilities",
        &[(header, refreshed)],
        None,
        deadline.saturating_duration_since(Instant::now()),
    )
    .is_some()
}

/// `dashboard_update_in_progress`: a live update reservation holds recovery
/// off; a stale or orphaned one is reclaimed.
pub(super) fn update_busy(home: &Path) -> bool {
    let path = home.join(UPDATE_LOCK_FILE);
    let Some((bytes, modified)) = read_update_lock(&path) else {
        return false;
    };
    let fresh = modified
        .and_then(|time| SystemTime::now().duration_since(time).ok())
        .is_none_or(|age| age < UPDATE_STALE);
    let payload = serde_json::from_slice::<Value>(&bytes)
        .ok()
        .and_then(|value| value.as_object().cloned());
    let runner_dead = |payload: &Map<String, Value>| {
        payload
            .get("runner_pid")
            .filter(|value| !value.is_boolean())
            .and_then(Value::as_i64)
            .is_some_and(|pid| pid > 0 && !host::pid_is_running(pid))
    };
    let keep = match payload {
        None => fresh,
        Some(payload) => fresh && !runner_dead(&payload),
    };
    keep || !reclaim(&path, &bytes)
}

fn read_update_lock(path: &Path) -> Option<(Vec<u8>, Option<SystemTime>)> {
    let metadata = fs::symlink_metadata(path).ok()?;
    if !metadata.is_file() {
        return Some((Vec::new(), metadata.modified().ok()));
    }
    let mut bytes = Vec::new();
    File::open(path)
        .ok()?
        .take(UPDATE_LOCK_MAX_BYTES + 1)
        .read_to_end(&mut bytes)
        .ok()?;
    Some((bytes, metadata.modified().ok()))
}

/// Remove the reservation only while it still holds the bytes judged stale.
fn reclaim(path: &Path, bytes: &[u8]) -> bool {
    match read_update_lock(path) {
        None => true,
        Some((current, _)) if current == bytes => fs::remove_file(path).is_ok(),
        Some(_) => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn update_reservation_holds_only_while_fresh_and_owned() {
        let home = tempfile::tempdir().expect("home");
        assert!(!update_busy(home.path()));
        let lock = home.path().join(UPDATE_LOCK_FILE);
        fs::write(&lock, b"not json").expect("write");
        assert!(
            update_busy(home.path()),
            "a fresh unreadable reservation holds"
        );
        fs::write(&lock, br#"{"runner_pid": 2147483646}"#).expect("write");
        assert!(
            !update_busy(home.path()),
            "a dead runner's reservation is reclaimed"
        );
        assert!(!lock.exists());
    }

    #[test]
    fn a_state_off_loopback_or_compatibility_has_no_port() {
        let state = |host: &str, compat: i64| {
            json!({
                "host": host, "port": 4100, "pid": 7, "compatibility_version": compat,
                "package_version": "1", "runtime_fingerprint": "abc",
            })
            .as_object()
            .cloned()
            .expect("map")
        };
        assert_eq!(daemon_port(&state("127.0.0.1", 2)), Some(4100));
        assert_eq!(daemon_port(&state("0.0.0.0", 2)), None);
        assert_eq!(daemon_port(&state("127.0.0.1", 1)), None);
    }
}

//! `POST /v1/update/reconnect/challenge` and `/verify`: the dashboard proves
//! it reached this daemon, and not another one on the same port, before it
//! trusts the reconnect. See `server_control_cloud_connect.py`.

use std::net::{IpAddr, SocketAddr};
use std::path::Path;
use std::sync::{Mutex, PoisonError};
use std::time::{SystemTime, UNIX_EPOCH};

use serde_json::{json, Map, Value};

const PROTOCOL_VERSION: i64 = 1;
const MAX_CONSUMED: usize = 256;

/// The challenge identities already accepted, oldest first, with the time
/// each stops mattering. Held across the replay check and the consume.
static CONSUMED: Mutex<Vec<(String, i64)>> = Mutex::new(Vec::new());

/// What this daemon published about itself.
pub(super) struct Daemon<'a> {
    pub(super) guard_home: &'a str,
    pub(super) local: SocketAddr,
    pub(super) pid: u32,
    pub(super) state_id: Option<&'a str>,
}

impl Daemon<'_> {
    /// The origin the dashboard reaches this daemon on.
    fn origin(&self) -> Option<String> {
        match self.local.ip() {
            IpAddr::V4(ip) if ip.is_loopback() && ip.octets() == [127, 0, 0, 1] => {
                Some(format!("http://127.0.0.1:{}", self.local.port()))
            }
            IpAddr::V6(ip) if ip.is_loopback() => {
                Some(format!("http://[::1]:{}", self.local.port()))
            }
            _ => None,
        }
    }

    /// The `state_id` of the published state, when that state is still this
    /// daemon's own.
    fn current_state_id(&self) -> Option<String> {
        let published = self.state_id?;
        let home = Path::new(self.guard_home);
        let state = crate::daemon_policy_authority::load_authenticated_daemon_state(home)?;
        let resolved = std::fs::canonicalize(home).ok()?;
        let current = state.get("guard_home").and_then(Value::as_str) == resolved.to_str()
            && state.get("host").and_then(Value::as_str) == Some(&self.local.ip().to_string())
            && state.get("port").and_then(Value::as_u64) == Some(u64::from(self.local.port()))
            && state.get("pid").and_then(Value::as_u64) == Some(u64::from(self.pid))
            && state.get("state_id").and_then(Value::as_str) == Some(published);
        current.then(|| published.to_owned())
    }
}

fn candidate_failure(reason_code: &str) -> (u16, Value) {
    (
        404,
        json!({"error": "daemon_candidate_unavailable", "reason_code": reason_code}),
    )
}

fn strict_origin(value: Option<&Value>) -> Option<String> {
    let text = value?.as_str()?;
    let normalized = super::super::super::auth::normalize_origin(text);
    crate::daemon_route_session::strict_loopback_origin(text.trim(), normalized.as_deref())
}

fn protocol_matches(payload: &Map<String, Value>) -> bool {
    // Python compares with `!=`, so `1.0` and `true` also equal 1.
    match payload.get("protocol_version") {
        Some(Value::Number(number)) => number.as_f64() == Some(PROTOCOL_VERSION as f64),
        Some(Value::Bool(flag)) => *flag,
        _ => false,
    }
}

fn reconnect(args: Value, guard_home: &str) -> Option<Map<String, Value>> {
    match crate::dashboard_reconnect::dispatch(&args, guard_home) {
        Ok(Value::Object(answer)) => Some(answer),
        _ => None,
    }
}

pub(super) fn challenge(payload: &Map<String, Value>, daemon: &Daemon<'_>) -> (u16, Value) {
    if !protocol_matches(payload) {
        return candidate_failure("dashboard_reconnect_protocol_mismatch");
    }
    let candidate = strict_origin(payload.get("candidate_origin"));
    let Some(origin) = daemon
        .origin()
        .filter(|origin| candidate.as_ref() == Some(origin))
    else {
        return candidate_failure("dashboard_reconnect_origin_mismatch");
    };
    let Some(state_id) = daemon.current_state_id() else {
        return candidate_failure("dashboard_reconnect_state_unavailable");
    };
    let args = json!({
        "op": "challenge",
        "reconnect_id": payload.get("reconnect_id"),
        "client_nonce": payload.get("client_nonce"),
        "candidate_origin": origin,
        "state_id": state_id,
    });
    let Some(answer) = reconnect(args, daemon.guard_home) else {
        return candidate_failure("dashboard_reconnect_identity_unavailable");
    };
    match answer.get("challenge") {
        Some(challenge @ Value::Object(_)) => (200, challenge.clone()),
        _ => candidate_failure(
            answer
                .get("reason")
                .and_then(Value::as_str)
                .unwrap_or("dashboard_reconnect_identity_unavailable"),
        ),
    }
}

fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|elapsed| i64::try_from(elapsed.as_millis()).unwrap_or(i64::MAX))
        .unwrap_or(0)
}

pub(super) fn verify(payload: &Map<String, Value>, daemon: &Daemon<'_>) -> (u16, Value) {
    if !protocol_matches(payload) {
        return candidate_failure("dashboard_reconnect_protocol_mismatch");
    }
    let Some(Value::Object(raw)) = payload.get("challenge") else {
        return candidate_failure("dashboard_reconnect_malformed_proof");
    };
    let candidate = strict_origin(raw.get("candidate_origin"));
    let origin = daemon
        .origin()
        .filter(|origin| candidate.as_ref() == Some(origin));
    let state_id = daemon.current_state_id();
    let (Some(origin), Some(state_id)) = (origin, state_id) else {
        return candidate_failure("dashboard_reconnect_proof_context_mismatch");
    };
    let identity = match reconnect(
        json!({"op": "challenge_identity", "challenge": raw}),
        daemon.guard_home,
    ) {
        None => return candidate_failure("dashboard_reconnect_identity_unavailable"),
        Some(answer) => match answer.get("identity").and_then(Value::as_str) {
            Some(identity) => identity.to_owned(),
            None => return candidate_failure("dashboard_reconnect_malformed_proof"),
        },
    };
    let now = now_ms();
    let mut consumed = CONSUMED.lock().unwrap_or_else(PoisonError::into_inner);
    consumed.retain(|(_, expires_at_ms)| *expires_at_ms >= now);
    if consumed.iter().any(|(seen, _)| *seen == identity) {
        return candidate_failure("dashboard_reconnect_proof_replayed");
    }
    let verdict = reconnect(
        json!({
            "op": "consume",
            "challenge": raw,
            "proof": payload.get("proof"),
            "expected_candidate_origin": origin,
            "expected_state_id": state_id,
        }),
        daemon.guard_home,
    );
    let reason = verdict
        .as_ref()
        .and_then(|verdict| verdict.get("reason")?.as_str().map(str::to_owned))
        .unwrap_or_else(|| "dashboard_reconnect_identity_unavailable".to_owned());
    if verdict.and_then(|verdict| verdict.get("verified")?.as_bool()) != Some(true) {
        return candidate_failure(&reason);
    }
    let expires_at_ms = match raw.get("expires_at_ms") {
        Some(Value::Number(number)) => number.as_i64().unwrap_or(now),
        _ => now,
    };
    consumed.push((identity, expires_at_ms));
    let excess = consumed.len().saturating_sub(MAX_CONSUMED);
    consumed.drain(..excess);
    drop(consumed);
    (200, json!({"verified": true, "reason_code": reason}))
}

#[cfg(all(test, unix))]
#[path = "daemon_edge_reconnect_tests.rs"]
mod tests;

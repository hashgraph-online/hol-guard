//! Daemon port selection and start-timeout arithmetic.

use guard_contracts::{
    DaemonAdoptablePortsQueryV1, DaemonCandidatePortsQueryV1, DaemonConfiguredPortQueryV1,
    DaemonStartTimeoutsQueryV1,
};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use crate::daemon_lifecycle_facts::Ctx;
use crate::daemon_lifecycle_text::{norm_path, py_strip, python_int};

const DEFAULT_PORT: i64 = 4781;
const PORT_RANGE: i64 = 1000;
const CANDIDATE_WINDOW: i64 = 25;
const START_TIMEOUT_SECONDS: f64 = 15.0;
const POST_UPDATE_START_TIMEOUT_SECONDS: f64 = 30.0;
const START_TIMEOUT_MARGIN_SECONDS: f64 = 5.0;

/// `_stable_port_for_guard_home`: a port derived from the resolved home.
fn stable_port(ctx: &Ctx, guard_home: &str) -> i64 {
    let resolved = ctx
        .resolve(guard_home)
        .unwrap_or_else(|| norm_path(guard_home));
    let digest = Sha256::digest(resolved.as_bytes());
    let prefix = u32::from_be_bytes([digest[0], digest[1], digest[2], digest[3]]);
    DEFAULT_PORT + i64::from(prefix) % PORT_RANGE
}

fn explicit_env(env_port: Option<&String>) -> Option<&str> {
    env_port
        .map(String::as_str)
        .filter(|raw| !py_strip(raw).is_empty())
}

/// `_configured_port`: the environment port when valid, else the stable one.
fn configured_port(ctx: &Ctx, env_port: Option<&String>, guard_home: &str) -> i64 {
    match explicit_env(env_port).and_then(python_int) {
        Some(port) if port > 0 => port,
        _ => stable_port(ctx, guard_home),
    }
}

pub(crate) fn configured_port_result(ctx: &Ctx, query: &DaemonConfiguredPortQueryV1) -> Value {
    json!({"port": configured_port(ctx, query.env_port.as_ref(), &query.guard_home)})
}

/// `_prepend_preferred_port`: a positive preferred port leads, duplicates drop.
fn prepend_preferred(ports: Vec<i64>, preferred: Option<i64>) -> Vec<i64> {
    let Some(preferred) = preferred.filter(|port| *port > 0) else {
        return ports;
    };
    let mut ordered = vec![preferred];
    for port in ports {
        if !ordered.contains(&port) {
            ordered.push(port);
        }
    }
    ordered
}

pub(crate) fn candidate_ports(ctx: &Ctx, query: &DaemonCandidatePortsQueryV1) -> Value {
    let configured = configured_port(ctx, query.env_port.as_ref(), &query.guard_home);
    if explicit_env(query.env_port.as_ref()).is_some() {
        return json!({"ports": prepend_preferred(vec![configured], query.preferred_port)});
    }
    let offset = configured - DEFAULT_PORT;
    let ports = (0..CANDIDATE_WINDOW.min(PORT_RANGE))
        .map(|step| DEFAULT_PORT + (offset + step).rem_euclid(PORT_RANGE))
        .collect();
    json!({"ports": prepend_preferred(ports, query.preferred_port)})
}

/// `_adoptable_guard_daemon_ports`: state port, configured port, running ports.
pub(crate) fn adoptable_ports(ctx: &Ctx, query: &DaemonAdoptablePortsQueryV1) -> Value {
    let mut preferred: Vec<i64> = Vec::new();
    if let Some(port) = query.state_port.as_i64().filter(|port| *port > 0) {
        preferred.push(port);
    }
    let configured = configured_port(ctx, query.env_port.as_ref(), &query.guard_home);
    if configured > 0 {
        preferred.push(configured);
    }
    preferred.extend(query.running_ports.iter().copied());
    let mut ordered: Vec<i64> = Vec::new();
    for port in preferred {
        if !ordered.contains(&port) {
            ordered.push(port);
        }
    }
    json!({"ports": ordered})
}

pub(crate) fn start_timeouts(query: &DaemonStartTimeoutsQueryV1) -> Value {
    let base = if query.desktop {
        POST_UPDATE_START_TIMEOUT_SECONDS
    } else {
        START_TIMEOUT_SECONDS
    };
    let floor = query.worker_ready_floor + START_TIMEOUT_MARGIN_SECONDS;
    json!({
        "default": base.max(floor),
        "post_update": POST_UPDATE_START_TIMEOUT_SECONDS.max(floor),
    })
}

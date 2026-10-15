//! Reservation claims, recovery-owner liveness and start-progress gates.

use crate::approval_gate_state::constant_time_eq;
use guard_contracts::{
    DaemonClaimQueryV1, DaemonEphemeralInactiveQueryV1, DaemonOwnerStateQueryV1,
    DaemonStartProgressQueryV1,
};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use crate::daemon_lifecycle_facts::{as_int, Ctx};

const RESERVATION_SECONDS: f64 = 30.0;
const EPHEMERAL_STALE_SECONDS: f64 = 30.0;
const POST_UPDATE_START_TIMEOUT_SECONDS: f64 = 30.0;
const START_TIMEOUT_MARGIN_SECONDS: f64 = 5.0;

/// A reservation whose `created_at` is a number younger than the window.
fn reservation_is_fresh(existing: &Value, now: f64) -> bool {
    let created_at = match existing
        .as_object()
        .and_then(|object| object.get("created_at"))
    {
        Some(Value::Bool(flag)) => Some(f64::from(u8::from(*flag))),
        Some(Value::Number(number)) => number.as_f64(),
        _ => None,
    };
    created_at.is_some_and(|created| {
        let age = now - created;
        (0.0..RESERVATION_SECONDS).contains(&age)
    })
}

pub(crate) fn wake_claim(query: &DaemonClaimQueryV1) -> Value {
    json!({"claim": !reservation_is_fresh(&query.existing, query.now)})
}

pub(crate) fn recovery_claim(ctx: &Ctx, query: &DaemonClaimQueryV1) -> Value {
    let owner = owner_state(ctx, &query.existing);
    let held = match owner {
        Some(true) => true,
        None => reservation_is_fresh(&query.existing, query.now),
        Some(false) => false,
    };
    json!({"claim": !held})
}

/// `secrets.compare_digest` on two strings; non-ASCII text cannot be compared.
fn texts_equal(left: &str, right: &str) -> bool {
    left.is_ascii() && right.is_ascii() && constant_time_eq(left.as_bytes(), right.as_bytes())
}

fn non_empty<'a>(reservation: &'a Value, key: &str) -> Option<&'a str> {
    reservation
        .get(key)
        .and_then(Value::as_str)
        .filter(|text| !text.is_empty())
}

/// `_guard_daemon_recovery_owner_state`: whether the claimed worker is alive;
/// `None` when that cannot be proven either way.
fn owner_state(ctx: &Ctx, reservation: &Value) -> Option<bool> {
    let pid = reservation
        .as_object()?
        .get("pid")
        .and_then(as_int)
        .filter(|pid| *pid > 0)?;
    if !ctx.boolean("pid_running", pid) {
        return Some(false);
    }
    if let Some(expected) = non_empty(reservation, "process_command_digest") {
        let command = ctx.fact(format!("cmd:{pid}"))?.as_str()?;
        let actual = hex::encode(Sha256::digest(command.as_bytes()));
        if !texts_equal(&actual, expected) {
            return Some(false);
        }
    }
    if let Some(expected) = non_empty(reservation, "process_start_marker") {
        let actual = ctx.fact(format!("start_token:{pid}"))?.as_str()?;
        if !texts_equal(actual, expected) {
            return Some(false);
        }
    }
    if !ctx.nt {
        return Some(true);
    }
    if let Some(expected) = reservation.get("process_creation_time").and_then(as_int) {
        let actual = ctx.fact(format!("win_ctime:{pid}")).and_then(as_int);
        if actual != Some(expected) {
            return Some(false);
        }
    }
    let liveness = ctx.fact(format!("win_live:{pid}")).and_then(Value::as_bool);
    Some(liveness != Some(false))
}

pub(crate) fn recovery_owner_state(ctx: &Ctx, query: &DaemonOwnerStateQueryV1) -> Value {
    json!({"state": owner_state(ctx, &query.reservation)})
}

/// `_guard_daemon_start_progress_is_live`.
pub(crate) fn start_progress_live(ctx: &Ctx, query: &DaemonStartProgressQueryV1) -> Value {
    json!({"live": progress_is_live(ctx, query)})
}

fn progress_is_live(ctx: &Ctx, query: &DaemonStartProgressQueryV1) -> bool {
    let record = &query.record;
    let Some(pid) = record.get("pid").and_then(as_int).filter(|pid| *pid > 0) else {
        return false;
    };
    let Some(token) = non_empty(record, "process_start_token") else {
        return false;
    };
    let Some(recorded_at_ns) = record.get("recorded_at_ns").and_then(as_int) else {
        return false;
    };
    let timeout = POST_UPDATE_START_TIMEOUT_SECONDS
        .max(query.worker_ready_floor + START_TIMEOUT_MARGIN_SECONDS);
    let limit_ns = (timeout * 1_000_000_000.0) as i64;
    let age_ns = query.now_ns.saturating_sub(recorded_at_ns);
    if age_ns < 0 || age_ns >= limit_ns {
        return false;
    }
    if !ctx.boolean("pid_running", pid) {
        return false;
    }
    let actual = ctx
        .fact(format!("start_token:{pid}"))
        .and_then(Value::as_str);
    if actual != Some(token) {
        return false;
    }
    ctx.boolean("matches_command", pid)
}

/// `_ephemeral_guard_home_is_inactive`.
pub(crate) fn ephemeral_inactive(ctx: &Ctx, query: &DaemonEphemeralInactiveQueryV1) -> Value {
    let stale_by_fallback = query.fallback_age_seconds >= EPHEMERAL_STALE_SECONDS;
    if let Some(state) = query.state.as_object() {
        let pid = state.get("pid").and_then(as_int).filter(|pid| *pid > 0);
        let Some(pid) = pid else {
            return json!({"inactive": stale_by_fallback});
        };
        if !ctx.boolean("pid_running", pid) || !ctx.boolean("matches_command", pid) {
            return json!({"inactive": stale_by_fallback});
        }
    }
    let heartbeat = ctx.fact("heartbeat_age".to_owned()).and_then(Value::as_f64);
    let inactive = heartbeat.map_or(stale_by_fallback, |age| age >= EPHEMERAL_STALE_SECONDS);
    json!({"inactive": inactive})
}

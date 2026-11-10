//! `GET /v1/healthz/details`: the daemon's identity and diagnostics, read by
//! the CLI and the launcher to adopt a running daemon and by support to see
//! how it is doing.
//!
//! The identity fields (`pid`, `guard_home`, `package_version`,
//! `runtime_fingerprint`, `source_root`) come from the state this process
//! published, so a caller that adopts the daemon compares the same values it
//! read from that state. The counts and the persistence health come from the
//! store; the evidence writer's counters from the writer this process hosts.

use std::path::Path;

use serde_json::{json, Map, Value};

use super::{network, NativeReads, ReadConfig};

/// `GUARD_DAEMON_COMPATIBILITY_VERSION`.
const COMPATIBILITY_VERSION: i64 = 2;
/// The review lanes the scheduler reports latency for.
const HOOK_LANES: [&str; 3] = ["decision", "content-security", "evidence"];
/// `_MAX_CONCURRENT_RUNTIME_HOOKS` and the scheduler's queue bounds.
const HOOK_ACTIVE_LIMIT: u64 = 32;
const HOOK_QUEUED_LIMIT: u64 = 128;
const HOOK_RETAINED_BYTES_LIMIT: u64 = 32 * 1024 * 1024;
/// `_MAX_CONCURRENT_DAEMON_*`.
const REQUEST_LIMIT: u64 = 32;
const CONNECTION_LIMIT: u64 = 128;
const CONTROL_LIMIT: u64 = 8;
const CRITICAL_LIMIT: u64 = 8;
/// `REPAIR_SELF_CHECK_KEY`, which the worker host publishes its last run to.
const REPAIR_SELF_CHECK_KEY: &str = "daemon_repair_self_check_status";

/// The details body, or `None` when a store read fails and the request is
/// left to the daemon's refusal path.
pub(super) fn respond(config: &ReadConfig, reads: &NativeReads) -> Option<Value> {
    let state = reads.published_state()?;
    let store = |method: &str, args: Value| reads.store_call(config, method, args);
    let receipts = store("count_receipts", json!({}))?;
    let pending = store(
        "count_approval_requests",
        json!({ "status": "pending", "exclude_watch_only": false }),
    )?;
    let tables = store("list_table_names", json!({}))?;
    let activity = store("get_command_activity_persistence_health", json!({}))?;
    let repair_self_check = store(
        "get_sync_payload",
        json!({ "state_key": REPAIR_SELF_CHECK_KEY }),
    )
    .filter(Value::is_object)
    .unwrap_or(Value::Null);
    let guard_home = Path::new(&config.guard_home);
    let writer = crate::hook_evidence_writer_op::health_stats(guard_home);
    let field = |name: &str| state.get(name).cloned().unwrap_or(Value::Null);
    let hook_capacity = hook_capacity();
    let hook_load = hook_load(&writer, &hook_capacity);
    let uptime = (reads.uptime().as_secs_f64() * 10.0).round() / 10.0;
    Some(json!({
        "ok": true,
        "receipts": receipts,
        "approvals": pending,
        "pending_approvals": pending,
        "hook_evidence_writer": writer,
        "sqlite_profile": sqlite_profile(),
        "sqlite_migration_gate": sqlite_migration_gate(),
        "quarantined_store": crate::storage_retention::quarantine_summary(guard_home),
        "onefile_extraction": Value::Null,
        "repair_self_check": repair_self_check,
        "uptime_seconds": uptime,
        "pid": reads.daemon_pid(),
        "tables": tables,
        "compatibility_version": COMPATIBILITY_VERSION,
        "package_version": field("package_version"),
        "runtime_fingerprint": field("runtime_fingerprint"),
        // Adoption needs the install root to reject a previous generation
        // still running from the same, now upgraded, install.
        "source_root": field("source_root"),
        "guard_home": field("guard_home"),
        "command_activity_evidence": command_activity_evidence(&activity),
        "network_protection": network::supervisor_health(),
        "hook_capacity": hook_capacity,
        "hook_load": hook_load,
        "request_capacity": {
            "active": reads.active_connections().saturating_sub(1),
            "connection_limit": CONNECTION_LIMIT,
            "control_limit": CONTROL_LIMIT,
            "critical_limit": CRITICAL_LIMIT,
            "limit": REQUEST_LIMIT,
            "rejected": 0,
        },
    }))
}

/// The persisted command-activity counters as the details report them.
fn command_activity_evidence(health: &Value) -> Value {
    let count = |name: &str| health.get(name).and_then(Value::as_i64).unwrap_or(0);
    let text = |name: &str| health.get(name).cloned().unwrap_or(Value::Null);
    let errors = count("persistence_error_count");
    json!({
        "state": if errors != 0 { "degraded" } else { "healthy" },
        "dropped_event_count": count("dropped_event_count"),
        "persistence_error_count": errors,
        "last_error_code": text("last_error_code"),
        "last_error_at": text("last_error_at"),
        "schema_version": text("schema_version"),
    })
}

/// The hook scheduler's bounds. Hooks are reviewed as they arrive, so nothing
/// is queued, expired or rejected for capacity.
fn hook_capacity() -> Value {
    let lanes = || {
        Value::Object(
            HOOK_LANES
                .iter()
                .map(|lane| ((*lane).to_owned(), json!(0.0)))
                .collect::<Map<String, Value>>(),
        )
    };
    json!({
        "active": 0,
        "limit": HOOK_ACTIVE_LIMIT,
        "queued": 0,
        "queued_limit": HOOK_QUEUED_LIMIT,
        "retained_bytes": 0,
        "retained_bytes_limit": HOOK_RETAINED_BYTES_LIMIT,
        "per_harness_active": {},
        "per_harness_queued": {},
        "per_harness_rejected": {},
        "rejected": 0,
        "expired": 0,
        "cancelled": 0,
        "retries": 0,
        "completed": 0,
        "oldest_queued_ms": 0.0,
        "queue_wait_by_lane_p95_ms": lanes(),
        "service_time_by_lane_p95_ms": lanes(),
        "queue_wait_by_lane_p99_ms": lanes(),
        "service_time_by_lane_p99_ms": lanes(),
        "rejection_reasons": {},
    })
}

/// The load the details summarize, in the daemon's order of severity.
fn hook_load(writer: &Value, capacity: &Value) -> Value {
    let positive =
        |value: &Value, name: &str| value.get(name).and_then(Value::as_u64).unwrap_or(0) > 0;
    let (state, detail) = if positive(writer, "failures") && positive(writer, "queued") {
        (
            "store-contended",
            "Evidence persistence is retrying outside the security decision path.",
        )
    } else if positive(capacity, "expired") || positive(capacity, "rejected") {
        (
            "saturated",
            "Secure review capacity was exhausted; recovery is automatic as load falls.",
        )
    } else if positive(capacity, "queued") {
        ("backlogged", "Queued reviews are draining automatically.")
    } else {
        ("healthy", "Review capacity is available.")
    };
    json!({ "state": state, "detail": detail })
}

/// `SQLiteProfiler().snapshot()` for a daemon that keeps no Python store
/// connections to profile.
fn sqlite_profile() -> Value {
    let timings = || json!({ "p50": 0.0, "p95": 0.0, "p99": 0.0, "max": 0.0 });
    json!({
        "connects": 0,
        "transactions": 0,
        "commits": 0,
        "busy_locked": 0,
        "busy_locked_percent": 0.0,
        "connect_ms": timings(),
        "transaction_ms": timings(),
        "commit_ms": timings(),
    })
}

/// `migration_gate_report()` over that profile: no end-to-end latency was
/// measured, so the store-wait gate is not evaluated.
fn sqlite_migration_gate() -> Value {
    json!({
        "store_p95_percent": null,
        "busy_locked_percent": 0.0,
        "store_wait_gate_tripped": null,
        "busy_locked_gate_tripped": false,
        "conclusion": "insufficient_end_to_end_profile",
    })
}

#[cfg(test)]
#[path = "daemon_edge_health_details_tests.rs"]
mod tests;

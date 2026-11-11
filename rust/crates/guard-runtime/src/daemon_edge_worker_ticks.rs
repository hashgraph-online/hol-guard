//! The background passes the daemon runs itself rather than as Guard
//! library calls: the runtime heartbeat, the idle-shutdown hold and storage
//! maintenance, which also rotates `daemon.log`. Each answers what its
//! `workers/ticks.py` call did.

use std::time::{SystemTime, UNIX_EPOCH};

use serde_json::{json, Value};

use super::super::super::reads::{NativeReads, ReadConfig};
use crate::policy_bundle_time::micros_to_utc_isoformat;

const MICROS_PER_DAY: i64 = 86_400_000_000;
/// Command-activity aggregates are kept for this many calendar months.
const AGGREGATE_MONTHS: i64 = 13;
const ACTIVITY_BATCH_SIZE: i64 = 1_000;
const STORAGE_BATCH_SIZE: i64 = 500;
const UPLOADED_CLOUD_EVENT_LIMIT: i64 = 10_000;
const UPLOADED_CLOUD_EVENT_RETAIN_DAYS: i64 = 7;
/// Maintenance gives way to any request holding the store.
const STORAGE_BUSY_MS: u64 = 25;
const HOUSEKEEPING_BUSY_MS: u64 = 1;

/// Runs `call` natively when the daemon owns it: `None` for a call that
/// still goes to the Guard library, otherwise the pass's answer.
pub(super) fn native(
    reads: &NativeReads,
    config: &ReadConfig,
    call: &str,
    args: &Value,
) -> Option<Option<Value>> {
    let answer = match call {
        "worker.runtime_heartbeat" => heartbeat(reads, config, args),
        "worker.idle_holds" => Some(json!({"ok": true, "hold": idle_holds(reads, config)})),
        "worker.maintain_activity" => Some(json!({"ok": maintain(reads, config)})),
        _ => return None,
    };
    Some(answer)
}

fn now_micros() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_micros() as i64)
}

fn isoformat(micros: i64) -> Option<String> {
    micros_to_utc_isoformat(micros, "+00:00")
}

/// Records that the daemon at `host:port` is alive.
fn heartbeat(reads: &NativeReads, config: &ReadConfig, args: &Value) -> Option<Value> {
    let text = |key: &str| args.get(key).and_then(Value::as_str);
    let record = json!({
        "session_id": text("session_id")?,
        "daemon_host": text("host")?,
        "daemon_port": args.get("port").and_then(Value::as_u64)?,
        "started_at": text("started_at")?,
        "last_heartbeat_at": isoformat(now_micros())?,
    });
    reads
        .store_write(config, "upsert_runtime_state", record)
        .ok()
        .map(|_| json!({"ok": true}))
}

/// Whether durable work keeps an idle daemon alive: a pending review or a
/// review event still queued for Guard Cloud. A store that cannot be read
/// holds nothing; the rows stay durable either way.
pub(super) fn idle_holds(reads: &NativeReads, config: &ReadConfig) -> bool {
    let pending = reads
        .store_write(
            config,
            "count_approval_requests",
            json!({"status": "pending", "exclude_watch_only": false}),
        )
        .ok()
        .and_then(|total| total.as_i64())
        .is_some_and(|total| total > 0);
    if pending {
        return true;
    }
    let Some(now) = isoformat(now_micros()) else {
        return false;
    };
    reads
        .store_write(config, "review_event_outbox_status", json!({"now": now}))
        .ok()
        .and_then(|status| status.get("depth").and_then(Value::as_i64))
        .is_some_and(|depth| depth > 0)
}

/// One storage-maintenance pass: a command-activity batch, then one batch
/// across the evidence tables. `true` once storage work is complete.
pub(super) fn maintain(reads: &NativeReads, config: &ReadConfig) -> bool {
    let Ok((retain_days, receipt_limit, event_limit)) =
        crate::guard_config_load::evidence_retention(config.guard_home())
    else {
        return false;
    };
    let now = now_micros();
    crate::storage_retention::daemon_log::rotate(config.guard_home(), now);
    let Some(args) = activity_args(now, retain_days) else {
        return false;
    };
    if reads
        .store_write(config, "maintain_command_activity", args)
        .is_err()
    {
        if let Some(occurred_at) = isoformat(now) {
            let _ = reads.store_write(
                config,
                "record_command_activity_persistence_failure",
                json!({"error_code": "maintenance_failed", "occurred_at": occurred_at}),
            );
        }
    }
    let Some(args) = storage_args(now_micros(), retain_days, receipt_limit, event_limit) else {
        return false;
    };
    let completed = reads
        .store_within(config, "maintain_storage", args, STORAGE_BUSY_MS)
        .ok()
        .and_then(|result| result.get("completed").and_then(Value::as_bool))
        .unwrap_or(false);
    if completed {
        // Maintenance never delays or fails an enforcement request.
        let _ = reads.store_within(
            config,
            "run_storage_housekeeping",
            json!({}),
            HOUSEKEEPING_BUSY_MS,
        );
        crate::storage_retention::sweep_after_maintenance(config.guard_home());
    }
    completed
}

/// `maintain_command_activity`'s instants and calendar boundaries for `now`.
pub(super) fn activity_args(now: i64, retain_days: i64) -> Option<Value> {
    let instant = isoformat(now)?;
    let today = instant.get(..10)?.to_owned();
    Some(json!({
        "now": instant,
        "today": today,
        "detail_cutoff": isoformat(now.checked_sub(retain_days.checked_mul(MICROS_PER_DAY)?)?)?,
        "aggregate_cutoff": aggregate_cutoff(&today)?,
        "batch_size": ACTIVITY_BATCH_SIZE,
    }))
}

/// The first day of the oldest month whose command-activity aggregates are
/// kept, for `today` as `YYYY-MM-DD`.
pub(super) fn aggregate_cutoff(today: &str) -> Option<String> {
    let year: i64 = today.get(..4)?.parse().ok()?;
    let month: i64 = today.get(5..7)?.parse().ok()?;
    let index = year * 12 + month - 1 - (AGGREGATE_MONTHS - 1);
    Some(format!("{:04}-{:02}-01", index / 12, index % 12 + 1))
}

pub(super) fn storage_args(
    now: i64,
    retain_days: i64,
    receipt_limit: i64,
    event_limit: i64,
) -> Option<Value> {
    let days = |count: i64| isoformat(now.checked_sub(count.checked_mul(MICROS_PER_DAY)?)?);
    Some(json!({
        "now": isoformat(now)?,
        "cutoff": days(retain_days)?,
        "cloud_cutoff": days(UPLOADED_CLOUD_EVENT_RETAIN_DAYS)?,
        "batch_size": STORAGE_BATCH_SIZE,
        "receipt_detail_limit": receipt_limit,
        "guard_event_limit": event_limit,
        "uploaded_cloud_event_limit": UPLOADED_CLOUD_EVENT_LIMIT,
    }))
}

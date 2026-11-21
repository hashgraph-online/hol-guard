//! The background passes the daemon runs itself rather than as Guard
//! library calls: the runtime heartbeat, the idle-shutdown hold and storage
//! maintenance, which also rotates `daemon.log` and retires leftover Guard
//! processes (`orphaned_worker_reap`), and the hourly sweep of leaked
//! one-file extraction folders. Each answers what its `workers/ticks.py`
//! call did.

use std::sync::Mutex;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

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
/// The longest a maintenance pass spends listing and stopping leftovers.
const REAP_BUDGET: std::time::Duration = std::time::Duration::from_secs(3);
/// Leftovers are retired at most this often. The maintenance job retries
/// every few seconds while storage work is unfinished, and each retry must
/// not list every process again.
const REAP_INTERVAL: std::time::Duration = std::time::Duration::from_secs(60 * 60);
/// One-file sweep limits, as `onefile_extraction.py` sets them: a marked
/// folder must be ten minutes old, an unmarked one two hours, and one pass
/// deletes at most 250 unmarked folders in two minutes.
const ONEFILE_MIN_AGE_SECONDS: f64 = 600.0;
const ONEFILE_UNMARKED_MIN_AGE_SECONDS: f64 = 7_200.0;
const ONEFILE_MAX_UNMARKED_RECLAIMS: u64 = 250;
const ONEFILE_UNMARKED_BUDGET_SECONDS: f64 = 120.0;
/// When this daemon last retired leftovers.
static LAST_REAP: Mutex<Option<Instant>> = Mutex::new(None);

/// Whether a reap that last ran at `last` is due again at `now`.
fn reap_due(last: Option<Instant>, now: Instant) -> bool {
    last.is_none_or(|last| now.saturating_duration_since(last) >= REAP_INTERVAL)
}

/// Retire leftovers when the last reap is an hour old or there was none.
fn reap_when_due() {
    let now = Instant::now();
    {
        let Ok(mut last) = LAST_REAP.lock() else {
            return;
        };
        if !reap_due(*last, now) {
            return;
        }
        *last = Some(now);
    }
    let _ = crate::orphaned_worker_reap::reap_from_daemon(std::process::id(), REAP_BUDGET);
}

/// Sends the weekly plugin install report when counts are on and the week
/// has not been sent. Off, not due and failed sends all wait for the next
/// tick; the scheduler only needs to know whether the pass ran cleanly.
fn plugin_telemetry(config: &ReadConfig) -> Value {
    let Some(home) = config.user_home.as_deref() else {
        return json!({"ok": false});
    };
    let sent = crate::plugin_telemetry_weekly::send_if_due(
        &crate::plugin_telemetry_host::LiveHol,
        config.guard_home(),
        std::path::Path::new(home),
        &crate::plugin_telemetry_weekly::current_week(),
    );
    json!({"ok": sent.is_ok()})
}

/// Reclaims the `_MEI*` folders hard-killed one-file Guard launches left in
/// the temp folder. Folders still in use, the library process's own among
/// them, keep a live owner or show up in the open-files scan and stay.
fn onefile_reclaim() -> Value {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0.0, |elapsed| elapsed.as_secs_f64());
    let swept = sweep_onefile(&std::env::temp_dir(), now);
    json!({"ok": swept.is_ok()})
}

/// One sweep of `temp_root` at `now` (Unix seconds); the sweep's report.
fn sweep_onefile(temp_root: &std::path::Path, now: f64) -> Result<Value, String> {
    let request = json!({
        "schema": "onefile-extraction-reclaim.v1",
        "temp_root": temp_root.to_string_lossy(),
        "current_meipass": Value::Null,
        "now": now,
        "min_age_seconds": ONEFILE_MIN_AGE_SECONDS,
        "unmarked_min_age_seconds": ONEFILE_UNMARKED_MIN_AGE_SECONDS,
        "max_unmarked_reclaims": ONEFILE_MAX_UNMARKED_RECLAIMS,
        "unmarked_time_budget_seconds": ONEFILE_UNMARKED_BUDGET_SECONDS,
        "scan_open_paths": true,
        "dry_run": false,
    });
    let answer = crate::onefile_extraction_reclaim::run_command(request.to_string().as_bytes())?;
    serde_json::from_slice(&answer)
        .map_err(|_| "onefile_extraction_reclaim_answer_invalid".to_owned())
}

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
        "worker.plugin_telemetry" => Some(plugin_telemetry(config)),
        "worker.onefile_reclaim" => Some(onefile_reclaim()),
        "worker.bundle_refresh" => Some(crate::cloud_bundle_sync::bundle_refresh(
            &crate::cloud_bundle_sync::BundleStore::new(
                config.guard_home(),
                config.store_path(),
                None,
            ),
        )),
        _ => return None,
    };
    Some(answer)
}

/// The Guard Cloud workspace queued review events sync to, or `None` while
/// the device has no healthy OAuth sign-in to sync with.
fn cloud_workspace(config: &ReadConfig) -> Option<String> {
    let store = crate::package_authority_op::ResidentSupplyChainStore::new(
        config.store_path(),
        config.guard_home(),
    );
    guard_command::local_supply_chain::SupplyChainStore::get_cloud_sync_profile(&store)?
        .get("workspace_id")
        .and_then(Value::as_str)
        .map(str::to_owned)
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
/// review event still queued for the bound Guard Cloud workspace. Events for
/// a workspace no usable profile names never drain, so they hold nothing. A
/// store that cannot be read holds nothing; the rows stay durable either way.
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
    // Queued events stay durable in guard.db, so a device without a usable
    // sync profile does not pin the daemon alive.
    let Some(workspace_id) = cloud_workspace(config) else {
        return false;
    };
    let Some(now) = isoformat(now_micros()) else {
        return false;
    };
    reads
        .store_write(
            config,
            "review_event_outbox_status",
            json!({"now": now, "workspace_id": workspace_id}),
        )
        .ok()
        .and_then(|status| status.get("depth").and_then(Value::as_i64))
        .is_some_and(|depth| depth > 0)
}

/// One storage-maintenance pass: a command-activity batch, then one batch
/// across the evidence tables. `true` once storage work is complete.
pub(super) fn maintain(reads: &NativeReads, config: &ReadConfig) -> bool {
    let now = now_micros();
    // The log rotates whatever the evidence settings say.
    crate::storage_retention::daemon_log::rotate(config.guard_home(), now);
    // Leftover workers, daemons of deleted homes and host-less relays of a
    // removed runtime are retired once an hour from the daemon, not only
    // when a launcher asks for background maintenance.
    reap_when_due();
    let Ok((retain_days, receipt_limit, event_limit)) =
        crate::guard_config_load::evidence_retention(config.guard_home())
    else {
        return false;
    };
    let Some(args) = activity_args(now, retain_days) else {
        return false;
    };
    // A command-activity backlog keeps the pass on its short retry, as an
    // unfinished storage batch does.
    let activity = reads.store_write(config, "maintain_command_activity", args);
    // A failing pass keeps its hourly interval rather than retrying hot.
    let activity_done = match &activity {
        Ok(result) => result.get(1).and_then(Value::as_bool).unwrap_or(true),
        Err(_) => true,
    };
    if activity.is_err() {
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
    completed && activity_done
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

#[cfg(test)]
mod reap_gate_tests {
    use super::*;

    #[test]
    fn the_daemon_reaps_at_most_once_an_hour() {
        let start = Instant::now();
        assert!(reap_due(None, start));
        assert!(!reap_due(Some(start), start));
        // A storage retry five seconds later does not reap again.
        assert!(!reap_due(
            Some(start),
            start + std::time::Duration::from_secs(5)
        ));
        assert!(!reap_due(
            Some(start),
            start + REAP_INTERVAL - std::time::Duration::from_secs(1)
        ));
        assert!(reap_due(Some(start), start + REAP_INTERVAL));
    }
}

#[cfg(all(test, unix))]
mod onefile_tests {
    use super::sweep_onefile;

    /// The pid of a child that has already exited.
    fn dead_pid() -> u32 {
        let mut child = std::process::Command::new("true").spawn().expect("spawn");
        let pid = child.id();
        child.wait().expect("wait");
        pid
    }

    #[test]
    fn the_daemon_sweep_removes_a_dead_launch_and_keeps_the_rest() {
        let root = tempfile::tempdir().expect("temp root");
        let temp_root = std::fs::canonicalize(root.path()).expect("canonical");
        let leaked = temp_root.join("_MEIdead01");
        std::fs::create_dir_all(leaked.join("codex_plugin_scanner")).expect("leaked");
        let pid = dead_pid();
        std::fs::write(
            leaked.join(".hol-guard-extraction-owner.json"),
            serde_json::json!({
                "schema": "guard.onefile-extraction-owner.v1",
                "pid": pid,
                "parent_pid": pid,
            })
            .to_string(),
        )
        .expect("marker");
        let other = temp_root.join("not-an-extraction");
        std::fs::create_dir_all(&other).expect("other");
        // Far enough ahead that every folder is past both age floors.
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock")
            .as_secs_f64()
            + 86_400.0;
        let report = sweep_onefile(&temp_root, now).expect("sweep");
        assert_eq!(report["reclaimed_count"], 1);
        assert!(!leaked.exists());
        assert!(other.exists());
    }
}

#[cfg(test)]
mod cloud_workspace_tests {
    use super::super::super::super::reads::HANDSHAKE_SCHEMA;
    use super::*;

    #[test]
    fn a_device_without_a_sign_in_names_no_workspace() {
        let home = tempfile::tempdir().unwrap();
        let guard_home = home.path().to_string_lossy().into_owned();
        let handshake = json!({
            "schema": HANDSHAKE_SCHEMA,
            "auth_token": "test",
            "guard_home": guard_home,
            "store_path": format!("{guard_home}/guard.db"),
            "source": "default",
            "busy_timeout_ms": 2000,
        });
        let config = ReadConfig::from_line(&serde_json::to_vec(&handshake).unwrap()).unwrap();
        assert_eq!(cloud_workspace(&config), None);
    }
    #[test]
    fn a_signed_in_device_names_its_workspace() {
        let home = tempfile::tempdir().unwrap();
        let guard_home = home.path().to_string_lossy().into_owned();
        let store_path = home.path().join("guard.db");
        rusqlite::Connection::open(&store_path)
            .unwrap()
            .execute_batch(
                "create table sync_state (state_key text primary key, \
                 payload_json text not null, updated_at text not null);",
            )
            .unwrap();
        let store =
            crate::package_authority_op::ResidentSupplyChainStore::new(&store_path, home.path());
        let credentials = json!({
            "issuer": "https://hol.org",
            "client_id": "guard-cli",
            "dpop_private_key_pem": "synthetic-pem",
            "dpop_public_jwk": {"kty": "EC"},
            "dpop_public_jwk_thumbprint": "synthetic-thumbprint",
            "workspace_id": "workspace-1",
        });
        crate::oauth_refresh::persist_rotated_oauth_refresh_token(
            &store,
            &credentials,
            None,
            None,
            "synthetic-refresh",
            None,
            None,
        )
        .unwrap();
        let handshake = json!({
            "schema": HANDSHAKE_SCHEMA,
            "auth_token": "test",
            "guard_home": guard_home,
            "store_path": store_path.to_string_lossy(),
            "source": "default",
            "busy_timeout_ms": 2000,
        });
        let config = ReadConfig::from_line(&serde_json::to_vec(&handshake).unwrap()).unwrap();
        assert_eq!(cloud_workspace(&config).as_deref(), Some("workspace-1"));
    }
}

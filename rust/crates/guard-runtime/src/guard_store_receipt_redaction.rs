//! `receipt_redaction_bookkeeping`: the `sync_state` rows the cloud sync keeps
//! about the receipt redaction level, and the Review privacy-projection
//! requeue that follows a level change.
//!
//! The level itself is resolved by the caller from the signed policy bundle or
//! the local config. These rows are cursor bookkeeping, not an authority
//! source. Each action runs inside one store write transaction, so a reader
//! never sees the cursor reset without the level that caused it.

use rusqlite::Connection;
use serde_json::{json, Value};

use crate::guard_store_args::Args;
use crate::guard_store_cloud_events::append_event;
use crate::guard_store_db::{exec, value_error, StoreResult};
use crate::guard_store_json::dumps_default;
use crate::guard_store_outbox_requeue::{requeue_pending, RequeueOptions};
use crate::guard_store_sync_state::{read_payload, write_encoded};

const LEVEL_KEY: &str = "cloud_receipt_redaction_level";
const CURSOR_KEY: &str = "receipt_sync_cursor";
const RELAXED_RESYNC_MARKER: &str = "cloud_receipt_redaction_relaxed_resync_v1";
const PRIVACY_PROJECTION_MARKER: &str = "cloud_review_privacy_projection_v2";
const COMMAND_DETAIL_BACKFILL_MARKER: &str = "cloud_receipt_command_detail_backfill_v2";

/// `_RECEIPT_REDACTION_LEVEL_RANK`; an unknown or missing level ranks as full.
fn rank(level: Option<&str>) -> u8 {
    match level {
        Some("partial") => 1,
        Some("none") => 2,
        _ => 0,
    }
}

pub(crate) fn valid_level(level: &str) -> bool {
    matches!(level, "full" | "partial" | "none")
}

/// The storage the bookkeeping needs, so the rules can be tested without the
/// Review outbox schema.
pub(crate) trait Bookkeeping {
    fn read(&mut self, key: &str) -> StoreResult<Option<Value>>;
    fn write(&mut self, key: &str, payload: &Value, now: &str) -> StoreResult<()>;
    fn delete(&mut self, key: &str) -> StoreResult<()>;
    /// `_requeue_cloud_review_privacy_projection`: the requeued count.
    fn requeue_projection(&mut self, level: &str, changed_at: &str) -> StoreResult<i64>;
    /// Append one `guard_events` row with already-encoded payload text.
    fn add_event(&mut self, name: &str, payload_json: &str, now: &str) -> StoreResult<()>;
}

/// The store's `sync_state` and Review outbox, inside the caller's write.
pub(crate) struct Store<'a> {
    pub(crate) connection: &'a Connection,
    pub(crate) source: &'a str,
}

impl Bookkeeping for Store<'_> {
    fn read(&mut self, key: &str) -> StoreResult<Option<Value>> {
        read_payload(self.connection, key)
    }

    fn write(&mut self, key: &str, payload: &Value, now: &str) -> StoreResult<()> {
        let encoded =
            serde_json::to_string(payload).map_or_else(|_| value_error("invalid_payload"), Ok)?;
        write_encoded(self.connection, key, &encoded, now)
    }

    fn delete(&mut self, key: &str) -> StoreResult<()> {
        exec(
            self.connection,
            "delete from sync_state where state_key = ?",
            &[Value::from(key)],
        )?;
        Ok(())
    }

    fn requeue_projection(&mut self, level: &str, changed_at: &str) -> StoreResult<i64> {
        let options = RequeueOptions {
            require_binding: false,
            only_retry_identity_drift: false,
            native_replay: false,
            repair_sequences: None,
            request_ids: None,
            snapshots: None,
        };
        let count = requeue_pending(self.connection, self.source, changed_at, &options)?;
        let marker = projection_marker(level, changed_at, count)?;
        write_encoded(
            self.connection,
            PRIVACY_PROJECTION_MARKER,
            &marker,
            changed_at,
        )?;
        Ok(count)
    }

    fn add_event(&mut self, name: &str, payload_json: &str, now: &str) -> StoreResult<()> {
        append_event(self.connection, name, payload_json, now, false)
    }
}

/// `json.dumps({"level": ..., "updated_at": ..., "requeued": n})`, the text the
/// Python requeue wrote, in its key order and separators.
fn projection_marker(level: &str, changed_at: &str, count: i64) -> StoreResult<String> {
    let (Some(level), Some(changed_at)) = (
        dumps_default(&Value::from(level)),
        dumps_default(&Value::from(changed_at)),
    ) else {
        return value_error("invalid_payload");
    };
    Ok(format!(
        "{{\"level\": {level}, \"updated_at\": {changed_at}, \"requeued\": {count}}}"
    ))
}

fn level_marker(level: &str, now: &str) -> Value {
    json!({"level": level, "updated_at": now})
}

fn marker_level(store: &mut impl Bookkeeping, key: &str) -> StoreResult<Option<String>> {
    Ok(store.read(key)?.and_then(|marker| {
        marker
            .get("level")
            .and_then(Value::as_str)
            .map(str::to_owned)
    }))
}

/// `_stored_cloud_receipt_redaction_level`.
fn stored_level(store: &mut impl Bookkeeping) -> StoreResult<Option<String>> {
    Ok(marker_level(store, LEVEL_KEY)?.filter(|level| valid_level(level)))
}

fn reset_cursor(
    store: &mut impl Bookkeeping,
    level: &str,
    now: &str,
    reason: &str,
) -> StoreResult<()> {
    let cursor = json!({
        "last_rowid": 0,
        "synced_at": now,
        "reason": reason,
        "receipt_redaction_level": level,
    });
    store.write(CURSOR_KEY, &cursor, now)
}

/// `_persist_cloud_receipt_redaction_level`: a relaxed level restarts the
/// receipt cursor so earlier receipts are uploaded again at the new level.
pub(crate) fn persist(
    store: &mut impl Bookkeeping,
    level: &str,
    local_level: &str,
    now: &str,
) -> StoreResult<()> {
    let previous = stored_level(store)?.unwrap_or_else(|| local_level.to_owned());
    if rank(Some(level)) > rank(Some(&previous)) {
        reset_cursor(store, level, now, "cloud_receipt_redaction_level_relaxed")?;
    }
    store.write(LEVEL_KEY, &level_marker(level, now), now)?;
    if level != previous {
        store.requeue_projection(level, now)?;
    }
    if rank(Some(level)) > rank(Some("full")) {
        store.write(RELAXED_RESYNC_MARKER, &level_marker(level, now), now)?;
    }
    Ok(())
}

/// `_reset_cloud_receipt_redaction_authority`: no signed override is in
/// effect, so the local level applies and the relaxation markers go.
pub(crate) fn reset(store: &mut impl Bookkeeping, local_level: &str, now: &str) -> StoreResult<()> {
    let previous = stored_level(store)?;
    store.write(LEVEL_KEY, &level_marker(local_level, now), now)?;
    if previous.is_some_and(|previous| previous != local_level) {
        store.requeue_projection(local_level, now)?;
    }
    store.delete(RELAXED_RESYNC_MARKER)?;
    store.delete(COMMAND_DETAIL_BACKFILL_MARKER)
}

/// `_ensure_cloud_review_privacy_projection`.
pub(crate) fn ensure_projection(
    store: &mut impl Bookkeeping,
    level: &str,
    now: &str,
) -> StoreResult<()> {
    if marker_level(store, PRIVACY_PROJECTION_MARKER)?.as_deref() == Some(level) {
        return Ok(());
    }
    store.requeue_projection(level, now)?;
    Ok(())
}

/// `_ensure_relaxed_receipt_redaction_resync`: restart the cursor once for a
/// relaxed level that was already in effect before the marker existed.
pub(crate) fn ensure_resync(
    store: &mut impl Bookkeeping,
    level: &str,
    now: &str,
) -> StoreResult<()> {
    if rank(Some(level)) <= rank(Some("full"))
        || marker_level(store, RELAXED_RESYNC_MARKER)?.as_deref() == Some(level)
    {
        return Ok(());
    }
    reset_cursor(
        store,
        level,
        now,
        "cloud_receipt_redaction_level_relaxed_existing",
    )?;
    store.write(RELAXED_RESYNC_MARKER, &level_marker(level, now), now)
}

/// A `ensure_projection` or `ensure_resync` call that would change nothing.
/// The store answers it from this read alone, without a write lock or a
/// dispatch. Any other call, including one with an invalid level that must
/// fail, goes to the write transaction, which repeats the check.
pub(crate) fn is_noop(connection: &Connection, args: &Args<'_>) -> StoreResult<bool> {
    let Some(level) = args.opt_str("level")?.filter(|level| valid_level(level)) else {
        return Ok(false);
    };
    let marker = match args.opt_str("action")? {
        Some("ensure_projection") => PRIVACY_PROJECTION_MARKER,
        Some("ensure_resync") if rank(Some(level)) <= rank(Some("full")) => return Ok(true),
        Some("ensure_resync") => RELAXED_RESYNC_MARKER,
        _ => return Ok(false),
    };
    let mut store = Store {
        connection,
        source: "",
    };
    Ok(marker_level(&mut store, marker)?.as_deref() == Some(level))
}

fn level_arg<'a>(args: &Args<'a>, key: &str) -> StoreResult<&'a str> {
    let level = args.str(key)?;
    if valid_level(level) {
        Ok(level)
    } else {
        value_error("invalid_receipt_redaction_level")
    }
}

/// The `receipt_redaction_bookkeeping` store method.
pub(crate) fn method(connection: &Connection, source: &str, args: &Args<'_>) -> StoreResult<Value> {
    let now = args.str("now")?;
    let mut store = Store { connection, source };
    match args.str("action")? {
        "persist" => persist(
            &mut store,
            level_arg(args, "level")?,
            level_arg(args, "local_level")?,
            now,
        )?,
        "reset" => reset(&mut store, level_arg(args, "local_level")?, now)?,
        "ensure_projection" => ensure_projection(&mut store, level_arg(args, "level")?, now)?,
        "ensure_resync" => ensure_resync(&mut store, level_arg(args, "level")?, now)?,
        "requeue_projection" => {
            return Ok(json!(
                store.requeue_projection(level_arg(args, "level")?, now)?
            ));
        }
        _ => return value_error("invalid_receipt_redaction_action"),
    }
    Ok(Value::Null)
}

/// Activation bookkeeping shares this module's store and level rules.
#[path = "guard_store_policy_bundle_activated.rs"]
pub(crate) mod policy_bundle_activated;

/// Rejection bookkeeping writes the same `sync_state` table and event log.
#[path = "guard_store_policy_bundle_rejection.rs"]
pub(crate) mod policy_bundle_rejection;

#[path = "guard_store_sync_summary.rs"]
pub(crate) mod sync_summary;

#[cfg(test)]
#[path = "guard_store_receipt_redaction_tests.rs"]
pub(crate) mod tests;

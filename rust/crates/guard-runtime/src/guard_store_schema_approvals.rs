//! The approval-queue steps of the store opener that follow the approval
//! columns: the version 23 Watch-only marking from
//! `store_watch_only_approval_schema.py`, the version 3 queue backfill, and
//! the approval indexes, in the order `store_connection_schema.py` runs them.

use rusqlite::Connection;

use crate::guard_store_approval_backfill;
use crate::guard_store_db::StoreResult;

/// `WATCH_ONLY_APPROVAL_MIGRATION_VERSION`.
pub(super) const WATCH_ONLY_VERSION: i64 = 23;
/// The queue backfill's version.
pub(super) const QUEUE_BACKFILL_VERSION: i64 = 3;

/// The columns `ensure_watch_only_approval_schema` adds, in its order.
pub(super) const WATCH_ONLY_COLUMNS: [(&str, &str); 5] = [
    ("guard_version", "text"),
    ("first_seen_guard_version", "text"),
    ("last_seen_guard_version", "text"),
    ("oauth_source", "text"),
    ("watch_only_observation", "integer not null default 0"),
];

/// Mark the rows the Watch-mode inbox recorded. A parity test on the Python
/// side holds this equal to the Python statement.
pub(super) const MARK_WATCH_ONLY: &str = r##"update approval_requests
set watch_only_observation = 1
where exists (
      select 1
      from json_each(coalesce(scanner_evidence_json, '[]'))
      where json_extract(value, '$.source') = 'observe_mode_inbox'
  )"##;

/// Run the Watch-only marking, the queue backfill and the approval indexes
/// in one savepoint, so a failure keeps none of them.
pub(super) fn ensure_approval_queue(connection: &Connection, now: &str) -> StoreResult<()> {
    super::tables::in_savepoint(connection, "approval_queue_schema", || {
        super::columns::ensure_columns(connection, "approval_requests", &WATCH_ONLY_COLUMNS)?;
        if !super::versions::applied(connection, WATCH_ONLY_VERSION)? {
            connection.execute_batch(MARK_WATCH_ONLY)?;
            super::versions::record(connection, WATCH_ONLY_VERSION, now)?;
        }
        if !super::versions::applied(connection, QUEUE_BACKFILL_VERSION)? {
            guard_store_approval_backfill::backfill(connection)?;
            super::versions::record(connection, QUEUE_BACKFILL_VERSION, now)?;
        }
        super::create_approval_indexes(connection)?;
        Ok(())
    })
}

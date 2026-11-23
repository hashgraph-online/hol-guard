//! The last schema steps the Python store runs after the Review outbox, in
//! its order: the receipt indexes and rollups, the rollup rebuild requests,
//! versions 7 and 8, the client-attachment lease columns, the local device,
//! storage maintenance, version 2, and reopening approvals the legacy wait
//! timeout expired. A mirror of the tail of `_initialize_schema` in
//! `store_connection_schema.py`.

use rusqlite::Connection;

use crate::guard_store_db::StoreResult;
use crate::guard_store_outbox_append::uuid4_hex;

/// Versions recorded once with no data step: the old rollup and Watch steps.
pub(super) const MARKER_VERSIONS: [i64; 2] = [7, 8];
/// `STORAGE_MAINTENANCE_MIGRATION_VERSION`, then
/// `STORAGE_QUERY_INDEX_MIGRATION_VERSION`.
pub(super) const STORAGE_VERSIONS: [i64; 2] = [20, 21];
/// The first schema version, recorded last.
pub(super) const BASE_VERSION: i64 = 2;

pub(super) fn ensure_tail(connection: &Connection, now: &str) -> StoreResult<()> {
    super::tables::in_savepoint(connection, "schema_tail", || {
        super::create_receipt_rollups(connection)?;
        super::request_rollup_rebuilds(connection, now)?;
        for version in MARKER_VERSIONS {
            super::record_version(connection, version, now)?;
        }
        super::upgrade_client_attachments(connection)?;
        super::ensure_local_device(connection, &uuid4_hex()?, now)?;
        super::create_storage_maintenance(connection)?;
        for version in STORAGE_VERSIONS {
            super::record_version(connection, version, now)?;
        }
        super::record_version(connection, BASE_VERSION, now)?;
        super::reopen_expired_approvals(connection)?;
        Ok(())
    })
}

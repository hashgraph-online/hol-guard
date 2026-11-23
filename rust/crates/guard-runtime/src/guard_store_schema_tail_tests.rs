use rusqlite::Connection;

use super::tail::{ensure_tail, BASE_VERSION, MARKER_VERSIONS, STORAGE_VERSIONS};
use super::{create_base, ensure_families};

const NOW: &str = "2026-11-23T00:00:00+00:00";
const LATER: &str = "2026-11-24T00:00:00+00:00";

fn fresh() -> Connection {
    let connection = Connection::open_in_memory().expect("open");
    create_base(&connection).expect("base");
    ensure_families(&connection, NOW).expect("families");
    connection
}

fn count(connection: &Connection, sql: &str) -> i64 {
    connection
        .query_row(sql, [], |row| row.get(0))
        .expect("count")
}

fn applied(connection: &Connection, version: i64) -> bool {
    connection
        .query_row(
            "select count(*) from schema_migrations where version = ?1",
            [version],
            |row| row.get::<_, i64>(0),
        )
        .expect("version")
        == 1
}

#[test]
fn a_fresh_store_records_every_tail_version_and_one_device() {
    let connection = fresh();
    let mut versions = vec![6, 16, BASE_VERSION];
    versions.extend(MARKER_VERSIONS);
    versions.extend(STORAGE_VERSIONS);
    for version in versions {
        assert!(applied(&connection, version), "version {version}");
    }
    assert_eq!(count(&connection, "select count(*) from guard_devices"), 1);
    assert_eq!(
        count(
            &connection,
            "select count(*) from sqlite_master where name = 'guard_storage_maintenance'"
        ),
        1
    );
    let device: String = connection
        .query_row("select installation_id from guard_devices", [], |row| {
            row.get(0)
        })
        .expect("device");
    ensure_tail(&connection, LATER).expect("again");
    let again: String = connection
        .query_row("select installation_id from guard_devices", [], |row| {
            row.get(0)
        })
        .expect("device");
    assert_eq!(device, again);
}

#[test]
fn a_missing_rollup_version_asks_for_one_rebuild() {
    let connection = fresh();
    connection
        .execute_batch(
            "delete from schema_migrations where version = 16; \
             delete from sync_state where state_key = 'receipt_rollups_rebuild_pending'",
        )
        .expect("reset");
    ensure_tail(&connection, LATER).expect("tail");
    assert!(applied(&connection, 16));
    assert_eq!(
        count(
            &connection,
            "select count(*) from sync_state where state_key = 'receipt_rollups_rebuild_pending'"
        ),
        1
    );
}

#[test]
fn a_failed_tail_keeps_nothing() {
    let connection = fresh();
    connection
        .execute_batch(
            "delete from schema_migrations where version in (7, 8, 2); \
             delete from guard_devices; \
             drop table guard_storage_maintenance; \
             create view guard_storage_maintenance as select 1 as x",
        )
        .expect("break");
    assert!(ensure_tail(&connection, LATER).is_err());
    assert!(!applied(&connection, 7));
    assert_eq!(count(&connection, "select count(*) from guard_devices"), 0);
}

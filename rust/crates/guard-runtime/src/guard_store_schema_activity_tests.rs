use rusqlite::Connection;

use super::activity::{ensure_activity, ensure_health, ACTIVITY_VERSION, HEALTH_ACTIVE_VERSION};
use super::create_base;
use crate::guard_store_db::StoreError;

const NOW: &str = "2026-01-02T03:04:05+00:00";

fn fresh() -> Connection {
    let connection = Connection::open_in_memory().expect("open");
    create_base(&connection).expect("base");
    connection
}

fn recorded(connection: &Connection, version: i64) -> bool {
    connection
        .query_row(
            "select count(*) from schema_migrations where version = ?1",
            [version],
            |row| row.get::<_, i64>(0),
        )
        .expect("count")
        == 1
}

fn refusal(error: StoreError) -> String {
    match error {
        StoreError::Runtime(message) => message,
        other => panic!("unexpected {other:?}"),
    }
}

#[test]
fn activity_and_health_are_created_seeded_and_versioned() {
    let connection = fresh();
    ensure_activity(&connection, NOW).expect("activity");
    ensure_health(&connection, NOW).expect("health");
    ensure_activity(&connection, NOW).expect("activity again");
    ensure_health(&connection, NOW).expect("health again");
    for version in [ACTIVITY_VERSION, 11, HEALTH_ACTIVE_VERSION] {
        assert!(recorded(&connection, version), "{version}");
    }
    let seeded: (String, i64) = connection
        .query_row(
            "select h.schema_version, a.command_error_active \
             from command_activity_health h join command_activity_health_active a using (singleton)",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .expect("singletons");
    assert_eq!(seeded, ("1.0.0".to_owned(), 0));
}

#[test]
fn a_health_error_marks_every_active_flag() {
    let connection = fresh();
    connection
        .execute_batch(&format!(
            "{}; insert into command_activity_health values (1, 0, 2, 'write_failed', '{NOW}', '1.0.0');",
            super::activity_sql::HEALTH_TABLE
        ))
        .expect("legacy health");
    ensure_health(&connection, NOW).expect("health");
    let flags: (i64, i64, i64) = connection
        .query_row(
            "select command_error_active, shadow_error_active, maintenance_error_active \
             from command_activity_health_active",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .expect("flags");
    assert_eq!(flags, (1, 1, 1));
}

#[test]
fn an_extra_activity_column_is_refused_and_rolled_back() {
    let connection = fresh();
    ensure_activity(&connection, NOW).expect("activity");
    connection
        .execute_batch(
            "delete from schema_migrations where version = 10; \
             alter table command_activity add column extra text;",
        )
        .expect("tamper");
    let message = refusal(ensure_activity(&connection, NOW).expect_err("refused"));
    assert_eq!(message, "incompatible command_activity schema");
    assert!(!recorded(&connection, ACTIVITY_VERSION));
}

#[test]
fn a_dropped_activity_index_is_refused() {
    let connection = fresh();
    connection
        .execute_batch(
            "create table command_activity_correlations (activity_id text not null, \
               kind text not null, harness text not null, key_id text not null, \
               digest text not null, primary key (activity_id, kind)); \
             create unique index idx_command_activity_request_correlation_unique \
               on command_activity_correlations (harness, key_id, digest);",
        )
        .expect("legacy");
    let message = refusal(ensure_activity(&connection, NOW).expect_err("refused"));
    assert_eq!(
        message,
        "incompatible command activity index: idx_command_activity_request_correlation_unique"
    );
    let tables: i64 = connection
        .query_row(
            "select count(*) from sqlite_master where name = 'command_activity'",
            [],
            |row| row.get(0),
        )
        .expect("count");
    assert_eq!(tables, 0, "the savepoint rolled the new tables back");
}

#[test]
fn a_changed_health_table_is_refused() {
    let connection = fresh();
    connection
        .execute_batch(
            "create table command_activity_health (singleton integer primary key, \
               dropped_event_count integer, persistence_error_count integer, \
               last_error_code text, last_error_at text, schema_version text)",
        )
        .expect("legacy");
    let message = refusal(ensure_health(&connection, NOW).expect_err("refused"));
    assert_eq!(
        message,
        "incompatible command_activity_health schema object"
    );
}

#[test]
fn a_busy_release_rolls_the_savepoint_back() {
    let directory = tempfile::tempdir().expect("directory");
    let path = directory.path().join("guard.db");
    let connection = Connection::open(&path).expect("open");
    connection
        .busy_timeout(std::time::Duration::ZERO)
        .expect("no wait");
    connection
        .execute_batch("pragma journal_mode = delete; create table keep (id integer)")
        .expect("setup");
    let reader = Connection::open(&path).expect("reader");
    reader
        .execute_batch("begin; select count(*) from keep")
        .expect("shared lock");
    let outcome = super::tables::in_savepoint(&connection, "probe", || {
        connection
            .execute_batch("create table added (id integer)")
            .map_err(StoreError::from)
    });
    assert!(outcome.is_err());
    assert!(connection.is_autocommit());
    reader.execute_batch("rollback").expect("release reader");
    let tables: i64 = connection
        .query_row(
            "select count(*) from sqlite_master where type = 'table'",
            [],
            |row| row.get(0),
        )
        .expect("count");
    assert_eq!(tables, 1);
}

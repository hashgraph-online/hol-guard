use rusqlite::Connection;

use super::activity::ensure_activity;
use super::activity_extra::{
    ensure_api, ensure_display, ensure_maintenance, API_VERSION, DISPLAY_VERSION,
    MAINTENANCE_SCHEMA_VERSION, MAINTENANCE_VERSION,
};
use super::create_base;
use crate::guard_store_db::StoreError;

const NOW: &str = "2026-01-02T03:04:05+00:00";

fn fresh() -> Connection {
    let connection = Connection::open_in_memory().expect("open");
    create_base(&connection).expect("base");
    ensure_activity(&connection, NOW).expect("activity");
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

fn count(connection: &Connection, sql: &str) -> i64 {
    connection
        .query_row(sql, [], |row| row.get(0))
        .expect("count")
}

fn runtime(error: StoreError) -> String {
    match error {
        StoreError::Runtime(message) => message,
        other => panic!("unexpected error: {other:?}"),
    }
}

fn ensure_all(connection: &Connection) {
    ensure_maintenance(connection, NOW).expect("maintenance");
    ensure_api(connection, NOW).expect("api");
    ensure_display(connection, NOW).expect("display");
}

fn insert_activity(connection: &Connection, activity_id: &str) {
    connection
        .execute(
            "insert into command_activity (activity_id, occurred_at, harness, hook_phase, \
             execution_status, proof_level, match_count, prompted, approval_reuse_status, \
             receipt_link_status, evaluation_latency_bucket, persistence_latency_bucket, \
             schema_version) values (?1, ?2, 'codex', 'pre', 'allowed', 'native', 0, 0, \
             'none', 'none', 'fast', 'fast', '1')",
            (activity_id, NOW),
        )
        .expect("activity row");
}

#[test]
fn a_fresh_store_gains_every_family_and_its_versions() {
    let connection = fresh();
    ensure_all(&connection);
    ensure_all(&connection);
    for version in [MAINTENANCE_VERSION, API_VERSION, DISPLAY_VERSION] {
        assert!(recorded(&connection, version), "{version}");
    }
    let version: String = connection
        .query_row(
            "select schema_version from command_activity_maintenance where singleton = 1",
            [],
            |row| row.get(0),
        )
        .expect("singleton");
    assert_eq!(version, MAINTENANCE_SCHEMA_VERSION);
    assert_eq!(
        count(
            &connection,
            "select count(*) from command_activity_maintenance"
        ),
        1
    );
}

#[test]
fn the_triggers_track_activity_rows() {
    let connection = fresh();
    ensure_all(&connection);
    insert_activity(&connection, "a-1");
    assert_eq!(
        count(
            &connection,
            "select count(*) from command_activity_invalidations"
        ),
        1
    );
    assert_eq!(
        count(
            &connection,
            "select count(*) from command_activity_rollup_pending"
        ),
        1
    );
    connection
        .execute(
            "insert into command_activity_invocation (activity_id, invocation_preview) \
             values ('a-1', 'git status')",
            [],
        )
        .expect("preview");
    let refused = connection.execute(
        "update command_activity_invocation set invocation_preview = 'ls'",
        [],
    );
    assert!(refused.is_err());
    let orphan = connection.execute(
        "insert into command_activity_invocation (activity_id, invocation_preview) \
         values ('missing', 'ls')",
        [],
    );
    assert!(orphan.is_err());
}

#[test]
fn a_reshaped_display_table_is_refused_and_rolled_back() {
    let connection = fresh();
    connection
        .execute_batch("create table command_activity_invocation (activity_id text primary key)")
        .expect("legacy table");
    let error = ensure_display(&connection, NOW).expect_err("refused");
    assert_eq!(
        runtime(error),
        "incompatible command_activity_invocation schema"
    );
    assert!(connection.is_autocommit());
    assert!(!recorded(&connection, DISPLAY_VERSION));
}

#[test]
fn a_maintenance_singleton_from_another_version_is_refused() {
    let connection = fresh();
    ensure_maintenance(&connection, NOW).expect("maintenance");
    connection
        .execute(
            "update command_activity_maintenance set schema_version = 'other'",
            [],
        )
        .expect("rewrite");
    let error = ensure_maintenance(&connection, NOW).expect_err("refused");
    assert_eq!(
        runtime(error),
        "incompatible command_activity_maintenance singleton"
    );
}

#[test]
fn a_rewritten_api_trigger_is_refused() {
    let connection = fresh();
    connection
        .execute_batch(
            "create trigger trg_command_activity_invalidation_delete \
             after delete on command_activity begin select 1; end",
        )
        .expect("drifted trigger");
    let error = ensure_api(&connection, NOW).expect_err("refused");
    assert_eq!(
        runtime(error),
        "incompatible command activity API schema object: \
         trg_command_activity_invalidation_delete"
    );
    assert!(!recorded(&connection, API_VERSION));
}

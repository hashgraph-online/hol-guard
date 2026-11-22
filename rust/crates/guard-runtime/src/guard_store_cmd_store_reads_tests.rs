use super::*;
use serde_json::Map;

use crate::guard_store_op_kind::{method_kind, Kind};

fn store() -> Connection {
    let connection = Connection::open_in_memory().unwrap();
    connection
        .execute_batch(
            "create table command_activity (activity_id text primary key);
             create table command_activity_health (
               singleton integer primary key, dropped_event_count integer not null,
               persistence_error_count integer not null, last_error_code text,
               last_error_at text, schema_version text not null);
             create table command_activity_health_active (
               singleton integer primary key, command_error_active integer not null,
               shadow_error_active integer not null, maintenance_error_active integer not null);",
        )
        .unwrap();
    connection
}

fn call(connection: &Connection, method: &str) -> StoreResult<Value> {
    let map = Map::new();
    dispatch(connection, method, &Args(&map))
}

#[test]
fn the_activity_count_reads_every_row() {
    let connection = store();
    assert_eq!(call(&connection, "count_command_activities").unwrap(), 0);
    connection
        .execute_batch("insert into command_activity values ('a'), ('b'), ('c');")
        .unwrap();
    assert_eq!(call(&connection, "count_command_activities").unwrap(), 3);
}

#[test]
fn the_health_counters_read_with_the_active_flags_summed() {
    let connection = store();
    connection
        .execute_batch(
            "insert into command_activity_health values (1, 4, 2, 'disk_full', '2026-01-01T00:00:00+00:00', '11');
             insert into command_activity_health_active values (1, 1, 0, 1);",
        )
        .unwrap();
    assert_eq!(
        call(&connection, "get_command_activity_persistence_health").unwrap(),
        json!({
            "dropped_event_count": 4,
            "persistence_error_count": 2,
            "active_error_count": 2,
            "last_error_code": "disk_full",
            "last_error_at": "2026-01-01T00:00:00+00:00",
            "schema_version": "11",
        })
    );
}

#[test]
fn missing_health_rows_are_reported_unavailable() {
    let connection = store();
    assert!(matches!(
        call(&connection, "get_command_activity_persistence_health"),
        Err(StoreError::Runtime(message))
            if message == "command activity persistence health is unavailable"
    ));
}

#[test]
fn table_names_read_sorted() {
    assert_eq!(
        call(&store(), "list_table_names").unwrap(),
        json!([
            "command_activity",
            "command_activity_health",
            "command_activity_health_active"
        ])
    );
}

#[test]
fn the_store_reads_are_routed_snapshot_methods() {
    for method in [
        "get_command_activity_persistence_health",
        "count_command_activities",
        "list_table_names",
    ] {
        assert!(handles(method));
        assert!(matches!(method_kind(method), Some(Kind::Snapshot)));
    }
    assert!(!handles("list_command_activity_page"));
}

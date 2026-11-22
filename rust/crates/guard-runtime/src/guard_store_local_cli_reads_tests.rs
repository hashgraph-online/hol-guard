//! The single-value local CLI reads and the capability-cause note.

use rusqlite::Connection;
use serde_json::{json, Map, Value};

use super::*;

fn empty() -> Connection {
    Connection::open_in_memory().unwrap()
}

fn store() -> Connection {
    let connection = empty();
    connection
        .execute_batch(
            "create table local_cli_authority (singleton integer primary key, revision integer);
             create table local_cli_observation (
               cli_id text primary key, identity_hash text, surface text,
               first_blocked_cause text);
             create table local_cli_grant (cli_id text primary key, state text);
             create table local_cli_command_grant (
               cli_id text, command_id text, state text);
             create table local_cli_grant_capability (
               cli_id text, capability text, state text);",
        )
        .unwrap();
    connection
}

fn call(connection: &Connection, method: &str, args: Value) -> StoreResult<Value> {
    let Value::Object(args) = args else {
        unreachable!("arguments are an object")
    };
    dispatch(connection, method, &Args(&args))
}

fn read(connection: &Connection, method: &str) -> Value {
    call(connection, method, json!({"cli_id": "local-cli.tool"})).unwrap()
}

#[test]
fn a_store_without_local_cli_tables_reads_as_empty() {
    let connection = empty();
    assert_eq!(read(&connection, "read_local_cli_revision"), json!(0));
    assert_eq!(read(&connection, "read_local_cli_surface"), Value::Null);
    assert_eq!(read(&connection, "has_local_cli_block_rules"), json!(false));
    assert_eq!(
        read(&connection, "read_local_cli_capabilities"),
        json!({"loopback-network": "off", "state-dir-read": "off", "state-dir-write": "off"})
    );
}

#[test]
fn the_revision_is_the_authority_row() {
    let connection = store();
    assert_eq!(read(&connection, "read_local_cli_revision"), json!(0));
    connection
        .execute("insert into local_cli_authority values (1, 7)", [])
        .unwrap();
    assert_eq!(read(&connection, "read_local_cli_revision"), json!(7));
    connection
        .execute("update local_cli_authority set revision = 'x'", [])
        .unwrap();
    assert!(call(&connection, "read_local_cli_revision", json!({})).is_err());
}

#[test]
fn the_surface_is_the_stored_text_or_null() {
    let connection = store();
    connection
        .execute(
            "insert into local_cli_observation values ('local-cli.tool', 'h1', 'mcp', null)",
            [],
        )
        .unwrap();
    assert_eq!(read(&connection, "read_local_cli_surface"), json!("mcp"));
    connection
        .execute("update local_cli_observation set surface = 3", [])
        .unwrap();
    assert_eq!(read(&connection, "read_local_cli_surface"), json!("3"));
    connection
        .execute("update local_cli_observation set surface = null", [])
        .unwrap();
    assert_eq!(read(&connection, "read_local_cli_surface"), Value::Null);
}

#[test]
fn only_a_blocked_grant_or_command_is_a_block_rule() {
    let connection = store();
    connection
        .execute_batch(
            "insert into local_cli_grant values ('local-cli.tool', 'allowed');
             insert into local_cli_command_grant values ('local-cli.tool', 'c1', 'allow');",
        )
        .unwrap();
    assert_eq!(read(&connection, "has_local_cli_block_rules"), json!(false));
    connection
        .execute("update local_cli_command_grant set state = 'block'", [])
        .unwrap();
    assert_eq!(read(&connection, "has_local_cli_block_rules"), json!(true));
    connection
        .execute_batch(
            "delete from local_cli_command_grant;
             update local_cli_grant set state = 'blocked';",
        )
        .unwrap();
    assert_eq!(read(&connection, "has_local_cli_block_rules"), json!(true));
}

#[test]
fn capabilities_are_the_full_map_for_one_cli() {
    let connection = store();
    connection
        .execute_batch(
            "insert into local_cli_grant_capability values ('local-cli.tool', 'state-dir-read', 'on');
             insert into local_cli_grant_capability values ('local-cli.tool', 'state-dir-write', 'off');
             insert into local_cli_grant_capability values ('local-cli.tool', 'unknown', 'on');
             insert into local_cli_grant_capability values ('local-cli.other', 'loopback-network', 'on');",
        )
        .unwrap();
    assert_eq!(
        read(&connection, "read_local_cli_capabilities"),
        json!({"loopback-network": "off", "state-dir-read": "on", "state-dir-write": "off"})
    );
}

#[test]
fn the_cause_note_keeps_the_newest_denial_of_a_cli_observation() {
    let connection = store();
    connection
        .execute_batch(
            "insert into local_cli_observation values ('local-cli.tool', 'h1', 'cli', null);
             insert into local_cli_observation values ('local-cli.server', 'h2', 'mcp', null);",
        )
        .unwrap();
    let note = |cli_id: &str, hash: &str, cause: &str| {
        call(
            &connection,
            "note_local_cli_capability_cause",
            json!({"cli_id": cli_id, "identity_hash": hash, "cause": cause}),
        )
    };
    assert_eq!(
        note("local-cli.tool", "h1", "read_home_state").unwrap(),
        json!(1)
    );
    assert_eq!(
        note("local-cli.tool", "h1", "read_home_state").unwrap(),
        json!(0)
    );
    assert_eq!(
        note("local-cli.tool", "h1", "connect_loopback").unwrap(),
        json!(1)
    );
    assert_eq!(
        note("local-cli.tool", "other", "write_home_state").unwrap(),
        json!(0)
    );
    assert_eq!(
        note("local-cli.server", "h2", "write_home_state").unwrap(),
        json!(0)
    );
    let cause: Option<String> = connection
        .query_row(
            "select first_blocked_cause from local_cli_observation where cli_id = 'local-cli.tool'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(cause.as_deref(), Some("connect_loopback"));
}

#[test]
fn a_cause_no_capability_resolves_is_refused() {
    let connection = store();
    let refused = call(
        &connection,
        "note_local_cli_capability_cause",
        json!({"cli_id": "local-cli.tool", "identity_hash": "h1", "cause": "exec_outside_roots"}),
    );
    assert!(
        matches!(refused, Err(StoreError::Value(message)) if message == "invalid_first_blocked_cause")
    );
}

#[test]
fn only_these_methods_are_handled_and_each_has_a_store_kind() {
    use crate::guard_store_op_kind::{method_kind, Kind};
    for method in [
        "read_local_cli_revision",
        "read_local_cli_surface",
        "has_local_cli_block_rules",
        "read_local_cli_capabilities",
    ] {
        assert!(handles(method), "{method}");
        assert!(matches!(method_kind(method), Some(Kind::Read)), "{method}");
    }
    assert!(handles("note_local_cli_capability_cause"));
    assert!(matches!(
        method_kind("note_local_cli_capability_cause"),
        Some(Kind::Write)
    ));
    assert!(!handles("read_local_cli_grant"));
    let args = Map::new();
    assert!(dispatch(&empty(), "read_local_cli_grant", &Args(&args)).is_err());
}

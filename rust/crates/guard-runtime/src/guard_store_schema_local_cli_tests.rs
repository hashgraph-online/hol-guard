use rusqlite::Connection;

use super::columns::table_columns;
use super::local_cli::{checksum, ensure_local_cli, VERSION};
use super::local_cli_sql::CATALOG_TABLE;
use crate::guard_store_db::StoreError;

const TABLES: [&str; 13] = [
    "local_cli_schema_migration",
    "local_cli_observation",
    "local_cli_grant",
    "local_cli_authority",
    "local_cli_command",
    "local_cli_command_grant",
    "local_mcp_tool_authority",
    "local_mcp_workflow_proposal",
    "local_mcp_catalog",
    "local_mcp_provider_grant",
    "local_mcp_provider_authority",
    "local_mcp_provider_action",
    "local_cli_grant_capability",
];

const V1_OBSERVATION: &str = "create table local_cli_observation (
    cli_id text primary key, identity_hash text not null, kind text not null,
    name text not null, interpreter_name text, example_label text not null,
    observed_count integer not null, last_seen_at text not null)";

fn marker(connection: &Connection) -> (i64, String) {
    connection
        .query_row(
            "select version, checksum from local_cli_schema_migration",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .expect("marker")
}

fn store_at(version: i64, sum: &str) -> Connection {
    let connection = Connection::open_in_memory().expect("open");
    connection
        .execute_batch(
            "create table local_cli_schema_migration (singleton integer primary key, \
             version integer not null, checksum text not null)",
        )
        .expect("marker table");
    connection
        .execute(
            "insert into local_cli_schema_migration values (1, ?1, ?2)",
            (version, sum),
        )
        .expect("marker");
    connection
}

fn refusal(connection: &Connection) -> String {
    match ensure_local_cli(connection) {
        Err(StoreError::Value(message)) => message,
        other => panic!("expected a refusal, got {other:?}"),
    }
}

#[test]
fn a_fresh_store_gets_the_current_marker_and_every_table() {
    let connection = Connection::open_in_memory().expect("open");
    ensure_local_cli(&connection).expect("schema");
    ensure_local_cli(&connection).expect("again");
    assert_eq!(marker(&connection), (VERSION, checksum(VERSION)));
    for table in TABLES {
        assert!(
            !table_columns(&connection, table)
                .expect("columns")
                .is_empty(),
            "{table}"
        );
    }
    let observation = table_columns(&connection, "local_cli_observation").expect("columns");
    assert!(observation.contains("first_blocked_cause"));
    assert!(observation.contains("last_context_at"));
    let revision: i64 = connection
        .query_row("select revision from local_cli_authority", [], |row| {
            row.get(0)
        })
        .expect("authority");
    assert_eq!(revision, 0);
}

#[test]
fn a_version_one_store_walks_the_chain_and_keeps_its_rows() {
    let connection = store_at(1, &checksum(1));
    connection.execute_batch(V1_OBSERVATION).expect("v1");
    connection
        .execute(
            "insert into local_cli_observation values ('cli', 'hash', 'executable', \
             'lanectl', null, 'lanectl status', 2, '2026-01-01T00:00:00+00:00')",
            [],
        )
        .expect("row");
    ensure_local_cli(&connection).expect("walk");
    assert_eq!(marker(&connection), (VERSION, checksum(VERSION)));
    let observation = table_columns(&connection, "local_cli_observation").expect("columns");
    for column in [
        "source_path",
        "surface",
        "source_label",
        "remote_origin",
        "last_context_at",
    ] {
        assert!(observation.contains(column), "{column}");
    }
    let surface: String = connection
        .query_row("select surface from local_cli_observation", [], |row| {
            row.get(0)
        })
        .expect("row kept");
    assert_eq!(surface, "cli");
    assert!(!table_columns(&connection, "local_cli_grant_capability")
        .expect("columns")
        .is_empty());
}

#[test]
fn a_version_six_command_grant_is_rebuilt_with_its_rows() {
    let connection = store_at(6, &checksum(6));
    connection
        .execute_batch(V1_OBSERVATION)
        .expect("observation");
    connection.execute_batch(CATALOG_TABLE).expect("v6 catalog");
    connection
        .execute_batch(
            "create table local_cli_command_grant (cli_id text not null, \
             command_id text not null, state text not null, primary key (cli_id, command_id)); \
             insert into local_cli_command_grant values ('cli', 'status', 'allow');",
        )
        .expect("v6 grant");
    ensure_local_cli(&connection).expect("walk");
    let state: String = connection
        .query_row("select state from local_cli_command_grant", [], |row| {
            row.get(0)
        })
        .expect("row kept");
    assert_eq!(state, "allow");
    let refused = connection.execute(
        "insert into local_cli_command_grant values ('cli', 'other', 'maybe')",
        [],
    );
    assert!(refused.is_err(), "the rebuilt table checks its state");
}

#[test]
fn a_newer_marker_is_refused_and_left_alone() {
    let connection = store_at(VERSION + 1, "future");
    let message = refusal(&connection);
    assert!(
        message.contains("is newer than this Guard build"),
        "{message}"
    );
    assert_eq!(marker(&connection), (VERSION + 1, "future".to_owned()));
}

#[test]
fn a_current_version_with_a_wrong_checksum_is_refused() {
    let connection = store_at(VERSION, "forged");
    let message = refusal(&connection);
    assert!(message.contains("may be damaged"), "{message}");
    assert_eq!(marker(&connection), (VERSION, "forged".to_owned()));
}

#[test]
fn a_marker_of_the_wrong_type_is_invalid() {
    let connection = Connection::open_in_memory().expect("open");
    connection
        .execute_batch(
            "create table local_cli_schema_migration (singleton integer primary key, \
             version, checksum); insert into local_cli_schema_migration values (1, '14', 'x');",
        )
        .expect("marker");
    assert_eq!(refusal(&connection), "invalid local CLI schema marker");
}

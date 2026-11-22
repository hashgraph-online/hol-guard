use rusqlite::{params, Connection};
use serde_json::{json, Map, Value};

use super::{dispatch, handles};
use crate::guard_store_args::Args;
use crate::guard_store_op_kind::{method_kind, Kind};

const METHOD: &str = "local_mcp_catalog_change_names";

fn store() -> Connection {
    let connection = Connection::open_in_memory().expect("memory store");
    connection
        .execute_batch(
            "create table local_mcp_catalog ( \
               cli_id text not null, identity_hash text not null, catalog_json, revision integer);",
        )
        .expect("schema");
    connection
}

fn catalog(connection: &Connection, cli_id: &str, identity: &str, raw: Value) {
    connection
        .execute(
            "insert into local_mcp_catalog values (?1, ?2, ?3, 1)",
            params![cli_id, identity, raw.to_string()],
        )
        .expect("catalog");
}

fn snapshot(changes: Value) -> Value {
    json!({"complete": true, "tools": [], "changes": changes})
}

fn names(connection: &Connection, cli_ids: Value) -> Value {
    let mut map = Map::new();
    map.insert("cli_ids".into(), cli_ids);
    dispatch(connection, &Args(&map)).expect("read")
}

#[test]
fn the_read_is_routed_as_a_snapshot() {
    assert!(handles(METHOD));
    assert!(matches!(method_kind(METHOD), Some(Kind::Snapshot)));
    assert!(!handles("read_local_cli_revision"));
}

#[test]
fn added_and_changed_names_come_back_sorted_and_distinct() {
    let connection = store();
    catalog(
        &connection,
        "cli-a",
        "one",
        snapshot(
            json!({"added": ["zeta", "alpha", 3], "changed": ["alpha", "mid"], "removed": ["gone"]}),
        ),
    );
    catalog(
        &connection,
        "cli-a",
        "two",
        snapshot(json!({"changed": ["beta"]})),
    );
    catalog(
        &connection,
        "cli-b",
        "one",
        snapshot(json!({"added": ["other-cli"]})),
    );
    assert_eq!(
        names(&connection, json!(["cli-a"])),
        json!({"names": ["alpha", "beta", "mid", "zeta"]})
    );
    assert_eq!(
        names(&connection, json!(["cli-b", "cli-a", "cli-b"])),
        json!({"names": ["alpha", "beta", "mid", "other-cli", "zeta"]})
    );
}

#[test]
fn a_catalog_that_no_longer_decodes_contributes_nothing() {
    let connection = store();
    catalog(
        &connection,
        "cli-a",
        "incomplete",
        json!({"tools": [], "changes": {"added": ["a"]}}),
    );
    catalog(
        &connection,
        "cli-a",
        "no-tools",
        json!({"complete": true, "changes": {"added": ["b"]}}),
    );
    catalog(&connection, "cli-a", "list-changes", snapshot(json!(["c"])));
    catalog(
        &connection,
        "cli-a",
        "string-added",
        snapshot(json!({"added": "d"})),
    );
    connection
        .execute(
            "insert into local_mcp_catalog values ('cli-a', 'blob', ?1, 1)",
            params![snapshot(json!({"added": ["e"]})).to_string().into_bytes()],
        )
        .expect("blob");
    connection
        .execute(
            "insert into local_mcp_catalog values ('cli-a', 'text', 'not json', 1)",
            [],
        )
        .expect("text");
    assert_eq!(names(&connection, json!(["cli-a"])), json!({"names": []}));
}

#[test]
fn no_ids_or_no_table_reads_no_names() {
    assert_eq!(names(&store(), json!([])), json!({"names": []}));
    let bare = Connection::open_in_memory().expect("memory store");
    assert_eq!(names(&bare, json!(["cli-a"])), json!({"names": []}));
}

#[test]
fn the_ids_are_required_and_must_be_strings() {
    let connection = store();
    assert!(dispatch(&connection, &Args(&Map::new())).is_err());
    let mut map = Map::new();
    map.insert("cli_ids".into(), json!([1]));
    assert!(dispatch(&connection, &Args(&map)).is_err());
}

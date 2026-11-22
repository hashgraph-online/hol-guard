use rusqlite::{params, Connection};
use serde_json::{json, Map, Value};

use super::{dispatch, handles, HISTORY_PAGE_BYTES};
use crate::guard_store_args::Args;
use crate::guard_store_op_kind::{method_kind, Kind};

fn store() -> Connection {
    Connection::open_in_memory().expect("memory store")
}

fn schema(connection: &Connection) {
    connection
        .execute_batch(
            "create table extension_control_authority_snapshot ( \
               singleton integer primary key, revision, \
               snapshot_json, snapshot_digest, snapshot_mac); \
             create table extension_control_authority_transition ( \
               revision integer primary key, \
               snapshot_json, snapshot_digest, snapshot_mac, \
               transition_json, transition_digest, transition_mac);",
        )
        .expect("schema");
}

fn pending_table(connection: &Connection) {
    connection
        .execute_batch(
            "create table extension_command_pack_pending ( \
               control_revision integer primary key, \
               record_json, record_digest, record_mac, link_json, link_digest, link_mac);",
        )
        .expect("pending schema");
}

fn snapshot(connection: &Connection, revision: i64) {
    connection
        .execute(
            "insert into extension_control_authority_snapshot values (1, ?1, 'snap', 'sd', 'sm')",
            params![revision],
        )
        .expect("snapshot");
}

fn transition(connection: &Connection, revision: i64, snapshot: &str) {
    connection
        .execute(
            "insert into extension_control_authority_transition \
             values (?1, ?2, 'd', 'm', 'tr', 'td', 'tm')",
            params![revision, snapshot],
        )
        .expect("transition");
}

fn call(connection: &Connection, method: &str, args: Value) -> Value {
    let Value::Object(map) = args else {
        panic!("object args");
    };
    dispatch(connection, method, &Args(&map)).expect("read")
}

fn evidence(connection: &Connection, observed: Value) -> Value {
    call(
        connection,
        "command_pack_legacy_evidence_rows",
        json!({"observed_revision": observed}),
    )
}

fn page(connection: &Connection, below: i64, before: Value) -> Value {
    call(
        connection,
        "command_pack_legacy_history_page",
        json!({"below_revision": below, "before": before}),
    )
}

#[test]
fn both_reads_are_routed_as_snapshots() {
    for method in [
        "command_pack_legacy_evidence_rows",
        "command_pack_legacy_history_page",
    ] {
        assert!(handles(method));
        assert!(matches!(method_kind(method), Some(Kind::Snapshot)));
    }
    assert!(!handles("list_command_pack_pending_records"));
}

#[test]
fn a_store_without_the_snapshot_table_is_refused() {
    assert_eq!(
        evidence(&store(), Value::Null),
        json!({"state": "schema_missing"})
    );
}

#[test]
fn an_empty_store_has_no_evidence() {
    let connection = store();
    schema(&connection);
    assert_eq!(
        evidence(&connection, json!(4)),
        json!({"state": "present", "snapshot": null, "pending": null, "transition": null})
    );
}

#[test]
fn the_snapshot_comes_back_as_stored_with_its_revision() {
    let connection = store();
    schema(&connection);
    snapshot(&connection, 7);
    assert_eq!(
        evidence(&connection, Value::Null)["snapshot"],
        json!({"record": "snap", "digest": "sd", "mac": "sm", "revision": 7})
    );
}

#[test]
fn a_snapshot_without_the_transition_table_is_refused() {
    let connection = store();
    connection
        .execute_batch(
            "create table extension_control_authority_snapshot ( \
               singleton integer primary key, revision, \
               snapshot_json, snapshot_digest, snapshot_mac);",
        )
        .expect("schema");
    snapshot(&connection, 3);
    assert_eq!(
        evidence(&connection, Value::Null),
        json!({"state": "schema_missing"})
    );
}

#[test]
fn the_observed_revision_selects_its_pending_row_and_transition() {
    let connection = store();
    schema(&connection);
    pending_table(&connection);
    snapshot(&connection, 4);
    transition(&connection, 5, "next");
    connection
        .execute(
            "insert into extension_command_pack_pending \
             values (5, 'act', 'ad', 'am', 'lnk', 'ld', 'lm')",
            [],
        )
        .expect("pending");
    let answer = evidence(&connection, json!(5));
    assert_eq!(
        answer["pending"],
        json!({
            "activation": {"record": "act", "digest": "ad", "mac": "am"},
            "link": {"record": "lnk", "digest": "ld", "mac": "lm"},
        })
    );
    assert_eq!(
        answer["transition"],
        json!({
            "transition": {"record": "tr", "digest": "td", "mac": "tm"},
            "snapshot": {"record": "next", "digest": "d", "mac": "m"},
        })
    );
}

#[test]
fn no_pending_row_means_no_transition_is_read() {
    let connection = store();
    schema(&connection);
    pending_table(&connection);
    transition(&connection, 5, "next");
    let answer = evidence(&connection, json!(5));
    assert_eq!(answer["pending"], Value::Null);
    assert_eq!(answer["transition"], Value::Null);
}

#[test]
fn without_an_observed_revision_no_pending_row_is_read() {
    let connection = store();
    schema(&connection);
    pending_table(&connection);
    connection
        .execute(
            "insert into extension_command_pack_pending \
             values (5, 'act', 'ad', 'am', 'lnk', 'ld', 'lm')",
            [],
        )
        .expect("pending");
    assert_eq!(evidence(&connection, Value::Null)["pending"], Value::Null);
}

#[test]
fn a_blob_cell_reads_as_null() {
    let connection = store();
    schema(&connection);
    connection
        .execute(
            "insert into extension_control_authority_snapshot values (1, 2, ?1, 'sd', 'sm')",
            params![b"snap".to_vec()],
        )
        .expect("snapshot");
    assert_eq!(
        evidence(&connection, Value::Null)["snapshot"]["record"],
        Value::Null
    );
}

#[test]
fn history_pages_newest_first_below_the_revision() {
    let connection = store();
    schema(&connection);
    for revision in 1..=4 {
        transition(&connection, revision, &format!("s{revision}"));
    }
    let answer = page(&connection, 4, Value::Null);
    let records: Vec<&str> = answer["items"]
        .as_array()
        .expect("items")
        .iter()
        .filter_map(|item| item["record"].as_str())
        .collect();
    assert_eq!(records, ["s3", "s2", "s1"]);
    assert_eq!(answer["next"], Value::Null);
}

#[test]
fn a_history_page_stops_at_its_budget_and_names_the_next() {
    let connection = store();
    schema(&connection);
    let big = "x".repeat(HISTORY_PAGE_BYTES / 2);
    for revision in 1..=3 {
        transition(&connection, revision, &big);
    }
    let first = page(&connection, 10, Value::Null);
    assert_eq!(first["items"].as_array().expect("items").len(), 1);
    assert_eq!(first["next"], json!(3));
    let second = page(&connection, 10, first["next"].clone());
    assert_eq!(second["items"].as_array().expect("items").len(), 1);
    assert_eq!(second["next"], json!(2));
    let last = page(&connection, 10, second["next"].clone());
    assert_eq!(last["items"].as_array().expect("items").len(), 1);
    assert_eq!(last["next"], Value::Null);
}

#[test]
fn a_full_page_of_small_rows_names_the_next() {
    let connection = store();
    schema(&connection);
    for revision in 1..=300 {
        transition(&connection, revision, "s");
    }
    let first = page(&connection, 301, Value::Null);
    assert_eq!(first["items"].as_array().expect("items").len(), 256);
    assert_eq!(first["next"], json!(45));
    let rest = page(&connection, 301, first["next"].clone());
    assert_eq!(rest["items"].as_array().expect("items").len(), 44);
    assert_eq!(rest["next"], Value::Null);
}

#[test]
fn history_without_the_transition_table_is_refused() {
    assert_eq!(
        page(&store(), 3, Value::Null),
        json!({"state": "schema_missing"})
    );
}

#[test]
fn a_non_integer_revision_argument_is_refused() {
    let mut args = Map::new();
    args.insert("observed_revision".to_owned(), json!("5"));
    assert!(dispatch(&store(), "command_pack_legacy_evidence_rows", &Args(&args)).is_err());
    let mut args = Map::new();
    args.insert("before".to_owned(), json!(1));
    assert!(dispatch(&store(), "command_pack_legacy_history_page", &Args(&args)).is_err());
}

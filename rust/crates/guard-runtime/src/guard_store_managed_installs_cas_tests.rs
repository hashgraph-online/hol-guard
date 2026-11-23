//! The transition rows move together or not at all, as the Python
//! transaction moved them.

use super::*;
use rusqlite::Connection;

fn store() -> Connection {
    let connection = Connection::open_in_memory().unwrap();
    connection
        .execute_batch(
            "create table managed_installs (
               harness text primary key, active integer not null, workspace text,
               manifest_json text not null, updated_at text not null);
             create table sync_state (
               state_key text primary key, payload_json text not null, updated_at text);
             insert into managed_installs values
               ('codex', 1, '/w', '{\"b\": 1, \"a\": [2]}', 't0');",
        )
        .unwrap();
    connection
}

fn call(
    connection: &Connection,
    op: fn(&Connection, &Args<'_>) -> StoreResult<Value>,
    args: Value,
) -> StoreResult<Value> {
    let Value::Object(args) = args else {
        unreachable!()
    };
    op(connection, &Args(&args))
}

fn stored_codex() -> Value {
    json!({"harness": "codex", "active": true, "workspace": "/w",
           "manifest": {"a": [2], "b": 1}, "updated_at": "t0"})
}

fn replacement(harness: &str) -> Value {
    json!({"harness": harness, "active": false, "workspace": null,
           "manifest_json": "{\"c\": 3}", "updated_at": "t1"})
}

fn rows(connection: &Connection) -> Vec<(String, i64, String)> {
    let mut statement = connection
        .prepare("select harness, active, manifest_json from managed_installs order by harness")
        .unwrap();
    statement
        .query_map([], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)))
        .unwrap()
        .map(Result::unwrap)
        .collect()
}

fn revision(connection: &Connection) -> i64 {
    super::super::read_revision(connection).unwrap()
}

#[test]
fn matching_rows_are_written_together_and_bump_the_revision_once() {
    let connection = store();
    let changes = json!([
        {"harness": "codex", "allowed": [stored_codex()], "replacement": replacement("codex")},
        {"harness": "cursor", "allowed": [null], "replacement": replacement("cursor")},
    ]);
    assert_eq!(
        call(&connection, compare, json!({"changes": changes})).unwrap(),
        Value::Bool(true)
    );
    let answer = call(
        &connection,
        compare_and_set,
        json!({"changes": changes, "now": "t1"}),
    )
    .unwrap();
    assert_eq!(answer, Value::Bool(true));
    assert_eq!(
        rows(&connection),
        vec![
            ("codex".to_owned(), 0, "{\"c\": 3}".to_owned()),
            ("cursor".to_owned(), 0, "{\"c\": 3}".to_owned()),
        ]
    );
    assert_eq!(revision(&connection), 1);
}

#[test]
fn one_moved_row_writes_nothing() {
    let connection = store();
    let mut moved = stored_codex();
    moved["updated_at"] = Value::from("t9");
    let changes = json!([
        {"harness": "cursor", "allowed": [null], "replacement": replacement("cursor")},
        {"harness": "codex", "allowed": [moved], "replacement": null},
    ]);
    assert_eq!(
        call(&connection, compare, json!({"changes": changes})).unwrap(),
        Value::Bool(false)
    );
    let answer = call(
        &connection,
        compare_and_set,
        json!({"changes": changes, "now": "t1"}),
    )
    .unwrap();
    assert_eq!(answer, Value::Bool(false));
    assert_eq!(rows(&connection).len(), 1);
    assert_eq!(revision(&connection), 0);
}

#[test]
fn an_inverse_accepts_either_allowed_row_and_deletes() {
    let connection = store();
    let changes = json!([
        {"harness": "codex", "allowed": [null, stored_codex()], "replacement": null},
    ]);
    let answer = call(
        &connection,
        compare_and_set,
        json!({"changes": changes, "now": "t1"}),
    )
    .unwrap();
    assert_eq!(answer, Value::Bool(true));
    assert!(rows(&connection).is_empty());
}

#[test]
fn malformed_changes_are_refused() {
    let connection = store();
    for changes in [
        json!([]),
        json!([{"harness": "codex", "allowed": [], "replacement": null}]),
        json!([{"harness": "codex", "allowed": [null], "replacement": replacement("cursor")}]),
        json!([{"harness": "codex", "allowed": [null], "replacement": {"harness": "codex"}}]),
        json!([{"harness": "codex", "allowed": ["row"], "replacement": null}]),
        json!([
            {"harness": "codex", "allowed": [null], "replacement": null},
            {"harness": "codex", "allowed": [null], "replacement": null},
        ]),
    ] {
        let answer = call(
            &connection,
            compare_and_set,
            json!({"changes": changes, "now": "t1"}),
        );
        assert!(answer.is_err(), "{changes}");
    }
    assert_eq!(rows(&connection).len(), 1);
}

#[test]
fn an_unreadable_stored_manifest_fails_the_call() {
    let connection = store();
    connection
        .execute_batch("update managed_installs set manifest_json = '{' where harness = 'codex'")
        .unwrap();
    let changes = json!([{"harness": "codex", "allowed": [null], "replacement": null}]);
    assert!(call(&connection, compare, json!({"changes": changes})).is_err());
}

#[test]
fn only_the_transition_write_commits_at_full_durability() {
    assert!(super::super::durable("compare_and_set_managed_installs"));
    assert!(!super::super::durable("set_managed_install"));
    assert!(super::super::handles("compare_managed_installs"));
}

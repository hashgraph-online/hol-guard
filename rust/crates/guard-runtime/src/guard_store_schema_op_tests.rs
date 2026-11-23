use rusqlite::Connection;
use serde_json::{json, Map, Value};

use super::{dispatch, handles, METHOD};
use crate::guard_store_args::Args;

const NOW: &str = "2026-11-23T00:00:00+00:00";

fn args() -> Map<String, Value> {
    let mut args = Map::new();
    args.insert("now".to_owned(), Value::from(NOW));
    args
}

fn shape(connection: &Connection) -> Vec<(String, String, Option<String>)> {
    let mut statement = connection
        .prepare("select type, name, sql from sqlite_master order by type, name")
        .unwrap();
    let rows = statement
        .query_map([], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)))
        .unwrap();
    rows.map(Result::unwrap).collect()
}

fn versions(connection: &Connection) -> Vec<i64> {
    let mut statement = connection
        .prepare("select version from schema_migrations order by version")
        .unwrap();
    let rows = statement.query_map([], |row| row.get(0)).unwrap();
    rows.map(Result::unwrap).collect()
}

#[test]
fn only_its_own_method_is_handled() {
    assert!(handles(METHOD));
    assert!(!handles("ensure_schema_tail"));
}

#[test]
fn a_new_store_gets_the_whole_schema_once() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("guard.db");
    std::fs::File::create(&path).unwrap();
    let connection = Connection::open(&path).unwrap();
    let args = args();

    let first = dispatch(&connection, &Args(&args)).unwrap();
    assert_eq!(first, json!({ "created": true }));
    let auto_vacuum: i64 = connection
        .pragma_query_value(None, "auto_vacuum", |row| row.get(0))
        .unwrap();
    assert_eq!(auto_vacuum, 2);
    let journal: String = connection
        .pragma_query_value(None, "journal_mode", |row| row.get(0))
        .unwrap();
    assert_eq!(journal, "wal");
    assert!(connection.is_autocommit());
    let built = shape(&connection);
    assert!(built
        .iter()
        .any(|(_, name, _)| name == "guard_review_outbox_events"));
    assert!(versions(&connection).contains(&2));

    let second = dispatch(&connection, &Args(&args)).unwrap();
    assert_eq!(second, json!({ "created": false }));
    assert_eq!(shape(&connection), built);
}

#[test]
fn a_failed_chain_leaves_the_store_as_it_was() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("guard.db");
    let connection = Connection::open(&path).unwrap();
    // A view under a table name the base creates makes the chain fail.
    connection
        .execute_batch("create view guard_storage_maintenance as select 1 as one")
        .unwrap();
    let before = shape(&connection);

    assert!(dispatch(&connection, &Args(&args())).is_err());
    assert!(connection.is_autocommit());
    assert_eq!(shape(&connection), before);
}

#[test]
fn a_missing_instant_is_refused_before_anything_is_written() {
    let connection = Connection::open_in_memory().unwrap();
    assert!(dispatch(&connection, &Args(&Map::new())).is_err());
    assert!(shape(&connection).is_empty());
}

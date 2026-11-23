use rusqlite::Connection;

use super::columns::table_columns;
use super::create_base;
use super::evidence::{ensure_evidence, ensure_extension_control};

fn fresh() -> Connection {
    let connection = Connection::open_in_memory().expect("open");
    create_base(&connection).expect("base");
    connection
}

fn index_count(connection: &Connection) -> i64 {
    connection
        .query_row(
            "select count(*) from sqlite_master where type = 'index' \
             and tbl_name = 'guard_evidence' and name like 'idx_evidence_%'",
            [],
            |row| row.get(0),
        )
        .expect("count")
}

fn marker(connection: &Connection) -> (i64, String) {
    connection
        .query_row(
            "select version, checksum from extension_control_schema_migration",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .expect("marker")
}

#[test]
fn a_fresh_store_gains_the_evidence_table_and_indexes() {
    let connection = fresh();
    ensure_evidence(&connection).expect("evidence");
    ensure_evidence(&connection).expect("again");
    assert!(table_columns(&connection, "guard_evidence")
        .expect("columns")
        .contains("action_identity"));
    assert_eq!(index_count(&connection), 11);
}

#[test]
fn an_older_evidence_table_gains_the_identity_column() {
    let connection = fresh();
    connection
        .execute_batch("drop table if exists guard_evidence")
        .expect("drop");
    connection
        .execute_batch(
            "create table guard_evidence (evidence_id text not null primary key, \
             action_id text not null default '', request_id text not null default '', \
             harness text not null default '', workspace text not null default '', \
             signal_id text not null default '', category text not null default '', \
             severity text not null default '', confidence real not null default 0.0, \
             summary text not null default '', details_json text not null default '{}', \
             created_at text not null)",
        )
        .expect("legacy table");
    ensure_evidence(&connection).expect("evidence");
    assert!(table_columns(&connection, "guard_evidence")
        .expect("columns")
        .contains("action_identity"));
    assert_eq!(index_count(&connection), 11);
}

#[test]
fn a_fresh_store_gains_the_extension_control_schema() {
    let connection = fresh();
    assert!(ensure_extension_control(&connection).expect("schema"));
    assert!(ensure_extension_control(&connection).expect("again"));
    assert_eq!(marker(&connection).0, 4);
    assert!(
        !table_columns(&connection, "extension_control_authority_epoch")
            .expect("columns")
            .is_empty()
    );
}

#[test]
fn an_unknown_extension_control_marker_is_left_alone() {
    let connection = fresh();
    connection
        .execute_batch(
            "create table extension_control_schema_migration (\
             singleton integer primary key check (singleton = 1), \
             version integer not null, checksum text not null); \
             insert into extension_control_schema_migration values (1, 99, 'forged')",
        )
        .expect("forged marker");
    assert!(!ensure_extension_control(&connection).expect("left alone"));
    assert_eq!(marker(&connection), (99, "forged".to_owned()));
    assert!(
        table_columns(&connection, "extension_control_authority_snapshot")
            .expect("columns")
            .is_empty()
    );
}

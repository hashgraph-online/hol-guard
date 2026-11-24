use rusqlite::Connection;

use super::columns::table_columns;
use super::{
    create_base, upgrade_approval_requests, upgrade_client_attachments, upgrade_policy_decisions,
    upgrade_runtime_receipts,
};

fn upgrade(connection: &Connection) {
    upgrade_policy_decisions(connection).expect("policy");
    upgrade_runtime_receipts(connection).expect("receipts");
    upgrade_approval_requests(connection).expect("approvals");
    upgrade_client_attachments(connection).expect("attachments");
}

fn shape(connection: &Connection) -> Vec<(String, String)> {
    let mut statement = connection
        .prepare(
            "select name, coalesce(sql, '') from sqlite_master \
             where name not like 'sqlite_%' order by type, name",
        )
        .expect("prepare");
    statement
        .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))
        .expect("query")
        .collect::<Result<_, _>>()
        .expect("rows")
}

#[test]
fn a_legacy_store_gains_every_listed_column() {
    let connection = Connection::open_in_memory().expect("open");
    connection
        .execute_batch(
            "create table policy_decisions (decision_id integer primary key, action text, \
               harness text, artifact_id text, scope text, workspace text, updated_at text);
             create table guard_local_once_approvals (request_id text, claimed_at text, \
               expires_at text);
             create table runtime_receipts (receipt_id text primary key);
             create table approval_requests (request_id text primary key);
             create table guard_client_attachments (client_id text primary key);",
        )
        .expect("legacy");
    upgrade(&connection);
    let has = |table: &str, column: &str| {
        table_columns(&connection, table)
            .expect("columns")
            .contains(column)
    };
    assert!(has("policy_decisions", "policy_provenance_json"));
    assert!(has("guard_local_once_approvals", "authority_kind"));
    assert!(has("runtime_receipts", "raw_command_text"));
    assert!(has("approval_requests", "extension_allow_hint_json"));
    assert!(has("guard_client_attachments", "lease_expires_at"));
    let default: String = connection
        .query_row(
            "select dflt_value from pragma_table_info('policy_decisions') where name = 'source'",
            [],
            |row| row.get(0),
        )
        .expect("default");
    assert_eq!(default, "'local'");
}

#[test]
fn upgrading_a_current_store_twice_changes_nothing() {
    let connection = Connection::open_in_memory().expect("open");
    create_base(&connection).expect("base");
    upgrade(&connection);
    let first = shape(&connection);
    upgrade(&connection);
    assert_eq!(shape(&connection), first);
}

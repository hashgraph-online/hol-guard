use rusqlite::Connection;

use super::super::workspace_sql::ASSESSMENT_STATEMENTS;
use super::{ensure_assessment, ensure_fix_proposal};
use crate::guard_store_db::StoreError;

const NOW: &str = "2026-01-02T03:04:05+00:00";

fn store() -> Connection {
    let connection = Connection::open_in_memory().expect("open");
    connection
        .execute_batch(
            "create table schema_migrations (version integer primary key, applied_at text not null)",
        )
        .expect("migrations");
    connection
}

fn recorded(connection: &Connection) -> Vec<i64> {
    let mut statement = connection
        .prepare("select version from schema_migrations order by version")
        .expect("prepare");
    statement
        .query_map([], |row| row.get(0))
        .expect("query")
        .collect::<Result<_, _>>()
        .expect("rows")
}

fn object_count(connection: &Connection, prefix: &str) -> i64 {
    connection
        .query_row(
            "select count(*) from sqlite_master where name like ?1 || '%'",
            [prefix],
            |row| row.get(0),
        )
        .expect("count")
}

#[test]
fn both_steps_create_their_objects_and_record_their_versions() {
    let connection = store();
    for _ in 0..2 {
        ensure_assessment(&connection, NOW).expect("assessment");
        ensure_fix_proposal(&connection, NOW).expect("fix proposal");
    }
    assert_eq!(recorded(&connection), [33, 34]);
    // Four tables, one trigger and three indexes.
    assert_eq!(object_count(&connection, "workspace_assessment"), 8);
    assert_eq!(object_count(&connection, "workspace_fix_proposals"), 2);
}

#[test]
fn generations_cannot_move_backward() {
    let connection = store();
    ensure_assessment(&connection, NOW).expect("assessment");
    let key = "k".repeat(64);
    connection
        .execute(
            "insert into workspace_assessment_state (codebase_key, worktree_key, private_root, \
             dirty_generation, admitted_at_ms) values (?1, ?1, '/root', 2, 0)",
            [&key],
        )
        .expect("state");
    let backward = connection.execute(
        "update workspace_assessment_state set dirty_generation = 1",
        [],
    );
    assert!(backward.is_err());
}

#[test]
fn a_changed_object_is_refused_and_nothing_is_recorded() {
    let connection = store();
    // A state table with one column more than this build declares.
    let widened = ASSESSMENT_STATEMENTS[0].replacen(
        "admitted_at_ms INTEGER",
        "extra_column TEXT, admitted_at_ms INTEGER",
        1,
    );
    connection.execute_batch(&widened).expect("widened state");
    connection
        .execute_batch("create table workspace_fix_proposals (proposal_id text primary key)")
        .expect("old proposals");
    let assessment = ensure_assessment(&connection, NOW);
    assert!(
        matches!(&assessment, Err(StoreError::Runtime(message))
            if message.ends_with("schema object: workspace_assessment_state")),
        "{assessment:?}"
    );
    let fix = ensure_fix_proposal(&connection, NOW);
    assert!(
        matches!(&fix, Err(StoreError::Runtime(message))
            if message.ends_with("schema object: workspace_fix_proposals")),
        "{fix:?}"
    );
    assert!(recorded(&connection).is_empty());
    assert_eq!(object_count(&connection, "workspace_assessment_runs"), 0);
}

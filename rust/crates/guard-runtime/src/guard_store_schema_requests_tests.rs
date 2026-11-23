use rusqlite::Connection;

use super::columns::table_columns;
use super::requests::ensure_requests_through_approvals;
use super::{create_base, ensure_families};

const NOW: &str = "2026-11-23T00:00:00+00:00";

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

fn versions(connection: &Connection) -> Vec<i64> {
    let mut statement = connection
        .prepare("select version from schema_migrations order by version")
        .expect("prepare");
    statement
        .query_map([], |row| row.get(0))
        .expect("query")
        .collect::<Result<_, _>>()
        .expect("rows")
}

fn fresh() -> Connection {
    let connection = Connection::open_in_memory().expect("open");
    create_base(&connection).expect("base");
    ensure_families(&connection, NOW).expect("families");
    connection
}

#[test]
fn a_fresh_store_gains_the_request_table_and_versions_four_and_five() {
    let connection = fresh();
    ensure_requests_through_approvals(&connection, NOW).expect("requests");
    let columns = table_columns(&connection, "mcp_policy_requests").expect("columns");
    assert_eq!(columns.len(), 15, "{columns:?}");
    let names: Vec<String> = shape(&connection)
        .into_iter()
        .map(|(name, _)| name)
        .collect();
    for index in [
        "idx_mcp_policy_requests_status",
        "idx_mcp_policy_requests_expires",
        "idx_mcp_policy_requests_idempotency",
        "runtime_receipt_envelopes",
    ] {
        assert!(names.iter().any(|name| name == index), "{index}");
    }
    let recorded = versions(&connection);
    assert!(
        recorded.contains(&4) && recorded.contains(&5),
        "{recorded:?}"
    );
}

#[test]
fn running_the_steps_twice_changes_nothing() {
    let connection = fresh();
    ensure_requests_through_approvals(&connection, NOW).expect("first");
    let first = (shape(&connection), versions(&connection));
    ensure_requests_through_approvals(&connection, "2027-01-01T00:00:00+00:00").expect("second");
    assert_eq!((shape(&connection), versions(&connection)), first);
}

#[test]
fn a_failed_step_keeps_none_of_the_run() {
    let connection = Connection::open_in_memory().expect("open");
    create_base(&connection).expect("base");
    // A view cannot gain the policy columns, so the policy step fails after
    // the request table, its indexes and version 4 were written.
    connection
        .execute_batch(
            "drop table policy_decisions; \
             create view policy_decisions as select 1 as artifact_id",
        )
        .expect("blocker");
    let before = (shape(&connection), versions(&connection));
    assert!(ensure_requests_through_approvals(&connection, NOW).is_err());
    assert!(connection.is_autocommit(), "no savepoint is left open");
    assert_eq!((shape(&connection), versions(&connection)), before);
}

use rusqlite::Connection;

use super::columns::table_columns;
use super::{create_base, ensure_families};
use crate::guard_store_db::StoreError;

const NOW: &str = "2026-01-02T03:04:05+00:00";

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
    connection
}

#[test]
fn a_fresh_store_gains_every_family_and_its_versions() {
    let connection = fresh();
    ensure_families(&connection, NOW).expect("families");
    for table in [
        "guard_continuation_claims",
        "guard_continuation_effects",
        "guard_bash_operations",
        "guard_workflow_capabilities",
    ] {
        assert!(
            !table_columns(&connection, table)
                .expect("columns")
                .is_empty(),
            "{table}"
        );
    }
    let recorded = versions(&connection);
    for version in [14, 22, 28, 30, 31, 32, 33, 34] {
        assert!(recorded.contains(&version), "{version}");
    }
}

#[test]
fn running_the_families_twice_changes_nothing() {
    let connection = fresh();
    ensure_families(&connection, NOW).expect("first");
    let before = (shape(&connection), versions(&connection));
    ensure_families(&connection, "2027-01-01T00:00:00+00:00").expect("second");
    assert_eq!((shape(&connection), versions(&connection)), before);
}

#[test]
fn legacy_resume_and_receipt_tables_gain_their_columns() {
    let connection = Connection::open_in_memory().expect("open");
    connection
        .execute_batch(
            "create table schema_migrations (version integer primary key, applied_at text not null);
             create table guard_request_resumes (request_id text primary key);
             create table guard_continuation_claims (request_id text, offer_hash text, \
               action text, state text, claimed_at text, evidence_id text, \
               primary key (request_id, offer_hash, action));
             create table native_hook_decision_receipts (decision_id text primary key);
             insert into native_hook_decision_receipts values ('d1');",
        )
        .expect("legacy");
    super::families::ensure_receipt_binding(&connection, NOW).expect("binding");
    super::families::ensure_resume(&connection).expect("resume");
    let resumes = table_columns(&connection, "guard_request_resumes").expect("resumes");
    for (name, _) in super::families::RESUME_CONTINUATION_COLUMNS {
        assert!(resumes.contains(name), "{name}");
    }
    let claims = table_columns(&connection, "guard_continuation_claims").expect("claims");
    assert!(claims.contains("lease_expires_at") && claims.contains("claim_id"));
    let binding: Option<String> = connection
        .query_row(
            "select command_extensions_json from native_hook_decision_receipts",
            [],
            |row| row.get(0),
        )
        .expect("legacy row");
    assert_eq!(binding, None, "an old row gets no invented binding");
    assert_eq!(versions(&connection), vec![28]);
}

#[test]
fn a_changed_bash_table_is_refused_and_rolled_back() {
    let connection = fresh();
    connection
        .execute_batch("create table guard_bash_operations (operation_id text primary key)")
        .expect("tampered");
    let error = super::families::ensure_bash_operations(&connection, NOW).expect_err("refused");
    match error {
        StoreError::Runtime(message) => assert_eq!(
            message,
            "incompatible command activity Bash operation schema object: guard_bash_operations"
        ),
        other => panic!("unexpected {other:?}"),
    }
    assert!(!versions(&connection).contains(&30));
    assert!(table_columns(&connection, "guard_bash_reviews")
        .expect("reviews")
        .is_empty());
}

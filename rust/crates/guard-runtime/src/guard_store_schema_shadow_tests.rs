use rusqlite::Connection;

use super::super::shadow_sql::{CURRENT, LEGACY, PREVIOUS_EVALUATIONS};
use super::{ensure_shadow, names_owned_table};
use crate::guard_store_db::StoreError;

const NOW: &str = "2026-01-02T03:04:05+00:00";
const EVALUATION: &str = "insert into command_activity_shadow_evaluations values (
    'a1', 't1', 'allow', 'allow', 'silent-verified', 'review', 'review', 'strengthened',
    'proposal-1', '1.0.0', 1, 100, 'guard.command-shadow.v1')";

fn store() -> Connection {
    let connection = Connection::open_in_memory().expect("open");
    connection
        .execute_batch(
            "create table schema_migrations (version integer primary key, applied_at text not null);
             create table command_activity (activity_id text primary key, occurred_at text not null);
             insert into command_activity values ('a1', 't1');",
        )
        .expect("base");
    connection
}

fn build(connection: &Connection, statements: &[&str]) {
    for statement in statements {
        connection.execute_batch(statement).expect("statement");
    }
}

fn shape(connection: &Connection) -> Vec<(String, String)> {
    let mut statement = connection
        .prepare(
            "select name, sql from sqlite_master where name like '%command_activity_shadow%' \
             order by name",
        )
        .expect("prepare");
    statement
        .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))
        .expect("query")
        .collect::<Result<_, _>>()
        .expect("rows")
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

fn refused(connection: &Connection) -> String {
    match ensure_shadow(connection, NOW) {
        Err(StoreError::Runtime(message)) => message,
        other => panic!("expected a refusal, got {other:?}"),
    }
}

#[test]
fn a_fresh_store_gains_the_current_objects_once() {
    let connection = store();
    ensure_shadow(&connection, NOW).expect("first");
    let first = shape(&connection);
    assert_eq!(first.len(), CURRENT.len());
    assert_eq!(recorded(&connection), vec![15, 17, 18]);
    ensure_shadow(&connection, NOW).expect("second");
    assert_eq!(shape(&connection), first);
}

#[test]
fn a_version_17_store_is_upgraded_with_its_rows() {
    let connection = store();
    let previous: Vec<&str> = std::iter::once(PREVIOUS_EVALUATIONS)
        .chain(CURRENT[1..].iter().copied())
        .collect();
    build(&connection, &previous);
    connection.execute_batch(EVALUATION).expect("evaluation");
    connection
        .execute_batch(
            "insert into command_activity_shadow_cohorts values ('a1', 0, 'baseline');
             insert into command_activity_shadow_cohorts values ('a1', 1, 'cdx-060-verified-reads');",
        )
        .expect("cohorts");
    ensure_shadow(&connection, NOW).expect("upgrade");
    let fresh = store();
    ensure_shadow(&fresh, NOW).expect("fresh");
    assert_eq!(shape(&connection), shape(&fresh));
    let cohorts: Vec<String> = connection
        .prepare("select cohort from command_activity_shadow_cohorts order by ordinal")
        .expect("prepare")
        .query_map([], |row| row.get(0))
        .expect("query")
        .collect::<Result<_, _>>()
        .expect("rows");
    assert_eq!(cohorts, ["baseline", "cdx-060-verified-reads"]);
    let proposed: String = connection
        .query_row(
            "select proposed_action from command_activity_shadow_evaluations",
            [],
            |row| row.get(0),
        )
        .expect("evaluation kept");
    assert_eq!(proposed, "review");
    assert_eq!(recorded(&connection), vec![15, 17, 18]);
}

#[test]
fn a_version_15_store_is_upgraded_to_the_current_objects() {
    let connection = store();
    build(&connection, &LEGACY);
    ensure_shadow(&connection, NOW).expect("upgrade");
    let fresh = store();
    ensure_shadow(&fresh, NOW).expect("fresh");
    assert_eq!(shape(&connection), shape(&fresh));
}

#[test]
fn a_hand_changed_index_is_refused_and_nothing_is_kept() {
    let connection = store();
    build(&connection, &CURRENT);
    connection
        .execute_batch(
            "drop index idx_command_activity_shadow_cohort;
             create index idx_command_activity_shadow_cohort on command_activity_shadow_cohorts (cohort)",
        )
        .expect("edit");
    let before = shape(&connection);
    assert_eq!(
        refused(&connection),
        "incompatible command shadow schema objects"
    );
    assert_eq!(shape(&connection), before);
    assert!(recorded(&connection).is_empty());
}

#[test]
fn an_outside_table_pointing_at_a_shadow_table_is_refused() {
    let connection = store();
    connection
        .execute_batch(
            "create table notes (activity_id text references command_activity_shadow_evaluations(activity_id))",
        )
        .expect("notes");
    assert_eq!(
        refused(&connection),
        "incompatible command shadow external foreign key"
    );
    assert!(shape(&connection).is_empty());
}

#[test]
fn an_outside_view_over_a_shadow_table_is_refused() {
    let connection = store();
    build(&connection, &CURRENT);
    connection
        .execute_batch("create view shadow_rows as select * from command_activity_shadow_cohorts")
        .expect("view");
    assert_eq!(
        refused(&connection),
        "incompatible command shadow external schema dependency"
    );
    assert!(recorded(&connection).is_empty());
}

#[test]
fn only_whole_owned_names_count_as_a_dependency() {
    assert!(names_owned_table(
        "select * from command_activity_shadow_cohorts"
    ));
    assert!(names_owned_table(
        "select * from main.command_activity_shadow_evaluations;"
    ));
    assert!(!names_owned_table(
        "select * from command_activity_shadow_cohorts_v15"
    ));
    assert!(!names_owned_table(
        "select * from xcommand_activity_shadow_cohorts"
    ));
    assert!(!names_owned_table("select * from command_activity"));
}

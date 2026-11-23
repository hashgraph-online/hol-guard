use rusqlite::Connection;

use super::{base_statements, create_base};

fn objects(connection: &Connection) -> Vec<(String, String, String)> {
    let mut statement = connection
        .prepare(
            "select type, name, coalesce(sql, '') from sqlite_master \
             where name not like 'sqlite_%' order by type, name",
        )
        .expect("prepare");
    statement
        .query_map([], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)))
        .expect("query")
        .collect::<Result<_, _>>()
        .expect("rows")
}

#[test]
fn the_base_creates_every_table_index_and_trigger() {
    let connection = Connection::open_in_memory().expect("open");
    create_base(&connection).expect("create");
    let created = objects(&connection);
    let count = |kind: &str| created.iter().filter(|(k, _, _)| k == kind).count();
    // 39 create-table statements, but `guard_connect_states` is listed twice
    // and the second `if not exists` creates nothing.
    assert_eq!(count("table"), 38);
    assert_eq!(count("index"), 12);
    assert_eq!(count("trigger"), 6);
    assert_eq!(base_statements().count(), 60);
}

#[test]
fn running_the_base_twice_changes_nothing() {
    let connection = Connection::open_in_memory().expect("open");
    create_base(&connection).expect("first");
    let first = objects(&connection);
    let migrations: i64 = connection
        .query_row("select count(*) from schema_migrations", [], |row| {
            row.get(0)
        })
        .expect("count");
    create_base(&connection).expect("second");
    assert_eq!(objects(&connection), first);
    let again: i64 = connection
        .query_row("select count(*) from schema_migrations", [], |row| {
            row.get(0)
        })
        .expect("count");
    assert_eq!(again, migrations);
}

#[test]
fn a_failed_base_run_leaves_no_partial_schema() {
    let connection = Connection::open_in_memory().expect("open");
    // A view under a base table's name makes that table's statement fail
    // part-way through the run.
    connection
        .execute_batch("create view schema_migrations as select 1 as version")
        .expect("blocker");
    assert!(create_base(&connection).is_err());
    let names: Vec<(String, String, String)> = objects(&connection);
    assert_eq!(names.len(), 1, "{names:?}");
}

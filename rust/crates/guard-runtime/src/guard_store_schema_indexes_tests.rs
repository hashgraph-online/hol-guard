use rusqlite::Connection;

use super::{
    create_approval_indexes, create_base, create_cache_indexes, create_receipt_rollups,
    create_storage_maintenance, upgrade_approval_requests, upgrade_client_attachments,
    upgrade_policy_decisions, upgrade_runtime_receipts,
};

fn build(connection: &Connection) {
    create_base(connection).expect("base");
    create_cache_indexes(connection).expect("cache indexes");
    upgrade_policy_decisions(connection).expect("policy");
    upgrade_runtime_receipts(connection).expect("receipts");
    upgrade_approval_requests(connection).expect("approvals");
    create_approval_indexes(connection).expect("approval indexes");
    create_receipt_rollups(connection).expect("rollups");
    upgrade_client_attachments(connection).expect("attachments");
    create_storage_maintenance(connection).expect("maintenance");
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

fn count(connection: &Connection, sql: &str) -> i64 {
    connection
        .query_row(sql, [], |row| row.get(0))
        .expect("count")
}

#[test]
fn the_index_steps_build_on_the_upgraded_tables() {
    let connection = Connection::open_in_memory().expect("open");
    build(&connection);
    let names: Vec<String> = shape(&connection)
        .into_iter()
        .map(|(name, _)| name)
        .collect();
    for expected in [
        "idx_ti_match_severity",
        "idx_supply_chain_eval_updated_at",
        "guard_storage_maintenance",
    ] {
        assert!(names.iter().any(|name| name == expected), "{expected}");
    }
    assert_eq!(
        count(
            &connection,
            "select count(*) from guard_storage_maintenance"
        ),
        1
    );
}

#[test]
fn building_twice_changes_nothing() {
    let connection = Connection::open_in_memory().expect("open");
    build(&connection);
    let first = shape(&connection);
    build(&connection);
    assert_eq!(shape(&connection), first);
    assert_eq!(
        count(
            &connection,
            "select count(*) from guard_storage_maintenance"
        ),
        1
    );
}

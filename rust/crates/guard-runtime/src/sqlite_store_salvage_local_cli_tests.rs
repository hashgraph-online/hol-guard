use rusqlite::Connection;

use super::super::tests::{count, execute, stores, Stores, LOCAL_CLI_SCHEMA};
use super::*;

fn local_cli_source(stores: &Stores) {
    execute(
        &stores.source,
        "insert into local_cli_authority values ('cli-1', 3);
         insert into local_cli_observation values ('cli-1', 'cli');
         insert into local_cli_grant values ('cli-1', 'allowed');
         insert into local_cli_command values ('cli-1', 'navigate');
         insert into local_cli_command values ('cli-1', 'other');
         insert into local_cli_command_grant values ('cli-1', 'navigate', 'block');
         insert into local_cli_command_grant values ('cli-1', 'other', 'block');
         insert into local_cli_grant_capability values ('cli-1', 'cap');",
    );
}

#[test]
fn custom_extension_grants_copy_with_their_catalog() {
    let stores = stores(LOCAL_CLI_SCHEMA, LOCAL_CLI_SCHEMA);
    local_cli_source(&stores);

    assert!(salvage_local_cli(&stores.source, &stores.destination));
    assert_eq!(
        count(
            &stores.destination,
            "select count(*) from local_cli_grant where state = 'allowed'"
        ),
        1
    );
    assert_eq!(
        count(
            &stores.destination,
            "select count(*) from local_cli_command_grant"
        ),
        2
    );
    assert_eq!(
        count(
            &stores.destination,
            "select count(*) from local_cli_grant_capability"
        ),
        1
    );
}

#[test]
fn a_missing_required_table_restores_no_grant() {
    for table in REQUIRED_LOCAL_CLI_TABLES {
        let stores = stores(LOCAL_CLI_SCHEMA, LOCAL_CLI_SCHEMA);
        local_cli_source(&stores);
        execute(&stores.source, &format!("drop table {table}"));

        assert!(
            !salvage_local_cli(&stores.source, &stores.destination),
            "{table}"
        );
        assert_eq!(
            count(&stores.destination, "select count(*) from local_cli_grant"),
            0
        );
        assert_eq!(
            count(
                &stores.destination,
                "select count(*) from local_cli_command"
            ),
            0
        );
    }
}

#[test]
fn a_command_grant_insert_error_restores_no_grant() {
    let stricter = LOCAL_CLI_SCHEMA.replace(
        "state text not null,\n        primary key (cli_id, command_id)",
        "state text not null check (command_id <> 'other'),\n        primary key (cli_id, command_id)",
    );
    assert_ne!(stricter, LOCAL_CLI_SCHEMA);
    let stores = stores(LOCAL_CLI_SCHEMA, &stricter);
    local_cli_source(&stores);

    assert!(!salvage_local_cli(&stores.source, &stores.destination));
    assert_eq!(
        count(&stores.destination, "select count(*) from local_cli_grant"),
        0
    );
    assert_eq!(
        count(
            &stores.destination,
            "select count(*) from local_cli_command_grant"
        ),
        0
    );
}

#[test]
fn a_transaction_rolled_back_by_an_insert_error_restores_nothing() {
    // `RAISE(ROLLBACK)` ends the transaction the way `SQLITE_FULL` can. A
    // copy that kept going would commit the allowed grant row by row while
    // its command blocks fail to restore.
    let stores = stores(LOCAL_CLI_SCHEMA, LOCAL_CLI_SCHEMA);
    local_cli_source(&stores);
    execute(&stores.source, "drop table local_cli_command_grant");
    execute(
        &stores.destination,
        "create trigger lost before insert on local_cli_observation
         begin select raise(rollback, 'database or disk is full'); end;",
    );

    assert!(!salvage_local_cli(&stores.source, &stores.destination));
    for table in [
        "local_cli_authority",
        "local_cli_grant",
        "local_cli_command",
    ] {
        assert_eq!(
            count(
                &stores.destination,
                &format!("select count(*) from {table}")
            ),
            0,
            "{table}"
        );
    }
}

/// A source "table" that is a view whose second row fails to read, as a
/// damaged page does part way through a scan.
fn failing_after_first_row(table: &str, columns: &str) -> String {
    format!(
        "alter table {table} rename to {table}_rows;
         create view {table} as select {columns} from {table}_rows
         where case when rowid > 1 then abs(-9223372036854775808) else 1 end;"
    )
}

#[test]
fn a_partial_grant_scan_keeps_the_rows_read_before_the_failure() {
    let stores = stores(LOCAL_CLI_SCHEMA, LOCAL_CLI_SCHEMA);
    local_cli_source(&stores);
    execute(
        &stores.source,
        "insert into local_cli_grant values ('cli-2', 'allowed');",
    );
    execute(
        &stores.source,
        &failing_after_first_row("local_cli_grant", "cli_id, state"),
    );
    let src = Connection::open(&stores.source).expect("source");
    let dst = Connection::open(&stores.destination).expect("destination");

    assert_eq!(
        copy_allowlisted_table(&src, &dst, "local_cli_grant"),
        Some(true)
    );
    assert_eq!(
        count(&stores.destination, "select count(*) from local_cli_grant"),
        1
    );
}

#[test]
fn a_partial_command_grant_scan_restores_no_grant() {
    let stores = stores(LOCAL_CLI_SCHEMA, LOCAL_CLI_SCHEMA);
    local_cli_source(&stores);
    execute(
        &stores.source,
        &failing_after_first_row("local_cli_command_grant", "cli_id, command_id, state"),
    );

    assert!(!salvage_local_cli(&stores.source, &stores.destination));
    assert_eq!(
        count(&stores.destination, "select count(*) from local_cli_grant"),
        0
    );
    assert_eq!(
        count(
            &stores.destination,
            "select count(*) from local_cli_command_grant"
        ),
        0
    );
}

#[test]
fn a_capability_without_its_cli_observation_is_dropped() {
    let stores = stores(LOCAL_CLI_SCHEMA, LOCAL_CLI_SCHEMA);
    local_cli_source(&stores);
    execute(
        &stores.source,
        "update local_cli_observation set surface = 'mcp'",
    );

    assert!(salvage_local_cli(&stores.source, &stores.destination));
    assert_eq!(
        count(&stores.destination, "select count(*) from local_cli_grant"),
        1
    );
    assert_eq!(
        count(
            &stores.destination,
            "select count(*) from local_cli_grant_capability"
        ),
        0
    );
}

#[cfg(unix)]
#[test]
fn linked_stores_are_refused() {
    let stores = stores(LOCAL_CLI_SCHEMA, LOCAL_CLI_SCHEMA);
    local_cli_source(&stores);
    let linked = stores.destination.with_file_name("linked.db");
    std::os::unix::fs::symlink(&stores.source, &linked).expect("symlink");

    assert!(!salvage_local_cli(&linked, &stores.destination));
    assert!(!salvage_local_cli(&stores.source, &linked));
    assert_eq!(
        count(&stores.destination, "select count(*) from local_cli_grant"),
        0
    );
}

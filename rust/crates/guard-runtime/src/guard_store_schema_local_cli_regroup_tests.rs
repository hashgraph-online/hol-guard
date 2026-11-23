use rusqlite::Connection;

use super::{regroup, NON_RECOGNITION_RISK_SUMMARIES};
use crate::connector_setup::queue_group_id;

const APPROVALS: &str = "create table approval_requests (
    request_id text primary key, status text not null, risk_summary text,
    raw_command_text text, queue_group_id text, workspace text, created_at text)";
const OBSERVATIONS: &str = "create table local_cli_observation (
    cli_id text primary key, identity_hash text not null, kind text not null,
    name text not null, interpreter_name text, example_label text not null,
    surface text not null, source_path text);
    insert into local_cli_observation values
        ('lane', 'lane-hash', 'executable', 'lanectl', null, 'lanectl', 'cli', null),
        ('kept', 'kept-hash', 'executable', 'keptctl', null, 'keptctl', 'cli', null);
    create table local_cli_grant (cli_id text, identity_hash text, state text);
    insert into local_cli_grant values ('kept', 'kept-hash', 'allowed');";
const WORKSPACE: &str = "/work/items";

fn store() -> Connection {
    let connection = Connection::open_in_memory().expect("open");
    connection.execute_batch(APPROVALS).expect("approvals");
    connection
        .execute_batch(OBSERVATIONS)
        .expect("observations");
    connection
}

fn review(connection: &Connection, id: &str, status: &str, summary: &str, command: &str) {
    connection
        .execute(
            "insert into approval_requests values (?1, ?2, ?3, ?4, 'action:old', ?5, ?1)",
            (id, status, summary, command, WORKSPACE),
        )
        .expect("review");
}

fn group(connection: &Connection, id: &str) -> String {
    connection
        .query_row(
            "select queue_group_id from approval_requests where request_id = ?1",
            [id],
            |row| row.get(0),
        )
        .expect("group")
}

#[test]
fn only_pending_setup_reviews_for_an_undecided_cli_move() {
    let connection = store();
    let [summary, ..] = NON_RECOGNITION_RISK_SUMMARIES;
    review(&connection, "a", "pending", summary, "lanectl status");
    review(
        &connection,
        "b",
        "pending",
        "another reason",
        "lanectl status",
    );
    review(&connection, "c", "approved", summary, "lanectl status");
    review(&connection, "d", "pending", summary, "keptctl status");
    review(&connection, "e", "pending", summary, "lanectl status | cat");
    assert_eq!(regroup(&connection), 1);
    assert_eq!(
        group(&connection, "a"),
        queue_group_id("lane-hash", WORKSPACE, "lanectl status")
    );
    for id in ["b", "c", "d", "e"] {
        assert_eq!(group(&connection, id), "action:old", "{id}");
    }
}

#[test]
fn a_store_without_approvals_moves_nothing() {
    let connection = Connection::open_in_memory().expect("open");
    connection
        .execute_batch(OBSERVATIONS)
        .expect("observations");
    assert_eq!(regroup(&connection), 0);
}

#[test]
fn a_store_error_leaves_every_review_where_it_was() {
    let connection = Connection::open_in_memory().expect("open");
    // No workspace or created_at column: the review read fails.
    connection
        .execute_batch(
            "create table approval_requests (request_id text, status text, \
             risk_summary text, raw_command_text text, queue_group_id text); \
             insert into approval_requests values ('a', 'pending', 'x', 'lanectl', 'action:old');",
        )
        .expect("approvals");
    connection
        .execute_batch(OBSERVATIONS)
        .expect("observations");
    assert_eq!(regroup(&connection), 0);
    assert_eq!(group(&connection, "a"), "action:old");
    connection
        .execute_batch("savepoint after; release savepoint after")
        .expect("no savepoint left open");
}

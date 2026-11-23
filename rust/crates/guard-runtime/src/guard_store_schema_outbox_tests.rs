use rusqlite::Connection;
use serde_json::Value;

use super::outbox::{ensure_review_outbox, APPROVAL_INDEX_VERSION, OUTBOX_VERSION};
use super::{create_base, ensure_families};
use crate::guard_store_outbox_identity::payload_digest;

const NOW: &str = "2026-11-23T00:00:00+00:00";

fn fresh() -> Connection {
    let connection = Connection::open_in_memory().expect("open");
    create_base(&connection).expect("base");
    ensure_families(&connection, NOW).expect("families");
    connection
}

fn insert(connection: &Connection, request_id: &str) {
    connection
        .execute(
            "insert into approval_requests (request_id, harness, artifact_id, artifact_name, \
             artifact_type, artifact_hash, policy_action, recommended_scope, \
             changed_fields_json, source_scope, config_path, review_command, approval_url, \
             status, created_at) values (?1, 'codex', 'a', 'a', 'tool', 'h', \
             'require-reapproval', 'artifact', '[]', 'global', 'c', 'r', 'u', 'pending', ?2)",
            (request_id, NOW),
        )
        .expect("insert");
}

fn count(connection: &Connection, sql: &str) -> i64 {
    connection
        .query_row(sql, [], |row| row.get(0))
        .expect("count")
}

fn events(connection: &Connection) -> Vec<(String, i64, String)> {
    let mut statement = connection
        .prepare(
            "select event_type, request_sequence, payload_hash \
             from guard_review_outbox_events order by stream_sequence",
        )
        .expect("prepare");
    statement
        .query_map([], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)))
        .expect("query")
        .collect::<Result<_, _>>()
        .expect("rows")
}

fn recorded(connection: &Connection, version: i64) -> bool {
    count(
        connection,
        &format!("select count(*) from schema_migrations where version = {version}"),
    ) == 1
}

#[test]
fn a_fresh_store_gains_the_outbox_and_versions_nine_and_twenty_five() {
    let connection = fresh();
    for table in [
        "guard_review_outbox_events",
        "guard_review_outbox_cursors",
        "guard_review_outbox_request_sequences",
        "guard_review_outbox_wake_state",
    ] {
        let sql =
            format!("select count(*) from sqlite_master where type = 'table' and name = '{table}'");
        assert_eq!(count(&connection, &sql), 1, "{table}");
    }
    assert_eq!(
        count(
            &connection,
            "select count(*) from sqlite_master where type = 'trigger' \
             and name like 'guard_review_outbox_%'"
        ),
        5
    );
    assert!(recorded(&connection, OUTBOX_VERSION));
    assert!(recorded(&connection, APPROVAL_INDEX_VERSION));
}

#[test]
fn approval_writes_append_review_events_and_wake_the_outbox() {
    let connection = fresh();
    insert(&connection, "first");
    connection
        .execute_batch("update approval_requests set status = 'approved', resolved_at = '2026-11-24T00:00:00+00:00'")
        .expect("resolve");
    let recorded = events(&connection);
    let kinds: Vec<(&str, i64)> = recorded
        .iter()
        .map(|(kind, sequence, _)| (kind.as_str(), *sequence))
        .collect();
    assert_eq!(
        kinds,
        [
            ("review.request.created", 1),
            ("review.request.resolved", 2)
        ]
    );
    assert_eq!(
        count(
            &connection,
            "select generation from guard_review_outbox_wake_state where singleton = 1"
        ),
        2
    );
}

#[test]
fn an_unrecorded_store_rewrites_every_payload_hash_once() {
    let connection = fresh();
    insert(&connection, "first");
    connection
        .execute_batch(&format!(
            "update guard_review_outbox_events set payload_hash = 'stale'; \
             delete from schema_migrations where version = {OUTBOX_VERSION}"
        ))
        .expect("forget");
    ensure_review_outbox(&connection, NOW).expect("upgrade");
    let payload: String = connection
        .query_row(
            "select payload_json from guard_review_outbox_events",
            [],
            |row| row.get(0),
        )
        .expect("payload");
    let source: Option<String> = connection
        .query_row(
            "select oauth_source from guard_review_outbox_events",
            [],
            |row| row.get(0),
        )
        .expect("source");
    let source = source.map_or(Value::Null, Value::from);
    let expected = payload_digest(
        &payload,
        [
            &source,
            &Value::Null,
            &Value::Null,
            &Value::Null,
            &Value::Null,
        ],
    );
    assert_eq!(events(&connection)[0].2, expected);
    // Once recorded, a stale hash is left for the delivery path to settle.
    connection
        .execute_batch("update guard_review_outbox_events set payload_hash = 'stale'")
        .expect("stale");
    ensure_review_outbox(&connection, NOW).expect("again");
    assert_eq!(events(&connection)[0].2, "stale");
}

#[test]
fn a_failed_step_keeps_none_of_the_run() {
    let connection = fresh();
    insert(&connection, "first");
    // A view in place of the version table lets the upgrade and the trigger
    // rebuild run, then refuses the version record.
    connection
        .execute_batch(
            "update guard_review_outbox_events set payload_hash = 'stale'; \
             drop trigger guard_review_outbox_after_insert; \
             drop table schema_migrations; \
             create view schema_migrations as select 1 as version, '' as applied_at where 0",
        )
        .expect("blocker");
    assert!(ensure_review_outbox(&connection, NOW).is_err());
    assert!(connection.is_autocommit(), "no savepoint is left open");
    assert_eq!(events(&connection)[0].2, "stale");
    assert_eq!(
        count(
            &connection,
            "select count(*) from sqlite_master where name = 'guard_review_outbox_after_insert'"
        ),
        0
    );
}

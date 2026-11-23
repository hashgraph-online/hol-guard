use rusqlite::Connection;

use super::approvals::{ensure_approval_queue, QUEUE_BACKFILL_VERSION, WATCH_ONLY_VERSION};
use super::{create_base, ensure_families};

const NOW: &str = "2026-11-23T00:00:00+00:00";
const INBOX: &str = r#"[{"source":"observe_mode_inbox"}]"#;

fn fresh() -> Connection {
    let connection = Connection::open_in_memory().expect("open");
    create_base(&connection).expect("base");
    ensure_families(&connection, NOW).expect("families");
    connection
}

fn insert(connection: &Connection, request_id: &str, evidence: &str) {
    connection
        .execute(
            "insert into approval_requests (request_id, harness, artifact_id, artifact_name, \
             artifact_type, artifact_hash, policy_action, recommended_scope, \
             changed_fields_json, source_scope, config_path, scanner_evidence_json, \
             review_command, approval_url, status, created_at, action_identity, \
             queue_group_id, last_seen_at) values (?1, 'codex', 'a', 'a', 'tool', 'h', \
             'require-reapproval', 'artifact', '[]', 'global', 'c', ?2, 'r', 'u', \
             'pending', ?3, 'i', 'g', ?3)",
            (request_id, evidence, NOW),
        )
        .expect("insert");
}

fn watch_only(connection: &Connection, request_id: &str) -> i64 {
    connection
        .query_row(
            "select watch_only_observation from approval_requests where request_id = ?1",
            [request_id],
            |row| row.get(0),
        )
        .expect("row")
}

fn recorded(connection: &Connection, version: i64) -> bool {
    connection
        .query_row(
            "select count(*) from schema_migrations where version = ?1",
            [version],
            |row| row.get::<_, i64>(0),
        )
        .expect("count")
        == 1
}

#[test]
fn a_fresh_store_records_versions_three_and_twenty_three() {
    let connection = fresh();
    assert!(recorded(&connection, WATCH_ONLY_VERSION));
    assert!(recorded(&connection, QUEUE_BACKFILL_VERSION));
}

#[test]
fn an_unrecorded_store_marks_inbox_rows_once() {
    let connection = fresh();
    insert(&connection, "inbox", INBOX);
    insert(&connection, "plain", "[]");
    connection
        .execute(
            "delete from schema_migrations where version = ?1",
            [WATCH_ONLY_VERSION],
        )
        .expect("forget");
    ensure_approval_queue(&connection, NOW).expect("mark");
    assert_eq!(watch_only(&connection, "inbox"), 1);
    assert_eq!(watch_only(&connection, "plain"), 0);
    assert!(recorded(&connection, WATCH_ONLY_VERSION));
    // Once recorded, a later inbox row is left for its writer to mark.
    insert(&connection, "later", INBOX);
    ensure_approval_queue(&connection, NOW).expect("again");
    assert_eq!(watch_only(&connection, "later"), 0);
}

#[test]
fn a_failed_step_keeps_none_of_the_run() {
    let connection = fresh();
    insert(&connection, "inbox", INBOX);
    connection
        .execute(
            "delete from schema_migrations where version = ?1",
            [WATCH_ONLY_VERSION],
        )
        .expect("forget");
    // A table squatting on an approval index name fails the index step after
    // the marking and its version were written.
    connection
        .execute_batch(
            "drop index idx_approval_status_created; create table idx_approval_status_created (x)",
        )
        .expect("blocker");
    assert!(ensure_approval_queue(&connection, NOW).is_err());
    assert!(connection.is_autocommit(), "no savepoint is left open");
    assert_eq!(watch_only(&connection, "inbox"), 0);
    assert!(!recorded(&connection, WATCH_ONLY_VERSION));
}

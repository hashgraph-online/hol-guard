use rusqlite::Connection;
use serde_json::Value;

use super::outbox_retired::{migrate_retired_outbox, MIGRATED_KEY};
use super::{create_base, ensure_families};
use crate::guard_store_outbox_identity::payload_digest_text;

const NOW: &str = "2026-11-23T00:00:00+00:00";
const LATER: &str = "2026-11-24T00:00:00+00:00";

fn with_retired_outbox() -> Connection {
    let connection = Connection::open_in_memory().expect("open");
    create_base(&connection).expect("base");
    ensure_families(&connection, NOW).expect("families");
    connection
        .execute(
            "delete from sync_state where state_key = ?1",
            [MIGRATED_KEY],
        )
        .expect("unmark");
    connection
        .execute_batch(
            "create table guard_live_request_outbox (
              sequence integer primary key autoincrement, local_request_id text not null,
              changed_at text not null, oauth_source text, oauth_subject_hash text,
              workspace_id text, machine_id text, machine_installation_id text,
              attempt_count integer not null default 0, next_attempt_at text, last_error text
            )",
        )
        .expect("retired");
    connection
}

fn retire(connection: &Connection, sequence: i64, changed_at: &str) {
    connection
        .execute(
            "insert into guard_live_request_outbox (sequence, local_request_id, changed_at, \
             oauth_source, oauth_subject_hash, workspace_id, machine_id, machine_installation_id) \
             values (?1, 'request-1', ?2, 'default', 'subject-1', 'workspace-1', 'machine-1', \
             'installation-1')",
            (sequence, changed_at),
        )
        .expect("retire");
}

fn request(connection: &Connection) {
    connection
        .execute(
            "insert into approval_requests (request_id, harness, artifact_id, artifact_name, \
             artifact_type, artifact_hash, policy_action, recommended_scope, \
             changed_fields_json, source_scope, oauth_source, config_path, review_command, \
             approval_url, status, created_at) values ('request-1', 'codex', 'a', 'a', 'tool', \
             'h', 'require-reapproval', 'artifact', '[]', 'global', 'default', 'c', 'r', 'u', \
             'pending', ?1)",
            [NOW],
        )
        .expect("request");
}

fn table_exists(connection: &Connection, name: &str) -> bool {
    connection
        .query_row(
            "select count(*) from sqlite_master where type = 'table' and name = ?1",
            [name],
            |row| row.get::<_, i64>(0),
        )
        .expect("count")
        == 1
}

type Event = (i64, String, String, Option<String>, String, String);

fn migrated(connection: &Connection) -> Vec<Event> {
    let mut statement = connection
        .prepare(
            "select request_sequence, binding_status, payload_json, quarantine_reason, \
             payload_hash, event_type from guard_review_outbox_events \
             where event_type = 'review.request.snapshot_migrated' order by request_sequence",
        )
        .expect("prepare");
    statement
        .query_map([], |row| {
            Ok((
                row.get(0)?,
                row.get(1)?,
                row.get(2)?,
                row.get(3)?,
                row.get(4)?,
                row.get(5)?,
            ))
        })
        .expect("query")
        .collect::<Result<_, _>>()
        .expect("rows")
}

const BINDING: [&str; 5] = [
    "default",
    "subject-1",
    "workspace-1",
    "machine-1",
    "installation-1",
];

#[test]
fn retired_rows_without_a_request_migrate_once_as_markers() {
    let connection = with_retired_outbox();
    retire(&connection, 1, NOW);
    retire(&connection, 2, LATER);
    migrate_retired_outbox(&connection, LATER).expect("migrate");
    let events = migrated(&connection);
    let sequences: Vec<i64> = events.iter().map(|event| event.0).collect();
    assert_eq!(sequences, [1, 2]);
    for event in &events {
        assert_eq!(event.1, "quarantined");
        assert_eq!(event.3.as_deref(), Some("retired_request_snapshot_missing"));
        assert_eq!(event.4, payload_digest_text(&event.2, BINDING));
    }
    assert_eq!(
        events[0].2,
        format!(
            "{{\"eventType\":\"review.request.snapshot_migrated\",\"localRequestId\":\"request-1\",\
             \"occurredAt\":\"{NOW}\",\"retiredSequence\":1,\"schema\":\"guard-cloud-review-event-v2\"}}"
        )
    );
    assert!(!table_exists(&connection, "guard_live_request_outbox"));
    // The marker keeps a second run from touching a recreated table.
    connection
        .execute_batch("create table guard_live_request_outbox (sequence integer)")
        .expect("recreate");
    migrate_retired_outbox(&connection, LATER).expect("again");
    assert!(table_exists(&connection, "guard_live_request_outbox"));
    assert_eq!(migrated(&connection).len(), 2);
}

#[test]
fn a_retired_row_with_its_request_migrates_ready_with_a_snapshot() {
    let connection = with_retired_outbox();
    request(&connection);
    retire(&connection, 5, LATER);
    migrate_retired_outbox(&connection, LATER).expect("migrate");
    let events = migrated(&connection);
    assert_eq!(events.len(), 1);
    let (sequence, status, payload, quarantine, _, _) = &events[0];
    assert_eq!(
        (*sequence, status.as_str(), quarantine),
        (5, "ready", &None)
    );
    let payload: Value = serde_json::from_str(payload).expect("json");
    assert_eq!(payload["requestSnapshot"]["request_id"], "request-1");
    assert_eq!(payload["occurredAt"], LATER);
    let last: i64 = connection
        .query_row(
            "select last_sequence from guard_review_outbox_request_sequences \
             where local_request_id = 'request-1'",
            [],
            |row| row.get(0),
        )
        .expect("sequence");
    assert_eq!(last, 5);
}

#[test]
fn a_retired_row_with_an_incomplete_identity_stays_quarantined() {
    let connection = with_retired_outbox();
    request(&connection);
    connection
        .execute(
            "insert into guard_live_request_outbox (local_request_id, changed_at, oauth_source) \
             values ('request-1', ?1, 'default')",
            [NOW],
        )
        .expect("retire");
    migrate_retired_outbox(&connection, LATER).expect("migrate");
    let events = migrated(&connection);
    assert_eq!(events[0].1, "quarantined");
    assert_eq!(events[0].3.as_deref(), Some("retired_identity_incomplete"));
}

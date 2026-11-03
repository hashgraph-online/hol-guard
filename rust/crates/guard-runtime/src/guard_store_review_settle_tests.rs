//! Settling rejected Cloud Review events: quarantine, counting and
//! dead-lettering in one store transaction.

use rusqlite::Connection;
use serde_json::{json, Value};

use super::{safe_high_water, sent_collisions, settle, Rejection, MAX_REJECTED_DELIVERY_ATTEMPTS};
use crate::guard_store_args::Args;
use crate::guard_store_db::StoreError;
use crate::guard_store_review_rejection_counts::forget_counts;

const SOURCE: &str = "default";
const COUNTS_KEY: &str = "guard_cloud_review_rejection_counts:default";

fn store() -> Connection {
    let connection = Connection::open_in_memory().unwrap();
    connection
        .execute_batch(
            "create table guard_review_outbox_events (
               stream_sequence integer primary key,
               event_id text not null unique,
               local_request_id text not null,
               request_sequence integer not null,
               event_type text not null,
               event_schema_version integer not null,
               payload_json text not null,
               payload_hash text not null,
               occurred_at text not null,
               oauth_source text, oauth_subject_hash text, workspace_id text,
               machine_id text, machine_installation_id text,
               binding_status text not null,
               quarantine_reason text, acknowledged_at text, last_error text);
             create table approval_requests (request_id text primary key, status text not null);
             create table sync_state (
               state_key text primary key, payload_json text not null, updated_at text not null);",
        )
        .unwrap();
    connection
}

fn insert_event(connection: &Connection, sequence: i64, request_id: &str) {
    connection
        .execute(
            "insert into guard_review_outbox_events values \
             (?1, 'event-' || ?1, ?2, ?1, 'review.request.created', 1, '{}', 'hash', 'then', \
              'default', 'subject', 'workspace', 'machine', 'installation', \
              'ready', null, null, null)",
            rusqlite::params![sequence, request_id],
        )
        .unwrap();
}

fn binding() -> Value {
    json!({
        "oauth_subject_hash": "subject",
        "workspace_id": "workspace",
        "machine_id": "machine",
        "machine_installation_id": "installation",
    })
}

fn call(connection: &Connection, sequences: &[i64], results: Value, events: Value) -> Value {
    let args = json!({
        "sequences": sequences,
        "results": results,
        "events": events,
        "acknowledged": [],
        "acknowledged_through": null,
        "binding": binding(),
        "changed_at": "2026-11-03T00:00:00+00:00",
    });
    settle(connection, SOURCE, &Args(args.as_object().unwrap())).unwrap()
}

fn status(connection: &Connection, sequence: i64) -> (String, Option<String>) {
    connection
        .query_row(
            "select binding_status, quarantine_reason from guard_review_outbox_events \
             where stream_sequence = ?1",
            [sequence],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap()
}

fn counts(connection: &Connection) -> Option<Value> {
    connection
        .query_row(
            "select payload_json from sync_state where state_key = ?1",
            [COUNTS_KEY],
            |row| row.get::<_, String>(0),
        )
        .ok()
        .map(|text| serde_json::from_str(&text).unwrap())
}

#[test]
fn terminal_rejection_is_quarantined_and_counts_as_progress() {
    let connection = store();
    insert_event(&connection, 7, "request-a");
    let reply = call(
        &connection,
        &[7],
        json!([{"code": "review_event_runtime_grant_missing"}]),
        json!([[7, {"eventId": "e7", "localRequestId": "request-a"}]]),
    );
    assert_eq!(reply, json!({"retained": [], "progressed": true}));
    assert_eq!(
        status(&connection, 7),
        (
            "quarantined".into(),
            Some("review_event_runtime_grant_missing".into())
        )
    );
    assert_eq!(counts(&connection), None);
}

#[test]
fn stored_quarantine_code_needs_a_quarantined_status() {
    let connection = store();
    insert_event(&connection, 3, "request-a");
    insert_event(&connection, 4, "request-a");
    let reply = call(
        &connection,
        &[3, 4],
        json!([
            {"code": "review_event_payload_hash_mismatch", "status": "rejected"},
            {"code": "review_event_payload_hash_mismatch", "status": "quarantined"},
        ]),
        json!([]),
    );
    assert_eq!(reply, json!({"retained": [0], "progressed": true}));
    assert_eq!(status(&connection, 3).0, "ready");
    assert_eq!(status(&connection, 4).0, "quarantined");
    assert_eq!(counts(&connection), Some(json!({"3": 1})));
}

#[test]
fn continuation_mismatch_quarantines_only_continuation_events() {
    let connection = store();
    insert_event(&connection, 1, "request-a");
    insert_event(&connection, 2, "request-a");
    let reply = call(
        &connection,
        &[1, 2],
        json!([
            {"code": "review_continuation_binding_mismatch"},
            {"code": "review_continuation_binding_mismatch"},
        ]),
        json!([
            [1, {"eventType": "continuation_resolved"}],
            [2, {"eventType": "review.request.created"}],
        ]),
    );
    assert_eq!(reply, json!({"retained": [1], "progressed": true}));
    assert_eq!(status(&connection, 1).0, "quarantined");
    assert_eq!(status(&connection, 2).0, "ready");
}

#[test]
fn repeated_rejections_dead_letter_at_the_cap() {
    let connection = store();
    insert_event(&connection, 9, "request-a");
    let results = json!([{"code": "review_event_invalid"}]);
    for attempt in 1..MAX_REJECTED_DELIVERY_ATTEMPTS {
        let reply = call(&connection, &[9], results.clone(), json!([]));
        assert_eq!(reply, json!({"retained": [0], "progressed": false}));
        assert_eq!(counts(&connection), Some(json!({"9": attempt})));
    }
    let reply = call(&connection, &[9], results, json!([]));
    assert_eq!(reply, json!({"retained": [], "progressed": true}));
    assert_eq!(
        status(&connection, 9),
        (
            "quarantined".into(),
            Some("review_event_retry_exhausted".into())
        )
    );
    assert_eq!(counts(&connection), Some(json!({})));
}

#[test]
fn retry_hints_and_pending_snapshot_requests_are_not_counted() {
    let connection = store();
    insert_event(&connection, 5, "request-p");
    insert_event(&connection, 6, "request-p");
    connection
        .execute(
            "insert into approval_requests values ('request-p', 'pending')",
            [],
        )
        .unwrap();
    let reply = call(
        &connection,
        &[5, 6],
        json!([
            {"code": "review_event_invalid", "retryAfterMs": 500},
            {"code": "review_event_snapshot_required"},
        ]),
        json!([[6, {"localRequestId": "request-p"}]]),
    );
    assert_eq!(reply, json!({"retained": [0, 1], "progressed": false}));
    assert_eq!(counts(&connection), None);
}

#[test]
fn snapshot_request_for_a_resolved_request_without_other_snapshots_is_quarantined() {
    let connection = store();
    insert_event(&connection, 8, "request-r");
    connection
        .execute(
            "insert into approval_requests values ('request-r', 'approved')",
            [],
        )
        .unwrap();
    let reply = call(
        &connection,
        &[8],
        json!([{"code": "missing_request_snapshot"}]),
        json!([[8, {"localRequestId": "request-r"}]]),
    );
    assert_eq!(reply, json!({"retained": [], "progressed": true}));
    assert_eq!(
        status(&connection, 8),
        (
            "quarantined".into(),
            Some("missing_request_snapshot".into())
        )
    );
}

#[test]
fn acknowledged_events_clear_their_counters_and_forget_drops_the_rest() {
    let connection = store();
    connection
        .execute(
            "insert into sync_state values (?1, '{\"1\": 4, \"2\": 2, \"x\": 9, \"3\": 0}', 'then')",
            [COUNTS_KEY],
        )
        .unwrap();
    let args = json!({
        "sequences": [],
        "results": [],
        "events": [],
        "acknowledged": [1],
        "acknowledged_through": 1,
        "binding": binding(),
        "changed_at": "now",
    });
    let reply = settle(&connection, SOURCE, &Args(args.as_object().unwrap())).unwrap();
    assert_eq!(reply, json!({"retained": [], "progressed": true}));
    assert_eq!(counts(&connection), Some(json!({"2": 2})));
    let args = json!({"sequences": [2], "changed_at": "later"});
    forget_counts(&connection, SOURCE, &Args(args.as_object().unwrap())).unwrap();
    assert_eq!(counts(&connection), Some(json!({})));
}

#[test]
fn incomplete_binding_and_mismatched_results_are_rejected() {
    let connection = store();
    let mut args = json!({
        "sequences": [1],
        "results": [{}],
        "events": [],
        "acknowledged": [],
        "acknowledged_through": null,
        "binding": {"oauth_subject_hash": "subject"},
        "changed_at": "now",
    });
    let invalid = |args: &Value| {
        matches!(
            settle(&connection, SOURCE, &Args(args.as_object().unwrap())),
            Err(StoreError::Invalid(_))
        )
    };
    assert!(invalid(&args));
    args["binding"] = binding();
    args["results"] = json!([]);
    assert!(invalid(&args));
}

#[test]
fn collision_recovery_needs_the_typed_code_and_the_exact_sent_event() {
    let results = [
        json!({"code": "review_event_snapshot_sequence_collision", "eventId": "event-41"}),
        json!({"code": "review_event_sequence_conflict", "eventId": "event-42"}),
        json!({"code": "review_event_snapshot_sequence_collision", "eventId": "other"}),
        json!({"code": "review_event_snapshot_sequence_collision", "eventId": "event-44"}),
    ];
    let sent = [
        json!({"eventId": "event-41"}),
        json!({"eventId": "event-42"}),
        json!({"eventId": "event-43"}),
    ];
    let rejections: Vec<Rejection> = (0..4)
        .map(|index| Rejection {
            sequence: 41 + index as i64,
            result: results[index].as_object().unwrap(),
            event: sent.get(index).and_then(Value::as_object),
        })
        .collect();
    let collisions = sent_collisions(&rejections);
    assert_eq!(
        collisions.into_iter().collect::<Vec<_>>(),
        [(41, "event-41")]
    );
    assert_eq!(safe_high_water(Some(&json!(0))), Some(0));
    assert_eq!(safe_high_water(Some(&json!(529))), Some(529));
    for invalid in [
        json!(true),
        json!(-1),
        json!(1.5),
        json!(9_007_199_254_740_992_i64),
    ] {
        assert_eq!(safe_high_water(Some(&invalid)), None, "{invalid}");
    }
    assert_eq!(safe_high_water(None), None);
}

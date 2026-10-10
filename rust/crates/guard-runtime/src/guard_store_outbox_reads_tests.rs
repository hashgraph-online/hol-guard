//! Reply-size bounds of the Review outbox reads, through the `guard_store` op.

use std::path::PathBuf;

use guard_contracts::{GuardStoreRequestV1, GUARD_STORE_REQUEST_SCHEMA};
use rusqlite::Connection;
use serde_json::{json, Map, Value};

use crate::guard_store_op::evaluate_guard_store_request;
use crate::guard_store_outbox_decode::{EVENT_SCHEMA_NAME, SNAPSHOT_COLUMNS};
use crate::guard_store_outbox_identity::payload_digest_text;
use crate::MAX_NATIVE_RESPONSE_BYTES;

const SOURCE: &str = "default";
const BINDING: [&str; 4] = ["subject", "workspace", "machine", "installation"];

struct Fixture {
    home: PathBuf,
    connection: Connection,
}

impl Fixture {
    fn new(tag: &str) -> Self {
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let home = std::env::temp_dir().join(format!(
            "hol-guard-store-reads-{tag}-{}-{nonce}",
            std::process::id()
        ));
        std::fs::create_dir_all(&home).unwrap();
        let home = std::fs::canonicalize(home).unwrap();
        let connection = Connection::open(home.join("guard.db")).unwrap();
        connection
            .execute_batch(
                "create table guard_review_outbox_events (
                   stream_sequence integer primary key autoincrement,
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
                   quarantine_reason text, acknowledged_at text,
                   attempt_count integer not null default 0,
                   next_attempt_at text, last_error text,
                   unique(local_request_id, request_sequence));",
            )
            .unwrap();
        Self { home, connection }
    }

    /// An authenticated event whose snapshot carries `filler` bytes.
    fn insert(&self, request_id: &str, sequence: i64, filler: usize) {
        let mut snapshot = Map::new();
        for column in SNAPSHOT_COLUMNS {
            snapshot.insert(column.to_owned(), Value::from("x"));
        }
        snapshot.insert("request_id".into(), Value::from(request_id));
        snapshot.insert("oauth_source".into(), Value::from(SOURCE));
        snapshot.insert("reason".into(), Value::from("r".repeat(filler)));
        snapshot.insert("continuation_snapshot_json".into(), Value::Null);
        for field in crate::guard_store_outbox_decode::SNAPSHOT_JSON_FIELDS {
            snapshot.insert(field.to_owned(), Value::from("{\"ratio\":0.1}"));
        }
        let payload = json!({
            "schema": EVENT_SCHEMA_NAME,
            "localRequestId": request_id,
            "eventType": "review.request.created",
            "oauthSource": SOURCE,
            "requestSnapshot": snapshot,
        })
        .to_string();
        let digest = payload_digest_text(
            &payload,
            [SOURCE, BINDING[0], BINDING[1], BINDING[2], BINDING[3]],
        );
        self.connection
            .execute(
                "insert into guard_review_outbox_events (event_id, local_request_id, \
                 request_sequence, event_type, event_schema_version, payload_json, \
                 payload_hash, occurred_at, oauth_source, oauth_subject_hash, workspace_id, \
                 machine_id, machine_installation_id, binding_status) \
                 values (?1, ?2, ?3, 'review.request.created', 1, ?4, ?5, 't', ?6, ?7, ?8, ?9, ?10, 'ready')",
                rusqlite::params![
                    format!("{request_id}-{sequence}"),
                    request_id,
                    sequence,
                    payload,
                    digest,
                    SOURCE,
                    BINDING[0],
                    BINDING[1],
                    BINDING[2],
                    BINDING[3]
                ],
            )
            .unwrap();
    }

    fn call(&self, method: &str, args: Value) -> (Value, usize) {
        let request = GuardStoreRequestV1 {
            schema: GUARD_STORE_REQUEST_SCHEMA.to_owned(),
            request_id: "reads".to_owned(),
            store_path: self.home.join("guard.db").to_string_lossy().into_owned(),
            guard_home: self.home.to_string_lossy().into_owned(),
            method: method.to_owned(),
            source: SOURCE.to_owned(),
            busy_timeout_ms: 5000,
            args: args.as_object().unwrap().clone(),
        };
        let bytes = evaluate_guard_store_request(&request)
            .unwrap_or_else(|error| panic!("{method} reply rejected: {error}"));
        let reply: Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(reply["status"], "ok", "{reply}");
        (reply["payload"].clone(), bytes.len())
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.home);
    }
}

fn ready_args(limit: i64) -> Value {
    json!({
        "now": "2030-01-01T00:00:00+00:00",
        "limit": limit,
        "oauth_subject_hash": BINDING[0],
        "workspace_id": BINDING[1],
        "machine_id": BINDING[2],
        "machine_installation_id": BINDING[3],
    })
}

#[test]
fn ready_batch_over_the_reply_cap_returns_a_bounded_prefix() {
    let fixture = Fixture::new("ready-prefix");
    for sequence in 1..=10 {
        fixture.insert("r1", sequence, 400 * 1024);
    }
    let (payload, reply_bytes) = fixture.call("list_ready_review_events", ready_args(50));
    let events = payload.as_array().unwrap();
    assert!(
        (1..10).contains(&events.len()),
        "prefix, not all or nothing: {}",
        events.len()
    );
    assert!(reply_bytes < MAX_NATIVE_RESPONSE_BYTES);
    assert_eq!(events[0]["sequence"], 1, "prefix keeps stream order");
    assert!(events
        .iter()
        .all(|event| event["payload_oversized"].is_null()));
}

#[test]
fn ready_row_between_budget_and_cap_is_returned_alone() {
    let fixture = Fixture::new("ready-single");
    fixture.insert("r1", 1, 1_500 * 1024);
    fixture.insert("r1", 2, 10);
    let (payload, reply_bytes) = fixture.call("list_ready_review_events", ready_args(50));
    let events = payload.as_array().unwrap();
    assert_eq!(events.len(), 1);
    assert!(events[0]["payload_oversized"].is_null());
    assert!(events[0]["payload_json"].as_str().unwrap().len() > 1_500 * 1024);
    assert!(reply_bytes < MAX_NATIVE_RESPONSE_BYTES);
}

#[test]
fn ready_row_that_cannot_fit_alone_is_flagged_without_payload() {
    let fixture = Fixture::new("ready-poison");
    fixture.insert("r1", 1, 2_200 * 1024);
    fixture.insert("r1", 2, 10);
    let (payload, reply_bytes) = fixture.call("list_ready_review_events", ready_args(50));
    let events = payload.as_array().unwrap();
    assert_eq!(events.len(), 1, "the poison row travels alone");
    assert_eq!(events[0]["payload_oversized"], true);
    assert_eq!(events[0]["payload_json"], "");
    assert_eq!(events[0]["sequence"], 1);
    assert_eq!(events[0]["workspace_id"], BINDING[1]);
    assert!(reply_bytes < MAX_NATIVE_RESPONSE_BYTES);
}

#[test]
fn snapshot_history_over_the_reply_cap_pages_without_loss() {
    let fixture = Fixture::new("snapshot-pages");
    for sequence in 1..=9 {
        fixture.insert("r1", sequence, 400 * 1024);
    }
    fixture.insert("r2", 1, 10);
    let mut seen = Vec::new();
    let mut cursor = Value::Null;
    let mut pages = 0;
    loop {
        let mut args = json!({"request_id": "r1"});
        if !cursor.is_null() {
            args["after"] = cursor.clone();
        }
        let (payload, reply_bytes) = fixture.call("list_review_event_snapshots", args);
        assert!(reply_bytes < MAX_NATIVE_RESPONSE_BYTES);
        pages += 1;
        for snapshot in payload["snapshots"].as_array().unwrap() {
            assert_eq!(snapshot["request_id"], "r1");
            seen.push(snapshot["reason"].as_str().unwrap().len());
            // Stored JSON text was decoded, decimals included.
            assert_eq!(snapshot["action_envelope_json"]["ratio"], 0.1);
        }
        assert!(pages < 20, "paging must terminate");
        cursor = payload["next"].clone();
        if cursor.is_null() {
            break;
        }
    }
    assert!(pages > 1, "history exceeding the cap needs several pages");
    assert_eq!(seen.len(), 9, "every snapshot is returned exactly once");
}

#[test]
fn snapshot_that_cannot_fit_alone_is_skipped_and_counted() {
    let fixture = Fixture::new("snapshot-poison");
    fixture.insert("r1", 1, 10);
    fixture.insert("r1", 2, 2_200 * 1024);
    let (payload, reply_bytes) =
        fixture.call("list_review_event_snapshots", json!({"request_id": "r1"}));
    assert_eq!(payload["snapshots"].as_array().unwrap().len(), 1);
    assert_eq!(payload["skipped_oversized"], 1);
    assert_eq!(payload["next"], Value::Null);
    assert!(reply_bytes < MAX_NATIVE_RESPONSE_BYTES);
}

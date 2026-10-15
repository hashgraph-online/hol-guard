//! Byte bounds for artifact inventory and snapshot reads, through `guard_store`.

use std::path::PathBuf;

use guard_contracts::{GuardStoreRequestV1, GUARD_STORE_REQUEST_SCHEMA};
use rusqlite::Connection;
use serde_json::{json, Value};

use crate::guard_store_op::evaluate_guard_store_request;
use crate::MAX_NATIVE_RESPONSE_BYTES;

const SOURCE: &str = "default";

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
            "hol-guard-inventory-pages-{tag}-{}-{nonce}",
            std::process::id()
        ));
        std::fs::create_dir_all(&home).unwrap();
        let home = std::fs::canonicalize(home).unwrap();
        let connection = Connection::open(home.join("guard.db")).unwrap();
        connection
            .execute_batch(
                "create table guard_review_outbox_events (
                   stream_sequence integer primary key,
                   payload_hash text not null default ''
                 );
                 create table artifact_snapshots (
                   artifact_id text not null,
                   harness text not null,
                   snapshot_json text not null,
                   artifact_hash text not null,
                   recorded_at text not null,
                   primary key (artifact_id, harness)
                 );
                 create table artifact_inventory (
                   artifact_id text not null,
                   harness text not null,
                   artifact_name text not null,
                   artifact_type text not null,
                   source_scope text not null,
                   config_path text not null,
                   publisher text,
                   origin_url text,
                   launch_command text,
                   transport text,
                   first_seen_at text not null,
                   last_seen_at text not null,
                   last_changed_at text,
                   last_approved_at text,
                   removed_at text,
                   present integer not null default 1,
                   last_policy_action text not null,
                   artifact_hash text not null,
                   primary key (artifact_id, harness)
                 );
                 create table sync_state (
                   state_key text primary key,
                   payload_json text not null,
                   updated_at text not null
                 );",
            )
            .unwrap();
        Self { home, connection }
    }

    fn call(&self, method: &str, args: Value) -> (Value, usize) {
        let request = GuardStoreRequestV1 {
            schema: GUARD_STORE_REQUEST_SCHEMA.to_owned(),
            request_id: "inventory-pages".to_owned(),
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
        (reply, bytes.len())
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.home);
    }
}

fn insert_snapshot(fixture: &Fixture, artifact_id: &str, bytes: usize) {
    let snapshot = json!({ "blob": "x".repeat(bytes) }).to_string();
    fixture
        .connection
        .execute(
            "insert into artifact_snapshots (
               artifact_id, harness, snapshot_json, artifact_hash, recorded_at
             ) values (?1, 'codex', ?2, 'hash', '2026-07-18T20:00:00+00:00')",
            (artifact_id, snapshot),
        )
        .unwrap();
}

fn insert_inventory(fixture: &Fixture, artifact_id: &str, name: &str, bytes: usize) {
    fixture
        .connection
        .execute(
            "insert into artifact_inventory (
               artifact_id, harness, artifact_name, artifact_type, source_scope,
               config_path, launch_command, first_seen_at, last_seen_at, present,
               last_policy_action, artifact_hash
             ) values (
               ?1, 'codex', ?2, 'mcp', 'user', 'cfg', ?3, 't', 't', 1, 'allow', 'hash'
             )",
            (artifact_id, name, "x".repeat(bytes)),
        )
        .unwrap();
}

fn store_sequence(fixture: &Fixture, payload: &str) {
    fixture
        .connection
        .execute(
            "insert into sync_state (state_key, payload_json, updated_at) values (
               'aibom_trust_attestation_sequence', ?1, '2026-07-18T20:00:00+00:00'
             )",
            (payload,),
        )
        .unwrap();
}

fn sequence_payload(fixture: &Fixture) -> String {
    fixture
        .connection
        .query_row(
            "select payload_json from sync_state where state_key = 'aibom_trust_attestation_sequence'",
            [],
            |row| row.get(0),
        )
        .unwrap()
}

#[test]
fn snapshot_history_over_the_reply_cap_pages_without_loss() {
    let fixture = Fixture::new("snapshot-pages");
    for index in 0..6 {
        insert_snapshot(&fixture, &format!("a{index}"), 400 * 1024);
    }
    let mut seen = Vec::new();
    let mut cursor = Value::Null;
    let mut pages = 0;
    loop {
        let mut args = json!({ "harness": "codex" });
        if !cursor.is_null() {
            args["after"] = cursor.clone();
        }
        let (reply, reply_bytes) = fixture.call("list_artifact_snapshots", args);
        assert_eq!(reply["status"], "ok", "{reply}");
        assert!(reply_bytes < MAX_NATIVE_RESPONSE_BYTES);
        pages += 1;
        for row in reply["payload"]["rows"].as_array().unwrap() {
            seen.push(row["artifact_id"].as_str().unwrap().to_owned());
        }
        assert!(pages < 20, "paging must terminate");
        cursor = reply["payload"]["next"].clone();
        if cursor.is_null() {
            break;
        }
    }
    assert!(pages > 1, "snapshots exceeding the cap need several pages");
    assert_eq!(
        seen,
        (0..6).map(|index| format!("a{index}")).collect::<Vec<_>>()
    );
}

#[test]
fn inventory_over_the_reply_cap_pages_without_loss() {
    let fixture = Fixture::new("inventory-pages");
    for index in 0..6 {
        insert_inventory(
            &fixture,
            &format!("id-{index:02}"),
            &format!("name-{index:02}"),
            400 * 1024,
        );
    }
    let mut seen = Vec::new();
    let mut cursor = Value::Null;
    let mut pages = 0;
    loop {
        let mut args = json!({ "harness": "codex" });
        if !cursor.is_null() {
            args["after"] = cursor.clone();
        }
        let (reply, reply_bytes) = fixture.call("list_artifact_inventory", args);
        assert_eq!(reply["status"], "ok", "{reply}");
        assert!(reply_bytes < MAX_NATIVE_RESPONSE_BYTES);
        pages += 1;
        for row in reply["payload"]["rows"].as_array().unwrap() {
            seen.push(row["artifact_id"].as_str().unwrap().to_owned());
        }
        assert!(pages < 20, "paging must terminate");
        cursor = reply["payload"]["next"].clone();
        if cursor.is_null() {
            break;
        }
    }
    assert!(pages > 1, "inventory exceeding the cap needs several pages");
    assert_eq!(
        seen,
        (0..6)
            .map(|index| format!("id-{index:02}"))
            .collect::<Vec<_>>()
    );
}

#[test]
fn snapshot_that_cannot_fit_alone_fails_instead_of_skipping() {
    let fixture = Fixture::new("snapshot-poison");
    insert_snapshot(&fixture, "a-small", 32);
    insert_snapshot(&fixture, "b-huge", 2_200 * 1024);
    let (first, first_bytes) =
        fixture.call("list_artifact_snapshots", json!({ "harness": "codex" }));
    assert_eq!(first["status"], "ok", "{first}");
    assert!(first_bytes < MAX_NATIVE_RESPONSE_BYTES);
    assert_eq!(first["payload"]["rows"].as_array().unwrap().len(), 1);
    assert_eq!(first["payload"]["rows"][0]["artifact_id"], "a-small");
    let (second, _) = fixture.call(
        "list_artifact_snapshots",
        json!({ "harness": "codex", "after": first["payload"]["next"] }),
    );
    assert_eq!(second["status"], "error", "{second}");
    assert_eq!(second["code"], "native_guard_store_value_error");
    assert_eq!(
        second["payload"]["message"],
        "artifact_row_exceeds_resident_response"
    );
    let remaining: i64 = fixture
        .connection
        .query_row("select count(*) from artifact_snapshots", [], |row| {
            row.get(0)
        })
        .unwrap();
    assert_eq!(remaining, 2, "the oversized row stays stored");
}

#[test]
fn attestation_sequence_rejects_values_past_i64_without_resetting() {
    let cases = [
        "9223372036854775807",
        "9223372036854775808",
        "\"9223372036854775808\"",
        "18446744073709551616",
    ];
    for payload_number in cases {
        let fixture = Fixture::new("sequence-overflow");
        let stored = format!("{{\"sequence\": {payload_number}}}");
        store_sequence(&fixture, &stored);
        let (reply, _) = fixture.call(
            "next_aibom_trust_attestation_sequence",
            json!({ "now": "2026-07-18T20:10:00+00:00" }),
        );
        assert_eq!(reply["status"], "error", "{payload_number}: {reply}");
        assert_eq!(reply["code"], "native_guard_store_value_error");
        assert_eq!(
            reply["payload"]["message"],
            "aibom_trust_attestation_sequence_overflow"
        );
        assert_eq!(sequence_payload(&fixture), stored);
    }
}

#[test]
fn attestation_sequence_accepts_unicode_decimal_digits() {
    let fixture = Fixture::new("sequence-unicode");
    store_sequence(&fixture, "{\"sequence\": \"٧\"}");
    let stored = sequence_payload(&fixture);
    assert_eq!(stored, "{\"sequence\": \"٧\"}", "stored {stored:?}");
    let (reply, _) = fixture.call(
        "next_aibom_trust_attestation_sequence",
        json!({ "now": "2026-07-18T20:10:00+00:00" }),
    );
    assert_eq!(reply["status"], "ok", "{reply}");
    assert_eq!(reply["payload"], 8);
    assert_eq!(sequence_payload(&fixture), "{\"sequence\": 8}");
}

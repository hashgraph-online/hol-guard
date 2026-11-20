use rusqlite::Connection;

use super::*;
use crate::guard_store_cmd_vectors_tests::temp_home;
use crate::pyjson;

const VECTORS: &str = include_str!("../testdata/guard_store/guard_sessions_vectors.json");

struct Store {
    config: ReadConfig,
    reads: NativeReads,
}

fn store(tag: &str, sessions: usize) -> Store {
    let home = temp_home(&format!("edge-initialize-{tag}"));
    let db = home.join("guard.db");
    let connection = Connection::open(&db).unwrap();
    connection
        .execute_batch(
            "create table guard_review_outbox_events (
                 stream_sequence integer primary key, payload_hash text not null default '');
             create table guard_events (
                 event_id integer primary key autoincrement, event_name text not null,
                 payload_json text not null, occurred_at text not null);",
        )
        .unwrap();
    let vectors: Value = serde_json::from_str(VECTORS).unwrap();
    for statement in vectors["schema_sql"].as_array().unwrap() {
        connection
            .execute_batch(statement.as_str().unwrap())
            .unwrap();
    }
    for index in 0..sessions {
        connection
            .execute(
                "insert into guard_sessions (session_id, harness, surface, status, client_name,
                     client_title, client_version, workspace, capabilities_json, created_at,
                     updated_at)
                 values (?1, 'codex', 'cli', 'idle', 'Codex', null, '1.2', '/work', '[]',
                     't1', ?2)",
                (format!("s-{index:02}"), format!("t{index:02}")),
            )
            .unwrap();
    }
    let handshake = json!({
        "schema": super::super::super::super::HANDSHAKE_SCHEMA,
        "auth_token": "initialize-test-secret",
        "guard_home": home.to_str().unwrap(),
        "store_path": db.to_str().unwrap(),
        "source": "default",
        "busy_timeout_ms": 2000,
    });
    Store {
        config: ReadConfig::from_line(&serde_json::to_vec(&handshake).unwrap()).unwrap(),
        reads: NativeReads::new(None),
    }
}

impl Store {
    fn post(&self, body: &str) -> Option<(u16, Value)> {
        let PyVal::Dict(payload) = pyjson::parse(body).unwrap() else {
            panic!("{body}");
        };
        respond(&payload, true, &self.config, &self.reads)
    }
}

#[test]
fn answers_with_client_defaults_and_the_newest_sessions() {
    let store = store("defaults", 25);
    let (status, body) = store.post("{}").unwrap();
    assert_eq!(status, 200);
    assert_eq!(body["protocol_version"], "1.1");
    assert_eq!(body["schema_version"], body["schema"]["schema_version"]);
    assert_eq!(body["protocol"]["negotiated_version"], "1.1");
    assert_eq!(body["client_id"].as_str().unwrap().len(), 32);
    assert_eq!(
        body["client"],
        json!({
            "client_name": "guard-client",
            "client_title": null,
            "version": null,
            "surface": "cli",
            "capabilities": [],
        })
    );
    assert_eq!(body["server_capabilities"]["methods"][0], "initialize");
    assert_eq!(
        body["server_capabilities"]["methods"]
            .as_array()
            .unwrap()
            .len(),
        16
    );
    let sessions = body["sessions"].as_array().unwrap();
    assert_eq!(sessions.len(), 20);
    assert_eq!(sessions[0]["session_id"], "s-24");
}

#[test]
fn keeps_only_string_versions_and_capabilities() {
    let store = store("strings", 1);
    let (status, body) = store
        .post(
            r#"{"supported_protocol_versions": [1, "1.0"], "client_name": "Desk",
                "surface": "approval-center", "capabilities": ["a", 2, "b"]}"#,
        )
        .unwrap();
    assert_eq!(status, 200);
    assert_eq!(body["protocol_version"], "1.1");
    assert_eq!(body["client"]["client_name"], "Desk");
    assert_eq!(body["client"]["surface"], "approval-center");
    assert_eq!(body["client"]["capabilities"], json!(["a", "b"]));
}

#[test]
fn rejects_a_client_that_shares_no_version() {
    let store = store("unsupported", 0);
    assert_eq!(
        store.post(r#"{"supported_protocol_versions": ["9.0"]}"#),
        Some((400, json!({"error": "unsupported_protocol_version"})))
    );
}

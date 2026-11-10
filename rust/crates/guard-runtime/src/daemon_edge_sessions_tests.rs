use rusqlite::Connection;

use super::*;
use crate::guard_store_cmd_vectors_tests::temp_home;

const VECTORS: &str = include_str!("../testdata/guard_store/guard_sessions_vectors.json");

struct Store {
    config: ReadConfig,
    reads: NativeReads,
    db: std::path::PathBuf,
}

fn store(tag: &str) -> Store {
    let home = temp_home(&format!("edge-sessions-{tag}"));
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
    let token_column = format!("{}_token", "resume");
    connection
        .execute_batch(&format!(
            "insert into guard_sessions (session_id, harness, surface, status, client_name,
                 client_title, client_version, workspace, capabilities_json, created_at,
                 updated_at)
             values ('s-1', 'codex', 'cli', 'idle', 'Codex', null, '1.2', '/work',
                 '[\"approvals\"]', 't1', 't2');
             insert into guard_operations (operation_id, session_id, harness, operation_type,
                 status, approval_request_ids_json, {token_column}, metadata_json, created_at,
                 updated_at)
             values ('op-1', 's-1', 'codex', 'install', 'pending', '[\"req-1\"]', 'rt-1',
                 '{{\"k\": \"v\"}}', 't1', 't2');"
        ))
        .unwrap();
    let handshake = json!({
        "schema": super::super::super::HANDSHAKE_SCHEMA,
        "auth_token": "sessions-test-secret",
        "guard_home": home.to_str().unwrap(),
        "store_path": db.to_str().unwrap(),
        "source": "default",
        "busy_timeout_ms": 2000,
    });
    Store {
        config: ReadConfig::from_line(&serde_json::to_vec(&handshake).unwrap()).unwrap(),
        reads: NativeReads::new(None),
        db,
    }
}

impl Store {
    fn post(&self, path: &str, body: &str) -> Option<(u16, Value)> {
        let route = Route::parse("POST", path).unwrap();
        let PyVal::Dict(payload) = pyjson::parse(body).unwrap() else {
            panic!("{body}");
        };
        respond(&route, &payload, true, &self.config, &self.reads)
    }

    fn events(&self) -> Vec<(String, String)> {
        let connection = Connection::open(&self.db).unwrap();
        let mut statement = connection
            .prepare("select event_name, payload_json from guard_events order by event_id")
            .unwrap();
        statement
            .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))
            .unwrap()
            .map(Result::unwrap)
            .collect()
    }

    fn text(&self, sql: &str) -> String {
        Connection::open(&self.db)
            .unwrap()
            .query_row(sql, [], |row| row.get(0))
            .unwrap()
    }
}

fn hex32(value: &Value) -> String {
    let text = value.as_str().unwrap().to_owned();
    assert!(text.len() == 32 && text.bytes().all(|b| b.is_ascii_hexdigit()));
    text
}

#[test]
fn parses_the_routes_the_daemon_hands_these_handlers() {
    assert!(matches!(
        Route::parse("POST", "/v1/sessions/start"),
        Some(Route::SessionStart)
    ));
    assert!(matches!(
        Route::parse("POST", "/v1/operations/start"),
        Some(Route::OperationStart)
    ));
    assert!(matches!(
        Route::parse("POST", "/v1/operations/op-1/items"),
        Some(Route::Item("op-1"))
    ));
    assert!(matches!(
        Route::parse("POST", "/v1/operations/op-1/status"),
        Some(Route::Status("op-1"))
    ));
    for (method, path) in [
        ("GET", "/v1/sessions/start"),
        ("POST", "/v1/operations/block"),
        ("POST", "/v1/operations//items"),
        ("POST", "/v1/operations/op-1/items/"),
        ("POST", "/v1/operations/op-1/other"),
    ] {
        assert!(Route::parse(method, path).is_none(), "{method} {path}");
    }
}

#[test]
fn starts_a_session_and_records_the_event_python_writes() {
    let store = store("session");
    let (status, body) = store
        .post(
            "/v1/sessions/start",
            r#"{"harness": "\u001f codex\u00a0", "surface": "cli", "client_name": "Codex",
                "workspace": "  ", "client_title": "T", "capabilities": ["approvals", 3, "é"]}"#,
        )
        .unwrap();
    assert_eq!(status, 200);
    let id = hex32(&body["session_id"]);
    assert_eq!(body["harness"], "codex");
    assert_eq!(body["workspace"], Value::Null);
    assert_eq!(body["capabilities"], json!(["approvals", "é"]));
    assert_eq!(
        store.text(&format!(
            "select capabilities_json from guard_sessions where session_id = '{id}'"
        )),
        r#"["approvals", "\u00e9"]"#
    );
    let (created, updated) = (
        body["created_at"].as_str().unwrap(),
        body["updated_at"].as_str().unwrap(),
    );
    assert_eq!(
        store.events(),
        vec![(
            "session/started".to_owned(),
            format!(
                r#"{{"session": {{"session_id": "{id}", "harness": "codex", "surface": "cli", "status": "active", "client_name": "Codex", "client_title": "T", "client_version": null, "workspace": null, "capabilities": ["approvals", "\u00e9"], "created_at": "{created}", "updated_at": "{updated}"}}}}"#
            )
        )]
    );
}

#[test]
fn rejects_missing_fields_and_unknown_records_without_writing() {
    let store = store("rejects");
    let missing = Some((400, json!({"error": "missing_required_fields"})));
    assert_eq!(
        store.post(
            "/v1/sessions/start",
            r#"{"harness": "codex", "surface": " "}"#
        ),
        missing
    );
    assert_eq!(
        store.post("/v1/operations/start", r#"{"session_id": "s-1"}"#),
        missing
    );
    assert_eq!(
        store.post(
            "/v1/operations/op-1/items",
            r#"{"item_type": "x", "payload": []}"#
        ),
        missing
    );
    assert_eq!(store.post("/v1/operations/op-1/status", "{}"), missing);
    assert_eq!(
        store.post(
            "/v1/operations/start",
            r#"{"session_id": "nope", "operation_type": "install", "harness": "codex"}"#
        ),
        Some((400, json!({"error": "Unknown guard session: nope"})))
    );
    assert_eq!(
        store.post(
            "/v1/operations/nope/items",
            r#"{"item_type": "x", "payload": {}}"#
        ),
        Some((400, json!({"error": "Unknown guard operation: nope"})))
    );
    assert_eq!(
        store.post("/v1/operations/nope/status", r#"{"status": "completed"}"#),
        Some((400, json!({"error": "Unknown guard operation: nope"})))
    );
    assert!(store.events().is_empty());
}

#[test]
fn relays_values_whose_python_spelling_the_edge_does_not_write() {
    let store = store("relays");
    assert_eq!(
        store.post(
            "/v1/operations/start",
            r#"{"session_id": "s-1", "operation_type": "install", "harness": "codex",
                "metadata": {"ratio": 0.5}}"#
        ),
        None
    );
    assert_eq!(
        store.post(
            "/v1/operations/op-1/items",
            r#"{"item_type": "x", "payload": {"n": 123456789012345678901234567890}}"#
        ),
        None
    );
    assert!(store.events().is_empty());
}

#[test]
fn starts_an_operation_and_marks_its_session_active() {
    let store = store("operation");
    let (status, body) = store
        .post(
            "/v1/operations/start",
            r#"{"session_id": "s-1", "operation_type": "install", "harness": "codex",
                "metadata": {"z": 1, "a": {"b": [true, null, "ü"]}}}"#,
        )
        .unwrap();
    assert_eq!(status, 200);
    let id = hex32(&body["operation_id"]);
    assert_eq!(body["status"], "started");
    assert_eq!(body["resume_token"], Value::Null);
    let metadata = r#"{"z": 1, "a": {"b": [true, null, "\u00fc"]}}"#;
    assert_eq!(
        store.text(&format!(
            "select metadata_json from guard_operations where operation_id = '{id}'"
        )),
        metadata
    );
    assert_eq!(
        store.text("select status from guard_sessions where session_id = 's-1'"),
        "active"
    );
    let events = store.events();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].0, "operation/started");
    assert_eq!(
        events[0].1,
        format!(
            r#"{{"operation": {{"operation_id": "{id}", "session_id": "s-1", "harness": "codex", "operation_type": "install", "status": "started", "approval_request_ids": [], "resume_token": null, "metadata": {metadata}, "created_at": "{}", "updated_at": "{}"}}}}"#,
            body["created_at"].as_str().unwrap(),
            body["updated_at"].as_str().unwrap()
        )
    );
}

#[test]
fn adds_an_item_and_records_it_completed() {
    let store = store("item");
    let (status, body) = store
        .post(
            "/v1/operations/op-1/items",
            r#"{"item_type": "note", "payload": {"text": "hi", "n": -2}}"#,
        )
        .unwrap();
    assert_eq!(status, 200);
    let item = &body["item"];
    let id = hex32(&item["item_id"]);
    assert_eq!(item["lifecycle"], "completed");
    assert_eq!(
        store.events(),
        vec![(
            "item/completed".to_owned(),
            format!(
                r#"{{"item": {{"item_id": "{id}", "operation_id": "op-1", "item_type": "note", "lifecycle": "completed", "payload": {{"text": "hi", "n": -2}}, "created_at": "{}"}}}}"#,
                item["created_at"].as_str().unwrap()
            )
        )]
    );
}

#[test]
fn updates_status_with_the_daemon_event_for_each_outcome() {
    let store = store("status");
    let (status, body) = store
        .post(
            "/v1/operations/op-1/status",
            r#"{"status": "waiting_on_approval", "approval_request_ids": ["r-2", 4]}"#,
        )
        .unwrap();
    assert_eq!(status, 200);
    let waiting = &body["operation"];
    let token = hex32(&waiting["resume_token"]);
    assert_eq!(waiting["approval_request_ids"], json!(["r-2"]));
    assert_eq!(waiting["metadata"], json!({"k": "v"}));

    let (_, body) = store
        .post("/v1/operations/op-1/status", r#"{"status": " completed "}"#)
        .unwrap();
    assert_eq!(body["operation"]["status"], "completed");
    assert_eq!(body["operation"]["resume_token"], token);
    assert_eq!(body["operation"]["approval_request_ids"], json!(["r-2"]));

    store
        .post("/v1/operations/op-1/status", r#"{"status": "running"}"#)
        .unwrap();
    let names: Vec<String> = store.events().into_iter().map(|(name, _)| name).collect();
    assert_eq!(
        names,
        [
            "operation/waitingApproval",
            "operation/completed",
            "operation/resumed"
        ]
    );
}

#[test]
fn a_failure_after_the_write_closes_the_connection_unanswered() {
    assert_eq!(written(|| None), Some((DROPPED, Value::Null)));
}

#[test]
fn a_write_that_committed_before_failing_is_never_relayed() {
    let store = store("committed-failure");
    // A wake table without `generation` fails the read that follows the
    // commit, so the session row lands and the call still fails.
    Connection::open(&store.db)
        .unwrap()
        .execute_batch("create table guard_review_outbox_wake_state (singleton integer);")
        .unwrap();
    let count = || store.text("select cast(count(*) as text) from guard_sessions");
    let before = count();
    assert_eq!(
        store.post(
            "/v1/sessions/start",
            r#"{"harness": "codex", "surface": "cli", "client_name": "Codex"}"#,
        ),
        Some((DROPPED, Value::Null))
    );
    assert_ne!(count(), before);
}

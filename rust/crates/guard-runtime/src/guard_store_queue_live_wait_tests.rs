//! Queues the silent review vectors' codex requests with a live wait and
//! reads back the session, operation and resume rows the same call wrote.

use guard_contracts::{GuardStoreRequestV1, GUARD_STORE_REQUEST_SCHEMA};
use rusqlite::{Connection, OptionalExtension};
use serde_json::{json, Map, Value};

use crate::guard_store_cmd_vectors_tests::{insert_rows, temp_home};
use crate::guard_store_op::evaluate_guard_store_request;

const VECTORS: &str = include_str!("../testdata/guard_store/silent_review_vectors.json");

fn scenario<'a>(vectors: &'a Value, name: &str) -> &'a Value {
    vectors["scenarios"]
        .as_array()
        .unwrap()
        .iter()
        .find(|item| item["name"] == name)
        .unwrap()
}

/// Seeds a guard home for `name` and queues its request with `live_wait`.
fn queue(tag: &str, name: &str, live_wait: Option<Value>) -> (Value, Connection) {
    queue_as(tag, name, live_wait, None)
}

fn queue_as(
    tag: &str,
    name: &str,
    live_wait: Option<Value>,
    harness: Option<&str>,
) -> (Value, Connection) {
    queue_with(
        tag,
        name,
        live_wait.map(|wait| ("codex_live_wait", wait)),
        harness,
    )
}

fn queue_with(
    tag: &str,
    name: &str,
    live_wait: Option<(&str, Value)>,
    harness: Option<&str>,
) -> (Value, Connection) {
    let vectors: Value = serde_json::from_str(VECTORS).unwrap();
    let scenario = scenario(&vectors, name);
    let home = temp_home(tag);
    let db = home.join("guard.db");
    let connection = Connection::open(&db).unwrap();
    for statement in vectors["schema_sql"].as_array().unwrap() {
        connection
            .execute_batch(statement.as_str().unwrap())
            .unwrap();
    }
    insert_rows(&connection, "approval_requests", &scenario["rows"]);
    let mut args = Map::new();
    let mut request = scenario["request"].clone();
    if let Some(harness) = harness {
        request["harness"] = Value::from(harness);
    }
    args.insert("request".to_owned(), request);
    args.insert("now".to_owned(), scenario["now"].clone());
    if let Some((key, live_wait)) = live_wait {
        args.insert(key.to_owned(), live_wait);
    }
    let request = GuardStoreRequestV1 {
        schema: GUARD_STORE_REQUEST_SCHEMA.to_owned(),
        request_id: "live-wait".to_owned(),
        store_path: db.to_string_lossy().into_owned(),
        guard_home: home.to_string_lossy().into_owned(),
        method: "add_approval_request".to_owned(),
        source: vectors["source"].as_str().unwrap().to_owned(),
        busy_timeout_ms: 5000,
        args,
    };
    let reply = serde_json::from_slice(&evaluate_guard_store_request(&request).unwrap()).unwrap();
    (reply, Connection::open(&db).unwrap())
}

fn wait() -> Value {
    json!({
        "metadata_json": json!({"codex_thread_id": "thread-1"}).to_string(),
        "workspace": null,
    })
}

fn operation_requests(connection: &Connection, operation_id: &str) -> Option<String> {
    connection
        .query_row(
            "select approval_request_ids_json from guard_operations where operation_id = ?",
            [operation_id],
            |row| row.get(0),
        )
        .optional()
        .unwrap()
}

fn sessions(connection: &Connection, session_id: &str) -> i64 {
    connection
        .query_row(
            "select count(*) from guard_sessions where session_id = ?",
            [session_id],
            |row| row.get(0),
        )
        .unwrap()
}

fn resume(connection: &Connection, request_id: &str) -> Option<(String, String, String)> {
    connection
        .query_row(
            "select operation_id, strategy, status from guard_request_resumes \
             where request_id = ?",
            [request_id],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .optional()
        .unwrap()
}

#[test]
fn the_request_its_operation_and_resume_record_are_written_together() {
    let (reply, connection) = queue("live-wait-fresh", "fresh_native_review", Some(wait()));
    assert_eq!(reply["status"], "ok", "{reply}");
    assert_eq!(
        reply["payload"],
        json!({"request_id": "r-new", "live_wait": "seeded"})
    );
    assert_eq!(
        operation_requests(&connection, "codex-hook-r-new").as_deref(),
        Some(r#"["r-new"]"#)
    );
    assert_eq!(
        resume(&connection, "r-new"),
        Some((
            "codex-hook-r-new".to_owned(),
            "codex-app-server-thread".to_owned(),
            "pending".to_owned()
        ))
    );
}

#[test]
fn the_resident_builds_a_live_bridges_wait_from_its_facts() {
    let (pid, token) = crate::codex_hook_identity::current_process_identity().unwrap();
    let facts = json!({
        "process": {"pid": pid, "startToken": token},
        "timeout_seconds": 90,
        "workspace": null,
    });
    let (reply, connection) = queue_with(
        "live-wait-facts",
        "fresh_native_review",
        Some(("codex_live_wait_facts", facts)),
        None,
    );
    assert_eq!(reply["status"], "ok", "{reply}");
    assert_eq!(
        reply["payload"],
        json!({"request_id": "r-new", "live_wait": "seeded"})
    );
    let metadata: String = connection
        .query_row(
            "select metadata_json from guard_operations where operation_id = 'codex-hook-r-new'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    let metadata: Value = serde_json::from_str(&metadata).unwrap();
    assert_eq!(metadata["codex_browser_wait_timeout_seconds"], 90);
    assert_eq!(
        metadata["codex_browser_wait_deadline_at"],
        "2026-03-01T12:01:30+00:00"
    );
    let snapshot: String = connection
        .query_row(
            "select continuation_snapshot_json from approval_requests where request_id = 'r-new'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    let snapshot: Value = serde_json::from_str(&snapshot).unwrap();
    assert_eq!(snapshot["capability"], "suspended-response");
    assert_eq!(snapshot["waitDeadline"], "2026-03-01T12:01:30+00:00");
    assert_eq!(
        resume(&connection, "r-new").map(|(operation, _, _)| operation),
        Some("codex-hook-r-new".to_owned())
    );
}

#[test]
fn a_bridge_that_is_gone_is_queued_without_a_wait() {
    let (pid, _) = crate::codex_hook_identity::current_process_identity().unwrap();
    let facts = json!({
        "process": {"pid": pid, "startToken": "not-the-start-token"},
        "timeout_seconds": 90,
        "workspace": null,
    });
    let (reply, connection) = queue_with(
        "live-wait-gone",
        "fresh_native_review",
        Some(("codex_live_wait_facts", facts)),
        None,
    );
    assert_eq!(reply["status"], "ok", "{reply}");
    assert_eq!(
        reply["payload"],
        json!({"request_id": "r-new", "live_wait": "not_live"})
    );
    assert_eq!(operation_requests(&connection, "codex-hook-r-new"), None);
    assert_eq!(resume(&connection, "r-new"), None);
}

#[test]
fn a_wait_that_cannot_be_linked_leaves_the_request_retry_only() {
    let (reply, connection) = queue(
        "live-wait-unlinked",
        "fresh_native_review",
        Some(json!({"workspace": null})),
    );
    assert_eq!(reply["status"], "ok", "{reply}");
    let payload = &reply["payload"];
    assert_eq!(payload["request_id"], "r-new", "{reply}");
    assert_ne!(payload["live_wait"], "seeded", "{reply}");
    assert!(payload["live_wait"].is_string(), "{reply}");
    assert_eq!(operation_requests(&connection, "codex-hook-r-new"), None);
    assert_eq!(resume(&connection, "r-new"), None);
}

#[test]
fn a_folded_retry_points_the_stored_request_at_the_waiting_hook() {
    let (reply, connection) = queue(
        "live-wait-dedupe",
        "dedupe_keeps_stored_fields",
        Some(wait()),
    );
    assert_eq!(reply["status"], "ok", "{reply}");
    assert_eq!(
        reply["payload"],
        json!({"request_id": "r-old", "live_wait": "seeded"})
    );
    assert_eq!(
        operation_requests(&connection, "codex-hook-r-old").as_deref(),
        Some(r#"["r-old"]"#)
    );
    assert_eq!(
        resume(&connection, "r-old").map(|(operation, _, status)| (operation, status)),
        Some(("codex-hook-r-old".to_owned(), "pending".to_owned()))
    );
    assert_eq!(operation_requests(&connection, "codex-hook-r-new"), None);
    assert_eq!(sessions(&connection, "codex-hook-r-new"), 0);
}

#[test]
fn a_wait_on_another_harness_is_not_linked() {
    let (reply, connection) = queue_as(
        "live-wait-other-harness",
        "fresh_native_review",
        Some(wait()),
        Some("claude-code"),
    );
    assert_eq!(reply["status"], "ok", "{reply}");
    let payload = &reply["payload"];
    assert_eq!(payload["request_id"], "r-new", "{reply}");
    assert_ne!(payload["live_wait"], "seeded", "{reply}");
    assert_eq!(operation_requests(&connection, "codex-hook-r-new"), None);
    assert_eq!(sessions(&connection, "codex-hook-r-new"), 0);
    assert_eq!(resume(&connection, "r-new"), None);
}

#[test]
fn a_rejected_request_keeps_no_waiting_operation() {
    let (reply, connection) = queue(
        "live-wait-rejected",
        "contradicted_request_rejected",
        Some(wait()),
    );
    assert_eq!(reply["status"], "error", "{reply}");
    assert_eq!(operation_requests(&connection, "codex-hook-r-new"), None);
    let sessions: i64 = connection
        .query_row("select count(*) from guard_sessions", [], |row| row.get(0))
        .unwrap();
    assert_eq!(sessions, 0);
}

#[test]
fn without_a_live_wait_the_reply_is_the_stored_id() {
    let (reply, connection) = queue("live-wait-none", "fresh_native_review", None);
    assert_eq!(reply["status"], "ok", "{reply}");
    assert_eq!(reply["payload"], "r-new");
    assert_eq!(resume(&connection, "r-new"), None);
}

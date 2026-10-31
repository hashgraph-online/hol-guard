//! The Claude review write queues the request recorded in
//! `silent_review_vectors.json` and stores the notice recorded in
//! `claude_review_notice_vectors.json` (both from Python), so the daemon's
//! own `claude_load_notice` reads back exactly what Python sent.

use base64ct::{Base64UrlUnpadded, Encoding};
use guard_contracts::{
    GuardStoreRequestV1, HookAuthorityStateRequestV1, GUARD_STORE_REQUEST_SCHEMA,
    HOOK_AUTHORITY_STATE_REQUEST_SCHEMA,
};
use rusqlite::{params, Connection};
use serde_json::{json, Map, Value};

use crate::guard_store_cmd_vectors_tests::temp_home;
use crate::guard_store_op::evaluate_guard_store_request;

const QUEUE_VECTORS: &str = include_str!("../testdata/guard_store/silent_review_vectors.json");
const NOTICE_VECTORS: &str =
    include_str!("../testdata/guard_store/claude_review_notice_vectors.json");
const KEY: [u8; 32] = [9; 32];
const KEY_ID: &str = "bound-key";

struct Fixture {
    home: std::path::PathBuf,
    source: String,
    request: Value,
    call: Value,
}

/// A store with the daemon's schema, the first recorded request that queues
/// into an empty inbox, and the first recorded notice call.
fn fixture(tag: &str) -> Fixture {
    let queue: Value = serde_json::from_str(QUEUE_VECTORS).unwrap();
    let notices: Value = serde_json::from_str(NOTICE_VECTORS).unwrap();
    let home = temp_home(tag);
    let connection = Connection::open(home.join("guard.db")).unwrap();
    for statement in queue["schema_sql"].as_array().unwrap() {
        connection
            .execute_batch(statement.as_str().unwrap())
            .unwrap();
    }
    let scenario = queue["scenarios"]
        .as_array()
        .unwrap()
        .iter()
        .find(|item| {
            item["native_defers"] != true
                && item["error"].is_null()
                && item["rows"].as_array().is_some_and(Vec::is_empty)
        })
        .unwrap();
    Fixture {
        home,
        source: queue["source"].as_str().unwrap().to_owned(),
        request: scenario["request"].clone(),
        call: notices["scenarios"][0]["calls"][0].clone(),
    }
}

fn write(fixture: &Fixture) -> Value {
    let call = &fixture.call;
    let mut args = Map::new();
    args.insert("request".to_owned(), fixture.request.clone());
    args.insert("now".to_owned(), call["now"].clone());
    args.insert(
        "claude_notice".to_owned(),
        json!({
            "now": call["now"],
            "session_id": call["session_id"],
            "tool_name": call["tool_name"],
            "payload": call["payload"],
            "integrity_key_b64": Base64UrlUnpadded::encode_string(&KEY),
            "integrity_key_id": KEY_ID,
        }),
    );
    let request = GuardStoreRequestV1 {
        schema: GUARD_STORE_REQUEST_SCHEMA.to_owned(),
        request_id: "claude-review".to_owned(),
        store_path: fixture.home.join("guard.db").to_string_lossy().into_owned(),
        guard_home: fixture.home.to_string_lossy().into_owned(),
        method: "add_claude_native_review_approval_request".to_owned(),
        source: fixture.source.clone(),
        busy_timeout_ms: 5000,
        args,
    };
    serde_json::from_slice(&evaluate_guard_store_request(&request).unwrap()).unwrap()
}

/// The daemon's `claude_load_notice`, under the same key.
fn load_notice(fixture: &Fixture) -> Value {
    let call = &fixture.call;
    let request = HookAuthorityStateRequestV1 {
        schema: HOOK_AUTHORITY_STATE_REQUEST_SCHEMA.to_owned(),
        store_path: fixture.home.join("guard.db").to_string_lossy().into_owned(),
        guard_home: fixture.home.to_string_lossy().into_owned(),
        op: "claude_load_notice".to_owned(),
        now: call["now"].as_str().unwrap().to_owned(),
        integrity_key_b64: Some(Base64UrlUnpadded::encode_string(&KEY)),
        integrity_key_id: Some(KEY_ID.to_owned()),
        session_id: call["session_id"].as_str().map(str::to_owned),
        tool_name: call["tool_name"].as_str().map(str::to_owned),
        ..Default::default()
    };
    crate::hook_authority_state_op::evaluate(&request).unwrap()["notice"].clone()
}

fn count(connection: &Connection, table: &str) -> i64 {
    connection
        .query_row(&format!("select count(*) from {table}"), [], |row| {
            row.get(0)
        })
        .unwrap()
}

#[test]
fn the_review_and_its_notice_commit_together() {
    let fixture = fixture("claude-review-notice");
    let reply = write(&fixture);
    assert_eq!(reply["status"], "ok", "{reply}");
    assert_eq!(reply["payload"], fixture.request["request_id"]);
    let mut notice = load_notice(&fixture);
    let notice = notice.as_object_mut().expect("a notice");
    assert_eq!(
        notice["integrity"]["integrity_key_id"], KEY_ID,
        "signed under the bound key"
    );
    notice.remove("integrity");
    let state_key = notice.remove("state_key").unwrap();
    assert_eq!(state_key, "claude_permission_notice:sess-1:Bash");
    assert_eq!(Value::Object(notice.clone()), fixture.call["payload"]);
    let connection = Connection::open(fixture.home.join("guard.db")).unwrap();
    assert_eq!(count(&connection, "approval_requests"), 1);
    let _ = std::fs::remove_dir_all(&fixture.home);
}

#[test]
fn a_row_signed_under_another_key_rolls_the_review_back() {
    let fixture = fixture("claude-review-foreign");
    let connection = Connection::open(fixture.home.join("guard.db")).unwrap();
    let foreign = json!({"session_id": "sess-1", "integrity": {"integrity_key_id": "rotated"}});
    connection
        .execute(
            "insert into sync_state (state_key, payload_json, updated_at) values (?1, ?2, ?3)",
            params![
                "claude_pending_permissions:sess-1",
                foreign.to_string(),
                "2026-03-01T12:00:00+00:00"
            ],
        )
        .unwrap();
    let reply = write(&fixture);
    assert_eq!(reply["status"], "error", "{reply}");
    assert_eq!(
        reply["payload"]["message"], "native_claude_review_notice_foreign_key",
        "{reply}"
    );
    assert_eq!(
        count(&connection, "approval_requests"),
        0,
        "queue rolled back"
    );
    assert_eq!(count(&connection, "sync_state"), 1, "only the foreign row");
    assert_eq!(count(&connection, "guard_events"), 0, "no audit rows");
    drop(connection);
    let _ = std::fs::remove_dir_all(&fixture.home);
}

#[test]
fn a_foreign_notice_without_a_pending_index_stays() {
    let fixture = fixture("claude-review-foreign-notice");
    let connection = Connection::open(fixture.home.join("guard.db")).unwrap();
    let foreign = json!({"session_id": "sess-1", "integrity": {"integrity_key_id": "rotated"}});
    let notice_key = "claude_permission_notice:sess-1:Bash";
    connection
        .execute(
            "insert into sync_state (state_key, payload_json, updated_at) values (?1, ?2, ?3)",
            params![notice_key, foreign.to_string(), "2026-03-01T12:00:00+00:00"],
        )
        .unwrap();
    let reply = write(&fixture);
    assert_eq!(reply["status"], "error", "{reply}");
    assert_eq!(
        reply["payload"]["message"], "native_claude_review_notice_foreign_key",
        "{reply}"
    );
    assert_eq!(
        count(&connection, "approval_requests"),
        0,
        "queue rolled back"
    );
    let stored: String = connection
        .query_row(
            "select payload_json from sync_state where state_key = ?1",
            params![notice_key],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(
        stored,
        foreign.to_string(),
        "notice stays signed under the other key"
    );
    assert_eq!(count(&connection, "guard_events"), 0, "no audit rows");
    drop(connection);
    let _ = std::fs::remove_dir_all(&fixture.home);
}

/// The daemon worker's `add_claude_approval_request` for the first recorded
/// notice scenario, with edits applied to its `claude_review` facts and its
/// top-level args.
fn daemon_write(
    fixture: &Fixture,
    edit: impl FnOnce(&mut Map<String, Value>, &mut Map<String, Value>),
) -> Value {
    let notices: Value = serde_json::from_str(NOTICE_VECTORS).unwrap();
    let scenario = &notices["scenarios"][0];
    let mut review = json!({
        "harness": scenario["harness"],
        "hook_payload": scenario["payload"],
        "reason": scenario["result"]["reason"],
        "review_binding": scenario["binding"],
        "config_path": scenario["workspace"],
        "source_scope": "project",
    })
    .as_object()
    .unwrap()
    .clone();
    let mut args = Map::new();
    args.insert("request".to_owned(), fixture.request.clone());
    args.insert("now".to_owned(), fixture.call["now"].clone());
    args.insert(
        "integrity_key_b64".to_owned(),
        json!(Base64UrlUnpadded::encode_string(&KEY)),
    );
    args.insert("integrity_key_id".to_owned(), json!(KEY_ID));
    edit(&mut review, &mut args);
    args.insert("claude_review".to_owned(), Value::Object(review));
    let request = GuardStoreRequestV1 {
        schema: GUARD_STORE_REQUEST_SCHEMA.to_owned(),
        request_id: "claude-daemon-review".to_owned(),
        store_path: fixture.home.join("guard.db").to_string_lossy().into_owned(),
        guard_home: fixture.home.to_string_lossy().into_owned(),
        method: "add_claude_approval_request".to_owned(),
        source: fixture.source.clone(),
        busy_timeout_ms: 5000,
        args,
    };
    serde_json::from_slice(&evaluate_guard_store_request(&request).unwrap()).unwrap()
}

/// The loaded notice without its signature, state key and random approval
/// code, checking the code is the one its question names.
fn unsigned_notice(fixture: &Fixture) -> Map<String, Value> {
    let mut notice = load_notice(fixture);
    let notice = notice.as_object_mut().expect("a notice");
    assert_eq!(notice["integrity"]["integrity_key_id"], KEY_ID);
    notice.remove("integrity");
    notice.remove("state_key");
    let code = notice.remove("approval_code").unwrap();
    let code = code.as_str().unwrap();
    assert!(code.len() == 12 && code.bytes().all(|byte| byte.is_ascii_hexdigit()));
    let question = notice.remove("approval_question").unwrap();
    assert!(question.as_str().unwrap().contains(code), "{question}");
    notice.clone()
}

fn recorded_without_code(fixture: &Fixture) -> Map<String, Value> {
    let mut recorded = fixture.call["payload"].as_object().unwrap().clone();
    recorded.remove("approval_code");
    recorded.remove("approval_question");
    recorded
}

#[test]
fn the_daemon_queue_records_the_python_notice() {
    let fixture = fixture("claude-daemon-review");
    let reply = daemon_write(&fixture, |_, _| {});
    assert_eq!(reply["status"], "ok", "{reply}");
    assert_eq!(reply["payload"], fixture.request["request_id"]);
    assert_eq!(unsigned_notice(&fixture), recorded_without_code(&fixture));
    let connection = Connection::open(fixture.home.join("guard.db")).unwrap();
    assert_eq!(count(&connection, "approval_requests"), 1);
    drop(connection);
    let _ = std::fs::remove_dir_all(&fixture.home);
}

#[test]
fn a_review_outside_a_workspace_names_the_guard_home() {
    let fixture = fixture("claude-daemon-review-home");
    let reply = daemon_write(&fixture, |review, _| {
        review.insert("config_path".to_owned(), json!("/home/user/.hol-guard"));
        review.insert("source_scope".to_owned(), json!("harness"));
    });
    assert_eq!(reply["status"], "ok", "{reply}");
    let mut expected = recorded_without_code(&fixture);
    expected.insert("config_path".to_owned(), json!("/home/user/.hol-guard"));
    expected.insert("source_scope".to_owned(), json!("harness"));
    assert_eq!(unsigned_notice(&fixture), expected);
    let _ = std::fs::remove_dir_all(&fixture.home);
}

#[test]
fn a_notice_the_daemon_cannot_record_leaves_the_review_queued() {
    for (tag, edit) in [
        ("keyless", "integrity_key_b64"),
        ("sessionless", "session_id"),
        ("unreadable-reason", "reason"),
    ] {
        let fixture = fixture(&format!("claude-daemon-review-{tag}"));
        let reply = daemon_write(&fixture, |review, args| match edit {
            "integrity_key_b64" => {
                args.remove(edit);
            }
            "session_id" => {
                review["hook_payload"]
                    .as_object_mut()
                    .unwrap()
                    .remove("session_id");
            }
            "reason" => {
                review.insert("reason".to_owned(), json!(7));
            }
            key => {
                review.remove(key);
            }
        });
        assert_eq!(reply["status"], "ok", "{tag}: {reply}");
        assert_eq!(reply["payload"], fixture.request["request_id"], "{tag}");
        assert!(load_notice(&fixture).is_null(), "{tag}: no notice");
        let connection = Connection::open(fixture.home.join("guard.db")).unwrap();
        assert_eq!(count(&connection, "approval_requests"), 1, "{tag}");
        drop(connection);
        let _ = std::fs::remove_dir_all(&fixture.home);
    }
}

#[test]
fn a_foreign_notice_row_is_re_signed_under_the_daemon_key() {
    let fixture = fixture("claude-daemon-review-foreign");
    let connection = Connection::open(fixture.home.join("guard.db")).unwrap();
    let foreign = json!({"session_id": "sess-1", "integrity": {"integrity_key_id": "rotated"}});
    connection
        .execute(
            "insert into sync_state (state_key, payload_json, updated_at) values (?1, ?2, ?3)",
            params![
                "claude_pending_permissions:sess-1",
                foreign.to_string(),
                "2026-03-01T12:00:00+00:00"
            ],
        )
        .unwrap();
    let reply = daemon_write(&fixture, |_, _| {});
    assert_eq!(reply["status"], "ok", "{reply}");
    assert_eq!(count(&connection, "approval_requests"), 1, "review stays");
    assert_eq!(
        unsigned_notice(&fixture),
        recorded_without_code(&fixture),
        "the stale row heals and the notice is recorded"
    );
    drop(connection);
    let _ = std::fs::remove_dir_all(&fixture.home);
}

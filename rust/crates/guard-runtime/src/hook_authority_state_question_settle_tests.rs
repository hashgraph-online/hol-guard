//! `claude_question_settle` against the recorded approval-question vectors:
//! the stored pending permission plus the hook's projection must settle the
//! way the verdict and the persist plan did when the hook ran them one by one.

use std::io::Read;

use flate2::read::GzDecoder;
use guard_contracts::{ClaudeGuardQuestionVerdictV1, NativePermissionPersistInputsV1};
use rusqlite::Connection;
use serde_json::{json, Map, Value};

use super::vectors::{events, fresh_store};
use super::Env;
use crate::hook_decision_native_permission_persist::native_permission_persist_plan;

const VECTORS: &[u8] = include_bytes!("../tests/fixtures/claude_guard_question_vectors.json.gz");
const NOW: &str = "2026-10-26T12:00:00.250000+00:00";
const SESSION: &str = "session-1";
const KEY: [u8; 32] = [7; 32];

fn cases() -> Vec<Value> {
    let mut text = String::new();
    GzDecoder::new(VECTORS).read_to_string(&mut text).unwrap();
    let document: Value = serde_json::from_str(&text).unwrap();
    document["cases"].as_array().unwrap().clone()
}

fn env(connection: &Connection) -> Env<'_> {
    Env {
        connection,
        guard_home: None,
        key: Some(zeroize::Zeroizing::new(KEY.to_vec())),
        key_id: Some("test-key"),
        now: NOW,
        foreign_key: None,
    }
}

/// The case's pending permission as the pre-tool hook records it.
fn recorded(pending: &Value) -> Map<String, Value> {
    let mut row = pending.as_object().expect("pending").clone();
    row.insert("session_id".into(), json!(SESSION));
    row.insert("saved_at".into(), json!(NOW));
    row.entry("artifact_hash")
        .or_insert(json!("sha256:artifact"));
    row.entry("command").or_insert(json!("rm -rf build"));
    row
}

/// The case request without `pending`: the op reads it from the store.
fn projection(case: &Value) -> Value {
    let mut question = case["request"].clone();
    question.as_object_mut().expect("request").remove("pending");
    question
}

fn settle(connection: &Connection, row: &Map<String, Value>, question: Option<&Value>) -> Value {
    let env = env(connection);
    env.claude_record_notice(SESSION, Some("Bash"), &Value::Object(row.clone()));
    env.claude_question_settle(SESSION, question, Some("/home/user"))
        .expect("settle")
}

#[test]
fn settles_every_recorded_question() {
    let cases = cases();
    assert_eq!(cases.len(), 90);
    for case in cases {
        let name = case["name"].as_str().unwrap();
        let (path, connection) = fresh_store("question-settle");
        let row = recorded(&case["pending"]);
        let reply = settle(&connection, &row, Some(&projection(&case)));
        let expected: ClaudeGuardQuestionVerdictV1 =
            serde_json::from_value(case["expected"].clone()).unwrap();
        let seen = row.get("permission_prompt_seen") == Some(&Value::Bool(true));
        let outcome = reply["outcome"].as_str().unwrap();
        match (expected.is_question, seen, expected.action) {
            (false, _, _) => assert_eq!(outcome, "none", "{name}"),
            (true, false, _) => assert_eq!(outcome, "unseen", "{name}"),
            (true, true, None) => assert_eq!(outcome, "unanswered", "{name}"),
            (true, true, Some(action)) => {
                let reason = if action == "allow" {
                    "Allowed through HOL Guard AskUserQuestion approval."
                } else {
                    "Blocked through HOL Guard AskUserQuestion approval."
                };
                let plan = native_permission_persist_plan(&NativePermissionPersistInputsV1 {
                    artifact_id: row["artifact_id"].as_str().unwrap().to_owned(),
                    artifact_hash: row["artifact_hash"].as_str().unwrap().to_owned(),
                    artifact_type: None,
                    config_path: None,
                    source_scope: None,
                    raw_command_text: None,
                    wrapper_chain: None,
                    action,
                    reason: reason.to_owned(),
                    source: "claude-ask-user-question".to_owned(),
                    authoritative_action: None,
                    tilde_home: Some("/home/user".to_owned()),
                })
                .unwrap();
                let mut comparable = reply.clone();
                comparable
                    .as_object_mut()
                    .expect("save reply")
                    .remove("pending_id");
                assert_eq!(
                    comparable,
                    json!({
                        "outcome": "save",
                        "artifact_id": row["artifact_id"],
                        "pending_artifact_hash": row["artifact_hash"],
                        "reason": reason,
                        "source": "claude-ask-user-question",
                        "plan": serde_json::to_value(plan).unwrap(),
                    }),
                    "{name}"
                );
            }
        }
        drop(connection);
        let _ = std::fs::remove_file(path);
    }
}

#[test]
fn an_unseen_prompt_is_recorded_and_left_pending() {
    let case = cases()
        .into_iter()
        .find(|case| case["name"] == "answers-keyed-allow-once")
        .unwrap();
    let (path, connection) = fresh_store("question-settle-unseen");
    let mut row = recorded(&case["pending"]);
    row.insert("permission_prompt_seen".into(), json!(false));
    let reply = settle(&connection, &row, Some(&projection(&case)));
    assert_eq!(reply, json!({ "outcome": "unseen" }));
    let unseen: Vec<_> = events(&connection)
        .into_iter()
        .filter(|(name, _, _)| name == "approval.pending_prompt_unseen")
        .collect();
    assert_eq!(unseen.len(), 1);
    let payload: Value = serde_json::from_str(&unseen[0].1).unwrap();
    assert_eq!(payload["artifact_id"], row["artifact_id"]);
    assert_eq!(payload["session_id"], json!(SESSION));
    assert!(env(&connection)
        .claude_load_single_pending(SESSION)
        .is_some());
    drop(connection);
    let _ = std::fs::remove_file(path);
}

#[test]
fn without_a_question_nothing_settles() {
    let case = &cases()[0];
    let (path, connection) = fresh_store("question-settle-none");
    let reply = settle(&connection, &recorded(&case["pending"]), None);
    assert_eq!(reply, json!({ "outcome": "none" }));
    let empty = fresh_store("question-settle-empty");
    assert_eq!(
        env(&empty.1)
            .claude_question_settle(SESSION, Some(&projection(case)), None)
            .unwrap(),
        json!({ "outcome": "none" })
    );
    drop(connection);
    drop(empty.1);
    let _ = std::fs::remove_file(path);
    let _ = std::fs::remove_file(empty.0);
}

#[test]
fn the_pending_artifact_details_reach_the_plan() {
    let case = cases()
        .into_iter()
        .find(|case| case["name"] == "answers-keyed-allow-once")
        .unwrap();
    let (path, connection) = fresh_store("question-settle-details");
    let mut row = recorded(&case["pending"]);
    row.insert(
        "config_path".into(),
        json!("/home/user/.claude/settings.json"),
    );
    row.insert("source_scope".into(), json!("project"));
    let reply = settle(&connection, &row, Some(&projection(&case)));
    let plan = native_permission_persist_plan(&NativePermissionPersistInputsV1 {
        artifact_id: row["artifact_id"].as_str().unwrap().to_owned(),
        artifact_hash: row["artifact_hash"].as_str().unwrap().to_owned(),
        artifact_type: None,
        config_path: Some("/home/user/.claude/settings.json".to_owned()),
        source_scope: Some("project".to_owned()),
        raw_command_text: None,
        wrapper_chain: None,
        action: "allow".to_owned(),
        reason: "Allowed through HOL Guard AskUserQuestion approval.".to_owned(),
        source: "claude-ask-user-question".to_owned(),
        authoritative_action: None,
        tilde_home: Some("/home/user".to_owned()),
    })
    .unwrap();
    assert_eq!(reply["plan"], serde_json::to_value(plan).unwrap());
    drop(connection);
    let _ = std::fs::remove_file(path);
}

#[test]
fn question_save_persists_the_plan_and_consumes_pending_state() {
    let case = cases()
        .into_iter()
        .find(|case| case["name"] == "answers-keyed-allow-once")
        .unwrap();
    let (path, connection) = fresh_store("question-save");
    connection
        .execute_batch(
            "create table policy_decisions (
                decision_id integer primary key autoincrement,
                harness text not null,
                scope text not null,
                artifact_id text,
                artifact_hash text,
                workspace text,
                publisher text,
                action text not null,
                reason text,
                owner text,
                source text not null,
                expires_at text,
                updated_at text,
                integrity_version integer,
                integrity_generation integer,
                payload_hash text,
                payload_mac text,
                integrity_key_id text,
                signed_at text
            )",
        )
        .expect("policy schema");
    let mut row = recorded(&case["pending"]);
    row.insert("artifact_type".into(), json!("tool_action_request"));
    let reply = settle(&connection, &row, Some(&projection(&case)));
    assert_eq!(reply["outcome"], "save");
    let mut save = reply.as_object().unwrap().clone();
    save.insert("session_id".into(), json!(SESSION));
    save.insert("current_generation".into(), json!(0));
    let saved = env(&connection)
        .claude_question_save(SESSION, &save)
        .expect("save");
    assert_eq!(saved["valid"], true);
    assert_eq!(saved["saved"], true);
    assert!(saved["next_control_state"].is_object());
    assert!(env(&connection)
        .claude_load_single_pending(SESSION)
        .is_some());
    env(&connection)
        .claude_question_consume(SESSION, &save)
        .expect("consume");
    assert!(env(&connection)
        .claude_load_single_pending(SESSION)
        .is_none());
    let action: String = connection
        .query_row(
            "select action from policy_decisions where harness='claude-code' and scope='artifact'",
            [],
            |row| row.get(0),
        )
        .expect("policy row");
    assert_eq!(action, "allow");
    drop(connection);
    let _ = std::fs::remove_file(path);
}

#[test]
fn question_save_rejects_a_plan_without_its_required_event_sequence() {
    let (path, connection) = fresh_store("question-save-invalid-plan");
    connection
        .execute_batch(
            "create table policy_decisions (
                decision_id integer primary key autoincrement,
                harness text not null, scope text not null, artifact_id text,
                artifact_hash text, workspace text, publisher text, action text not null,
                reason text, owner text, source text not null, expires_at text,
                updated_at text, integrity_version integer, integrity_generation integer,
                payload_hash text, payload_mac text, integrity_key_id text, signed_at text
            )",
        )
        .expect("policy schema");
    let payload = json!({
        "artifact_id": "artifact",
        "reason": "reason",
        "source": "claude-ask-user-question",
        "plan": {
            "stored_artifact_hash": "sha256:artifact",
            "policy_action": "allow",
            "events": [],
            "inventory_approved": false
        }
    });
    assert_eq!(
        env(&connection).claude_question_save(SESSION, payload.as_object().unwrap()),
        Err(super::ERROR_INVALID)
    );
    assert_eq!(
        connection
            .query_row("select count(*) from policy_decisions", [], |row| {
                row.get::<_, i64>(0)
            })
            .unwrap(),
        0
    );
    drop(connection);
    let _ = std::fs::remove_file(path);
}

#[test]
fn question_save_rejects_a_remote_policy_source() {
    let (path, connection) = fresh_store("question-save-remote-source");
    let payload = json!({
        "artifact_id": "artifact",
        "reason": "reason",
        "source": "cloud-sync",
        "plan": {
            "stored_artifact_hash": "sha256:artifact",
            "policy_action": "allow",
            "events": [{
                "name": "claude/native_permission_saved",
                "payload": {},
                "before_policy": false
            }],
            "inventory_approved": false
        }
    });
    assert_eq!(
        env(&connection).claude_question_save(SESSION, payload.as_object().unwrap()),
        Err(super::ERROR_INVALID)
    );
    drop(connection);
    let _ = std::fs::remove_file(path);
}

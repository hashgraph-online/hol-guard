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
                assert_eq!(
                    reply,
                    json!({
                        "outcome": "save",
                        "artifact_id": row["artifact_id"],
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

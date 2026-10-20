//! Parity vectors recorded from the retired Python hook authority state helpers
//! (`commands_support_hook_state`) on top of a real `GuardStore`. Each scenario
//! is replayed against a SQLite store holding the same two tables; after every
//! op the Claude and Cursor `sync_state` rows and the audit events must equal
//! what the Python left behind.

use std::collections::BTreeMap;

use guard_contracts::{HookAuthorityStateRequestV1, HOOK_AUTHORITY_STATE_REQUEST_SCHEMA};
use rusqlite::{params, Connection};
use serde_json::{json, Map, Value};

use super::evaluate;
use crate::store_vectors_support_tests::gunzip_json;

const VECTORS: &[u8] = include_bytes!("../tests/fixtures/hook_authority_state_vectors.json.gz");
const T0: &str = "2026-10-11T12:00:00.250000+00:00";

pub(super) fn fresh_store(label: &str) -> (std::path::PathBuf, Connection) {
    let path = std::env::temp_dir().join(format!("hook-state-{label}-{}.db", std::process::id()));
    let _ = std::fs::remove_file(&path);
    let connection = Connection::open(&path).expect("open store");
    connection
        .execute_batch(
            "create table sync_state (state_key text primary key, payload_json text not null, updated_at text not null);
             create table guard_events (event_name text not null, payload_json text not null, occurred_at text not null);",
        )
        .expect("schema");
    (path, connection)
}

pub(super) fn owned_rows(connection: &Connection) -> BTreeMap<String, (Value, String)> {
    let mut statement = connection
        .prepare(
            "select state_key, payload_json, updated_at from sync_state \
             where state_key like 'claude\\_%' escape '\\' or state_key like 'cursor\\_%' escape '\\'",
        )
        .expect("prepare");
    statement
        .query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
            ))
        })
        .expect("query")
        .map(|row| {
            let (key, text, updated_at) = row.expect("row");
            let payload =
                serde_json::from_str(&text).unwrap_or_else(|_| json!({ "__raw__": text }));
            (key, (payload, updated_at))
        })
        .collect()
}

pub(super) fn events(connection: &Connection) -> Vec<(String, String, String)> {
    let mut statement = connection
        .prepare("select event_name, payload_json, occurred_at from guard_events")
        .expect("prepare");
    let mut rows: Vec<(String, String, String)> = statement
        .query_map([], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)))
        .expect("query")
        .map(|row| {
            let (name, text, occurred_at): (String, String, String) = row.expect("row");
            let payload: Value = serde_json::from_str(&text).expect("event json");
            (name, payload.to_string(), occurred_at)
        })
        .collect();
    rows.sort();
    rows
}

fn recorded_events(after: &Value) -> Vec<(String, String, String)> {
    let mut rows: Vec<(String, String, String)> = after["events"]
        .as_array()
        .expect("events")
        .iter()
        .map(|event| {
            (
                event["event_name"].as_str().expect("name").to_owned(),
                event["payload"].to_string(),
                event["occurred_at"].as_str().expect("at").to_owned(),
            )
        })
        .collect();
    rows.sort();
    rows
}

fn recorded_rows(after: &Value) -> BTreeMap<String, (Value, String)> {
    after["sync_state"]
        .as_object()
        .expect("sync_state")
        .iter()
        .filter(|(key, _)| key.starts_with("claude_") || key.starts_with("cursor_"))
        .map(|(key, row)| {
            (
                key.clone(),
                (
                    row["payload"].clone(),
                    row["updated_at"].as_str().expect("updated").to_owned(),
                ),
            )
        })
        .collect()
}

pub(super) fn recorded_vectors() -> Value {
    gunzip_json(VECTORS)
}

/// Applies a raw store action; `false` for an `op` action.
pub(super) fn apply_raw(connection: &Connection, action: &Value) -> bool {
    let at = action.get("now").and_then(Value::as_str).unwrap_or(T0);
    let key = action.get("key").and_then(Value::as_str);
    match action["do"].as_str().expect("kind") {
        "raw_set" => {
            connection
                .execute(
                    "insert or replace into sync_state (state_key, payload_json, updated_at) values (?1, ?2, ?3)",
                    params![key.expect("key"), action["payload"].to_string(), at],
                )
                .expect("raw set");
        }
        "raw_set_text" => {
            connection
                .execute(
                    "insert or replace into sync_state (state_key, payload_json, updated_at) values (?1, ?2, ?3)",
                    params![key.expect("key"), action["text"].as_str().expect("text"), at],
                )
                .expect("raw set text");
        }
        "raw_delete" => {
            connection
                .execute(
                    "delete from sync_state where state_key = ?1",
                    params![key.expect("key")],
                )
                .expect("raw delete");
        }
        // The key each op ran with is recorded on the op itself.
        "key" => {}
        _ => return false,
    }
    true
}

/// The resident request a recorded `op` action replays against `path`.
pub(super) fn op_request(
    action: &Value,
    path: &std::path::Path,
    key_b64: &str,
) -> HookAuthorityStateRequestV1 {
    let mut wire: Map<String, Value> = action["args"].as_object().expect("args").clone();
    wire.insert("schema".into(), json!(HOOK_AUTHORITY_STATE_REQUEST_SCHEMA));
    wire.insert("op".into(), action["op"].clone());
    wire.insert("store_path".into(), json!(path.to_string_lossy()));
    wire.insert(
        "guard_home".into(),
        json!(std::env::temp_dir().to_string_lossy()),
    );
    if action["key_present"].as_bool().expect("key_present") {
        wire.insert("integrity_key_b64".into(), json!(key_b64));
        wire.insert("integrity_key_id".into(), action["key_id"].clone());
    }
    serde_json::from_value(Value::Object(wire)).expect("recorded request")
}

#[test]
fn state_transitions_match_the_retired_python() {
    let vectors = recorded_vectors();
    let key_b64 = vectors["key_b64"].as_str().expect("key").to_owned();
    let scenarios = vectors["scenarios"].as_array().expect("scenarios");
    assert!(scenarios.len() >= 29);
    let mut ops = 0;
    for scenario in scenarios {
        let name = scenario["name"].as_str().expect("name");
        let (path, connection) = fresh_store(name);
        for (step, action) in scenario["actions"]
            .as_array()
            .expect("actions")
            .iter()
            .enumerate()
        {
            let label = format!("{name} step {step}");
            if apply_raw(&connection, action) {
                continue;
            }
            match action["do"].as_str().expect("kind") {
                "op" => {
                    ops += 1;
                    let op = action["op"].as_str().expect("op");
                    let request = op_request(action, &path, &key_b64);
                    let mut result =
                        evaluate(&request).unwrap_or_else(|code| panic!("{label}: {code}"));
                    if op == "cursor_store_pending_state" {
                        // The retired Python only said whether it stored the row;
                        // the resident also names it, and the name must be the key
                        // the recorded request carried.
                        let named = result
                            .as_object_mut()
                            .and_then(|reply| reply.remove("state_key"));
                        assert_eq!(
                            named.as_ref(),
                            Some(&action["args"]["state_key"]),
                            "{label}: {op} state_key"
                        );
                    }
                    if op != "claude_record_notice" {
                        assert_eq!(result, action["result"], "{label}: {op} result");
                    }
                    assert_eq!(
                        owned_rows(&connection),
                        recorded_rows(&action["after"]),
                        "{label}: {op} sync_state"
                    );
                    assert_eq!(
                        events(&connection),
                        recorded_events(&action["after"]),
                        "{label}: {op} events"
                    );
                }
                other => panic!("unknown action {other}"),
            }
        }
        drop(connection);
        let _ = std::fs::remove_file(&path);
    }
    assert!(ops > 150, "only {ops} ops replayed");
}

#[test]
fn a_foreign_schema_or_op_is_refused() {
    let mut request = HookAuthorityStateRequestV1 {
        schema: "other".into(),
        op: "state_is_fresh".into(),
        now: T0.into(),
        ..Default::default()
    };
    assert_eq!(
        evaluate(&request),
        Err("native_hook_authority_state_schema_mismatch")
    );
    request.schema = HOOK_AUTHORITY_STATE_REQUEST_SCHEMA.into();
    request.op = "nope".into();
    request.store_path = "/nonexistent/dir/guard.db".into();
    assert_eq!(
        evaluate(&request),
        Err("native_hook_authority_state_store_unavailable")
    );
}

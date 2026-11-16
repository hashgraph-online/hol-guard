use guard_contracts::{GuardStoreRequestV1, GUARD_STORE_REQUEST_SCHEMA};
use rusqlite::Connection;
use serde_json::{json, Map, Value};

use super::{call_key, LOOKUP_METHOD, RECORD_METHOD};
use crate::guard_store_cmd_vectors_tests::temp_home;
use crate::guard_store_op::evaluate_guard_store_request;

fn payload(call_id: &str, command: &str) -> Map<String, Value> {
    json!({
        "hook_event_name": "PreToolUse",
        "tool_call_id": call_id,
        "tool_name": "bash",
        "tool_input": {"command": command},
    })
    .as_object()
    .unwrap()
    .clone()
}

fn seeded_home(tag: &str) -> std::path::PathBuf {
    let home = temp_home(tag);
    Connection::open(home.join("guard.db"))
        .unwrap()
        .execute_batch(
            "create table guard_review_outbox_events (
                stream_sequence integer primary key,
                payload_hash text not null default ''
            );
            create table guard_continuation_effects (
                effect_key text primary key,
                request_id text not null,
                evidence_id text not null,
                event_name text not null,
                created_at text not null
            )",
        )
        .unwrap();
    home
}

fn call(home: &std::path::Path, method: &str, payload: &Map<String, Value>, now: &str) -> Value {
    let mut args = Map::new();
    args.insert("harness".to_owned(), json!("omp"));
    args.insert("payload".to_owned(), Value::Object(payload.clone()));
    args.insert("now".to_owned(), json!(now));
    let request = GuardStoreRequestV1 {
        schema: GUARD_STORE_REQUEST_SCHEMA.to_owned(),
        request_id: "admitted-call".to_owned(),
        store_path: home.join("guard.db").to_string_lossy().into_owned(),
        guard_home: home.to_string_lossy().into_owned(),
        method: method.to_owned(),
        source: "default".to_owned(),
        busy_timeout_ms: 5000,
        args,
    };
    let reply: Value =
        serde_json::from_slice(&evaluate_guard_store_request(&request).unwrap()).unwrap();
    assert_eq!(reply["status"], "ok", "{reply}");
    reply["payload"].clone()
}

const AT: &str = "2026-01-01T00:00:00+00:00";

#[test]
fn key_needs_a_proven_call_id_name_and_object_input() {
    let base = payload("call-1", "ls -la");
    assert!(call_key("omp", &base).is_some());
    assert_eq!(call_key("OMP", &base), call_key("omp", &base));
    assert!(call_key("cursor", &base).is_none());
    assert!(call_key("claude-code", &base).is_none());
    let mut blank = base.clone();
    blank.insert("tool_call_id".to_owned(), json!("  "));
    assert!(call_key("omp", &blank).is_none());
    let mut long = base.clone();
    long.insert("tool_call_id".to_owned(), json!("x".repeat(513)));
    assert!(call_key("omp", &long).is_none());
    let mut text_input = base.clone();
    text_input.insert("tool_input".to_owned(), json!("ls -la"));
    assert!(call_key("omp", &text_input).is_none());
    assert_ne!(call_key("omp", &base), call_key("pi", &base));
    assert_ne!(
        call_key("omp", &base),
        call_key("omp", &payload("call-1", "ls -l"))
    );
}

#[test]
fn post_tool_use_finds_only_the_admitted_call() {
    let home = seeded_home("admitted-call-match");
    let admitted = payload("call-1", "ls -la");
    assert_eq!(call(&home, LOOKUP_METHOD, &admitted, AT), json!(false));
    assert_eq!(call(&home, RECORD_METHOD, &admitted, AT), json!(true));
    assert_eq!(call(&home, RECORD_METHOD, &admitted, AT), json!(false));

    let mut post = admitted.clone();
    post.insert("hook_event_name".to_owned(), json!("PostToolUse"));
    post.insert("tool_response".to_owned(), json!({"output": "total 0"}));
    assert_eq!(call(&home, LOOKUP_METHOD, &post, AT), json!(true));
    assert_eq!(
        call(&home, LOOKUP_METHOD, &payload("call-2", "ls -la"), AT),
        json!(false)
    );
    assert_eq!(
        call(&home, LOOKUP_METHOD, &payload("call-1", "cat .env"), AT),
        json!(false)
    );
}

#[test]
fn witness_lasts_one_hour() {
    let home = seeded_home("admitted-call-window");
    let admitted = payload("call-1", "ls -la");
    assert_eq!(call(&home, RECORD_METHOD, &admitted, AT), json!(true));
    assert_eq!(
        call(&home, LOOKUP_METHOD, &admitted, "2026-01-01T01:00:00+00:00"),
        json!(true)
    );
    assert_eq!(
        call(&home, LOOKUP_METHOD, &admitted, "2026-01-01T01:00:01+00:00"),
        json!(false)
    );
    assert_eq!(
        call(&home, LOOKUP_METHOD, &admitted, "2025-12-31T23:59:59+00:00"),
        json!(false)
    );
}

//! A saved decision is handed to a waiting Codex hook only while the hook is
//! live: ports of the live-hook deferral tests of `codex_resume.py`.

use std::path::{Path, PathBuf};

use rusqlite::Connection;
use serde_json::{json, Value};

use super::hook_is_waiting;
use crate::codex_hook_identity::current_process_identity;
use crate::codex_request_resume_op::Call;
use crate::guard_store_cmd_vectors_tests::temp_home;

const STARTED: &str = "2026-05-19T10:00:00+00:00";

fn live_process() -> Value {
    let (pid, token) = current_process_identity().expect("this process has a start token");
    json!({"pid": pid, "startToken": token})
}

fn home(tag: &str, config: &str) -> PathBuf {
    let home = temp_home(tag);
    std::fs::write(home.join("config.toml"), config).unwrap();
    home
}

fn store(harness: &str, status: &str, metadata: &Value) -> Connection {
    let connection = Connection::open_in_memory().unwrap();
    connection
        .execute_batch(
            "create table guard_operations (
               operation_id text primary key, session_id text not null, harness text not null,
               operation_type text not null, status text not null,
               approval_request_ids_json text not null, resume_token text,
               metadata_json text not null, created_at text not null, updated_at text not null);",
        )
        .unwrap();
    connection
        .execute(
            "insert into guard_operations values ('op-1', 's-1', ?, 'tool', ?, ?, null, ?, ?, ?)",
            rusqlite::params![
                harness,
                status,
                json!(["req-1"]).to_string(),
                metadata.to_string(),
                STARTED,
                STARTED,
            ],
        )
        .unwrap();
    connection
}

fn waiting(connection: &Connection, now: &str, guard_home: &Path) -> bool {
    let call = Call {
        request_id: "req-1",
        now,
    };
    hook_is_waiting(connection, &call, guard_home).unwrap()
}

fn pretool(extra: Value) -> Value {
    let mut metadata = json!({
        "codex_browser_wait_process": live_process(),
        "hook_event_name": "PreToolUse",
    });
    metadata
        .as_object_mut()
        .unwrap()
        .extend(extra.as_object().unwrap().clone());
    metadata
}

#[test]
fn the_pretool_bridge_wait_follows_the_codex_hook_hold_formula() {
    let guard_home = home("resume-hold", "approval_wait_timeout_seconds = 1\n");
    let connection = store("codex", "waiting_on_approval", &pretool(json!({})));
    assert!(waiting(
        &connection,
        "2026-05-19T10:00:04+00:00",
        &guard_home
    ));
    assert!(!waiting(
        &connection,
        "2026-05-19T10:00:05+00:00",
        &guard_home
    ));
}

#[test]
fn an_unreadable_config_holds_for_the_default_wait() {
    let guard_home = home("resume-default", "approval_wait_timeout_seconds = [\n");
    let connection = store("codex", "waiting_on_approval", &pretool(json!({})));
    assert!(waiting(
        &connection,
        "2026-05-19T10:02:03+00:00",
        &guard_home
    ));
    assert!(!waiting(
        &connection,
        "2026-05-19T10:02:04+00:00",
        &guard_home
    ));
}

#[test]
fn a_pretool_event_named_only_by_event_still_holds() {
    let guard_home = home("resume-event", "approval_wait_timeout_seconds = 1\n");
    let metadata = json!({"codex_browser_wait_process": live_process(), "event": "PreToolUse"});
    let connection = store("codex", "waiting_on_approval", &metadata);
    assert!(waiting(
        &connection,
        "2026-05-19T10:00:04+00:00",
        &guard_home
    ));
}

#[test]
fn an_explicit_browser_wait_deadline_bounds_the_hold() {
    let guard_home = home("resume-explicit", "approval_wait_timeout_seconds = 1\n");
    let metadata = json!({
        "codex_browser_wait_process": live_process(),
        "codex_hook_waits_for_browser_approval": true,
        "codex_browser_wait_deadline_at": "2026-05-19T10:10:00Z",
    });
    let connection = store("codex", "waiting_on_approval", &metadata);
    assert!(waiting(
        &connection,
        "2026-05-19T10:10:00+00:00",
        &guard_home
    ));
    assert!(!waiting(
        &connection,
        "2026-05-19T10:10:01+00:00",
        &guard_home
    ));
    // A naive caller clock is UTC.
    assert!(waiting(&connection, "2026-05-19T10:09:59", &guard_home));
}

#[test]
fn a_hook_that_does_not_wait_for_the_browser_has_no_explicit_deadline() {
    let guard_home = home("resume-no-wait", "approval_wait_timeout_seconds = 1\n");
    let metadata = json!({
        "codex_browser_wait_process": live_process(),
        "codex_browser_wait_deadline_at": "2026-05-19T10:10:00+00:00",
    });
    let connection = store("codex", "waiting_on_approval", &metadata);
    assert!(!waiting(
        &connection,
        "2026-05-19T10:00:01+00:00",
        &guard_home
    ));
}

#[test]
fn a_process_that_is_not_the_recorded_one_is_not_waiting() {
    let guard_home = home("resume-dead", "approval_wait_timeout_seconds = 1\n");
    let (pid, _) = current_process_identity().unwrap();
    let metadata = json!({
        "codex_browser_wait_process": {"pid": pid, "startToken": "posix:other"},
        "codex_hook_waits_for_browser_approval": true,
        "codex_browser_wait_deadline_at": "2026-05-19T10:10:00+00:00",
        "hook_event_name": "PreToolUse",
    });
    let connection = store("codex", "waiting_on_approval", &metadata);
    assert!(!waiting(
        &connection,
        "2026-05-19T10:00:01+00:00",
        &guard_home
    ));
}

#[test]
fn only_a_waiting_codex_operation_can_be_deferred() {
    let guard_home = home("resume-refused", "approval_wait_timeout_seconds = 1\n");
    let now = "2026-05-19T10:00:01+00:00";
    let other = store("claude-code", "waiting_on_approval", &pretool(json!({})));
    assert!(!waiting(&other, now, &guard_home));
    let done = store("codex", "completed", &pretool(json!({})));
    assert!(!waiting(&done, now, &guard_home));
    let neither = store("codex", "waiting_on_approval", &json!({}));
    assert!(!waiting(&neither, now, &guard_home));
    let other_event = store(
        "codex",
        "waiting_on_approval",
        &pretool(json!({"hook_event_name": "PostToolUse"})),
    );
    assert!(!waiting(&other_event, now, &guard_home));
    let no_operation = store("codex", "waiting_on_approval", &pretool(json!({})));
    no_operation
        .execute(
            "update guard_operations set approval_request_ids_json = '[]'",
            [],
        )
        .unwrap();
    assert!(!waiting(&no_operation, now, &guard_home));
}

#[test]
fn an_unparseable_caller_clock_is_never_waiting() {
    let guard_home = home("resume-clock", "approval_wait_timeout_seconds = 1\n");
    let connection = store("codex", "waiting_on_approval", &pretool(json!({})));
    assert!(!waiting(&connection, "not a time", &guard_home));
}

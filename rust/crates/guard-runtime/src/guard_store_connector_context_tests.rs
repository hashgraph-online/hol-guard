//! Scrubbing and the write itself, against a temporary `guard.db` that carries
//! the context columns `store_local_cli_context.py` adds.

use std::fs;
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};

use guard_contracts::{GuardStoreRequestV1, GUARD_STORE_REQUEST_SCHEMA};
use rusqlite::Connection;
use serde_json::{json, Value};

use super::{
    is_first_blocked_cause, scrub_context_text, strip_url_detail, FIRST_BLOCKED_CAUSES,
    MAX_LABEL_CHARS, MAX_SUMMARY_CHARS,
};
use crate::guard_store_op::evaluate;

const CLI_ID: &str = "local-cli.lanectl-1";
const HASH: &str = "abababababababababababababababababababababababababababababababab";
const NOW: &str = "2026-01-02T03:04:05Z";
const SCHEMA: &str = "
create table guard_review_outbox_events (
    stream_sequence integer primary key,
    payload_hash text not null default ''
);
create table local_cli_observation (
    cli_id text primary key,
    identity_hash text not null,
    kind text not null,
    name text not null,
    example_label text not null,
    observed_count integer not null,
    last_seen_at text not null,
    surface text not null default 'cli',
    first_blocked_cause text,
    last_trigger_summary text,
    last_why_now text,
    last_harness text,
    last_workspace_label text,
    last_context_at text
);
insert into local_cli_observation (cli_id, identity_hash, kind, name, example_label,
    observed_count, last_seen_at)
values ('local-cli.lanectl-1',
    'abababababababababababababababababababababababababababababababab',
    'executable', 'lanectl', 'lanectl', 1, '2026-01-01T00:00:00Z');
";

static COUNTER: AtomicUsize = AtomicUsize::new(0);

struct Home(PathBuf);

impl Home {
    fn new() -> Self {
        let home = std::env::temp_dir().join(format!(
            "hol-guard-connector-context-{}-{}",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&home).unwrap();
        Connection::open(home.join("guard.db"))
            .unwrap()
            .execute_batch(SCHEMA)
            .unwrap();
        Self(home)
    }

    fn record(&self, args: Value) -> Result<Value, &'static str> {
        let Value::Object(args) = args else {
            panic!("args must be an object");
        };
        evaluate(&GuardStoreRequestV1 {
            schema: GUARD_STORE_REQUEST_SCHEMA.to_owned(),
            request_id: "context-test".to_owned(),
            store_path: self.0.join("guard.db").to_string_lossy().into_owned(),
            guard_home: self.0.to_string_lossy().into_owned(),
            method: "record_connector_setup_context".to_owned(),
            source: "local".to_owned(),
            busy_timeout_ms: 5000,
            args,
        })
        .map(|(payload, _)| payload)
        .map_err(|error| error.code())
    }

    fn columns(&self) -> [Option<String>; 6] {
        Connection::open(self.0.join("guard.db"))
            .unwrap()
            .query_row(
                "select first_blocked_cause, last_trigger_summary, last_why_now, last_harness, \
                 last_workspace_label, last_context_at from local_cli_observation",
                [],
                |row| {
                    Ok([
                        row.get(0)?,
                        row.get(1)?,
                        row.get(2)?,
                        row.get(3)?,
                        row.get(4)?,
                        row.get(5)?,
                    ])
                },
            )
            .unwrap()
    }
}

impl Drop for Home {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn args(extra: Value) -> Value {
    let mut base = json!({"cli_id": CLI_ID, "identity_hash": HASH, "observed_at": NOW});
    base.as_object_mut()
        .unwrap()
        .extend(extra.as_object().unwrap().clone());
    base
}

#[test]
fn every_known_cause_is_accepted_and_others_are_not() {
    assert_eq!(FIRST_BLOCKED_CAUSES.len(), 5);
    for cause in FIRST_BLOCKED_CAUSES {
        assert!(is_first_blocked_cause(cause));
    }
    for other in [
        "",
        "Exec_Outside_Roots",
        "exec_outside_roots ",
        "network",
        "other",
    ] {
        assert!(!is_first_blocked_cause(other), "{other}");
    }
}

#[test]
fn urls_keep_scheme_host_and_path_only() {
    assert_eq!(
        strip_url_detail("open https://user:pw@mcp.example.test/v1/tools?token=abc#frag now"),
        "open https://mcp.example.test/v1/tools now"
    );
    assert_eq!(
        strip_url_detail("a http://mcp.example.test?q=1 b https://x.example.test/p"),
        "a http://mcp.example.test b https://x.example.test/p"
    );
    assert_eq!(strip_url_detail("no url here"), "no url here");
}

#[test]
fn scrubbed_text_has_no_secret_credential_or_query() {
    let text = scrub_context_text(
        "Authorization: Bearer abcdef0123456789 sent to https://u:p@mcp.example.test/a?k=v",
        MAX_SUMMARY_CHARS,
    )
    .unwrap();
    for leaked in ["abcdef0123456789", "u:p@", "k=v", "?"] {
        assert!(!text.contains(leaked), "{leaked} in {text}");
    }
    assert!(text.contains("https://mcp.example.test/a"), "{text}");
}

#[test]
fn whitespace_collapses_and_control_characters_drop() {
    assert_eq!(
        scrub_context_text("  runs\n\tlanectl \u{7} sync  ", MAX_LABEL_CHARS).as_deref(),
        Some("runs lanectl sync")
    );
    assert_eq!(scrub_context_text(" \n\t ", MAX_LABEL_CHARS), None);
    assert_eq!(scrub_context_text("", MAX_LABEL_CHARS), None);
}

#[test]
fn text_is_capped_by_characters() {
    let long = "é".repeat(MAX_SUMMARY_CHARS + 50);
    let text = scrub_context_text(&long, MAX_SUMMARY_CHARS).unwrap();
    assert_eq!(text.chars().count(), MAX_SUMMARY_CHARS);
}

#[test]
fn records_scrubbed_context_and_first_cause() {
    let home = Home::new();
    let changed = home
        .record(args(json!({
            "first_blocked_cause": "connect_loopback",
            "trigger_summary": "lanectl reached https://u:p@mcp.example.test/hook?t=1",
            "why_now": "A new connector",
            "harness": "codex",
            "workspace_label": "app",
        })))
        .unwrap();
    assert_eq!(changed, json!(1));
    let [cause, summary, why_now, harness, workspace, at] = home.columns();
    assert_eq!(cause.as_deref(), Some("connect_loopback"));
    assert_eq!(
        summary.as_deref(),
        Some("lanectl reached https://mcp.example.test/hook")
    );
    assert_eq!(why_now.as_deref(), Some("A new connector"));
    assert_eq!(harness.as_deref(), Some("codex"));
    assert_eq!(workspace.as_deref(), Some("app"));
    assert_eq!(at.as_deref(), Some(NOW));
}

#[test]
fn first_cause_sticks_and_text_follows_the_latest_review() {
    let home = Home::new();
    home.record(args(json!({
        "first_blocked_cause": "read_home_state",
        "trigger_summary": "first",
        "harness": "codex",
    })))
    .unwrap();
    home.record(args(json!({
        "first_blocked_cause": "exec_outside_roots",
        "trigger_summary": "second",
    })))
    .unwrap();
    let [cause, summary, _, harness, _, _] = home.columns();
    assert_eq!(cause.as_deref(), Some("read_home_state"));
    assert_eq!(summary.as_deref(), Some("second"));
    // An absent field leaves the kept value alone.
    assert_eq!(harness.as_deref(), Some("codex"));
}

#[test]
fn nothing_to_write_changes_nothing() {
    let home = Home::new();
    assert_eq!(
        home.record(args(json!({"trigger_summary": "  "}))).unwrap(),
        Value::Null
    );
    assert!(home.columns().iter().all(Option::is_none));
}

#[test]
fn unknown_observation_or_other_identity_changes_nothing() {
    let home = Home::new();
    let other_id = json!({"cli_id": "local-cli.other-1", "trigger_summary": "x"});
    assert_eq!(home.record(args(other_id)).unwrap(), json!(0));
    let other_hash = json!({"identity_hash": "cdcdcdcd", "trigger_summary": "x"});
    assert_eq!(home.record(args(other_hash)).unwrap(), json!(0));
    assert!(home.columns().iter().all(Option::is_none));
}

#[test]
fn invalid_requests_are_refused_without_a_write() {
    let home = Home::new();
    let refused = [
        json!({"first_blocked_cause": "sudo"}),
        json!({"cli_id": "not-a-cli-id"}),
        json!({"identity_hash": ""}),
        json!({"identity_hash": "ab cd"}),
        json!({"observed_at": "yesterday"}),
        json!({"trigger_summary": "x".repeat(5000)}),
    ];
    for extra in refused {
        let mut request = args(json!({"trigger_summary": "kept out"}));
        request
            .as_object_mut()
            .unwrap()
            .extend(extra.as_object().unwrap().clone());
        assert_eq!(
            home.record(request.clone()),
            Err("native_guard_store_value_error"),
            "{request}"
        );
    }
    assert!(home.columns().iter().all(Option::is_none));
}

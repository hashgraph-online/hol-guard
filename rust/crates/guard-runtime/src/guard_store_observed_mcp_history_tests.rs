//! The narrow history read the connector scan uses: which rows reach it, which
//! fields come back, and the budget that keeps a long history answerable.

use rusqlite::Connection;
use serde_json::{Map, Value};

use super::observed_mcp_history;
use crate::guard_store_args::Args;

fn store() -> Connection {
    let connection = Connection::open_in_memory().unwrap();
    connection
        .execute_batch(
            "create table approval_requests (harness text, artifact_name text, \
                 raw_command_text text, last_seen_at text, created_at text); \
             create table runtime_receipts (harness text, artifact_name text, \
                 raw_command_text text, timestamp text);",
        )
        .unwrap();
    connection
}

fn receipt(connection: &Connection, artifact_name: Option<&str>, raw: Option<&str>, at: &str) {
    connection
        .execute(
            "insert into runtime_receipts (harness, artifact_name, raw_command_text, timestamp) \
             values ('codex', ?, ?, ?)",
            rusqlite::params![artifact_name, raw, at],
        )
        .unwrap();
}

fn approval(connection: &Connection, artifact_name: Option<&str>, raw: Option<&str>, at: &str) {
    connection
        .execute(
            "insert into approval_requests \
                 (harness, artifact_name, raw_command_text, last_seen_at, created_at) \
             values ('codex', ?, ?, ?, ?)",
            rusqlite::params![artifact_name, raw, at, at],
        )
        .unwrap();
}

fn history(connection: &Connection, limit: i64) -> Value {
    let mut args = Map::new();
    args.insert("limit".to_owned(), Value::from(limit));
    observed_mcp_history(connection, &Args(&args)).unwrap()
}

/// The label the scan reads a row under: the command text without its `tool:`
/// prefix when it carries one, and the artifact name otherwise.
fn labels(history: &Value, key: &str) -> Vec<String> {
    history[key]
        .as_array()
        .unwrap()
        .iter()
        .map(|row| match row["raw_command_text"].as_str() {
            Some(raw) if raw.starts_with("tool:") => raw["tool:".len()..].to_owned(),
            _ => row["artifact_name"].as_str().unwrap().to_owned(),
        })
        .collect()
}

#[test]
fn only_rows_naming_an_mcp_tool_are_read() {
    let connection = store();
    receipt(
        &connection,
        None,
        Some("tool:mcp__server__read"),
        "2026-01-06",
    );
    receipt(&connection, None, Some("tool:git status"), "2026-01-05");
    receipt(&connection, Some("mcp__server__write"), None, "2026-01-04");
    receipt(&connection, Some("git"), None, "2026-01-03");
    receipt(&connection, None, None, "2026-01-02");
    // A row whose command text does not name a tool is read under its artifact
    // name, which is the label the scan would give it.
    receipt(
        &connection,
        Some("mcp__server__call"),
        Some("ls"),
        "2026-01-01",
    );
    // A command text that names something else decides the label on its own,
    // so the artifact name it ran under cannot pull the row back in.
    receipt(
        &connection,
        Some("mcp__server__write"),
        Some("tool:git status"),
        "2026-01-01",
    );
    approval(
        &connection,
        None,
        Some("tool:mcp__client__call"),
        "2026-01-04",
    );
    approval(&connection, None, Some("tool:rm -rf /"), "2026-01-05");

    let history = history(&connection, 100);
    assert_eq!(
        labels(&history, "receipts"),
        [
            "mcp__server__read",
            "mcp__server__write",
            "mcp__server__call"
        ]
    );
    assert_eq!(labels(&history, "approvals"), ["mcp__client__call"]);
}

#[test]
fn a_row_carries_only_the_fields_the_scan_parses() {
    let connection = store();
    receipt(&connection, Some("mcp__server__read"), None, "2026-01-01");
    approval(&connection, Some("mcp__server__read"), None, "2026-01-01");

    let history = history(&connection, 100);
    let keys = |key: &str| {
        history[key].as_array().unwrap()[0]
            .as_object()
            .unwrap()
            .keys()
            .cloned()
            .collect::<Vec<_>>()
    };
    assert_eq!(
        keys("receipts"),
        ["artifact_name", "harness", "raw_command_text", "timestamp"]
    );
    assert_eq!(
        keys("approvals"),
        [
            "artifact_name",
            "created_at",
            "harness",
            "last_seen_at",
            "raw_command_text"
        ]
    );
}

#[test]
fn neither_history_can_outgrow_its_budget_or_starve_the_other() {
    let connection = store();
    let padded = format!("tool:mcp__server__{}", "x".repeat(64 * 1024));
    for index in 0..20 {
        let at = format!("2026-01-{:02}", index + 1);
        receipt(&connection, None, Some(&padded), &at);
        approval(&connection, None, Some(&padded), &at);
    }

    let history = history(&connection, 100);
    for key in ["receipts", "approvals"] {
        let rows = history[key].as_array().unwrap();
        assert!(!rows.is_empty(), "{key} was starved");
        assert!(rows.len() < 20, "{key} ignored its budget");
        assert!(
            serde_json::to_vec(&history[key]).unwrap().len()
                <= guard_contracts::MAX_NATIVE_RESPONSE_BYTES / 4,
            "{key} exceeded its budget"
        );
    }
}

#[test]
fn a_row_too_large_to_carry_does_not_hide_the_rows_behind_it() {
    let connection = store();
    let oversized = format!("tool:mcp__server__{}", "x".repeat(600 * 1024));
    receipt(
        &connection,
        None,
        Some("tool:mcp__server__read"),
        "2026-01-01",
    );
    receipt(&connection, None, Some(&oversized), "2026-01-02");
    approval(
        &connection,
        None,
        Some("tool:mcp__client__call"),
        "2026-01-01",
    );
    approval(&connection, None, Some(&oversized), "2026-01-02");

    let history = history(&connection, 100);
    assert_eq!(labels(&history, "receipts"), ["mcp__server__read"]);
    assert_eq!(labels(&history, "approvals"), ["mcp__client__call"]);
}

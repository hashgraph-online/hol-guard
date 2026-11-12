//! The connector scan: how history labels parse into connectors, the caps that
//! bound one answer, and the time each connector was last seen at.

use rusqlite::Connection;
use serde_json::{json, Value};

use super::observed_mcp_discovery;
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

fn receipt(connection: &Connection, harness: &str, label: &str, at: Option<&str>) {
    connection
        .execute(
            "insert into runtime_receipts (harness, raw_command_text, timestamp) \
             values (?, ?, ?)",
            rusqlite::params![harness, format!("tool:{label}"), at],
        )
        .unwrap();
}

fn approval(
    connection: &Connection,
    label: &str,
    last_seen_at: Option<&str>,
    created_at: Option<&str>,
) {
    connection
        .execute(
            "insert into approval_requests \
                 (harness, raw_command_text, last_seen_at, created_at) \
             values ('codex', ?, ?, ?)",
            rusqlite::params![format!("tool:{label}"), last_seen_at, created_at],
        )
        .unwrap();
}

fn discover(connection: &Connection, configured: Value) -> Value {
    let args = json!({ "configured_servers": configured });
    observed_mcp_discovery(connection, &Args(args.as_object().unwrap())).unwrap()
}

fn connectors(answer: &Value) -> &Vec<Value> {
    answer["connectors"].as_array().unwrap()
}

fn tool_names(connector: &Value) -> Vec<&str> {
    connector["tools"]
        .as_array()
        .unwrap()
        .iter()
        .map(|tool| tool["name"].as_str().unwrap())
        .collect()
}

#[test]
fn codex_apps_tools_group_under_their_app() {
    let connection = store();
    receipt(
        &connection,
        "codex",
        "mcp__codex_apps__composio__search",
        Some("2026-01-03T00:00:00Z"),
    );
    receipt(
        &connection,
        "codex",
        "mcp__codex_apps__composio__execute",
        Some("2026-01-02T00:00:00Z"),
    );
    receipt(
        &connection,
        "codex",
        "mcp__codex_apps__search",
        Some("2026-01-01T00:00:00Z"),
    );
    let answer = discover(&connection, json!({}));
    let found = connectors(&answer);
    assert_eq!(found.len(), 2);
    assert_eq!(found[0]["namespace"], "mcp__codex_apps__composio__");
    assert_eq!(found[0]["server_name"], "composio");
    assert_eq!(found[0]["harness"], "codex");
    assert_eq!(tool_names(&found[0]), ["search", "execute"]);
    assert_eq!(found[1]["namespace"], "mcp__codex_apps__");
    assert_eq!(found[1]["server_name"], "Codex Apps");
    assert_eq!(
        found[1]["tools"][0]["qualified_name"],
        "mcp__codex_apps__search"
    );
}

#[test]
fn labels_come_from_tool_text_or_the_artifact_name_only() {
    let connection = store();
    connection
        .execute_batch(
            "insert into runtime_receipts (harness, artifact_name, raw_command_text) values \
                 ('codex', 'mcp__server__read-file', null), \
                 ('codex', null, 'tool:mcp__server__read_file'), \
                 ('codex', null, 'tool:mcp__server__read_file'), \
                 ('codex', 'mcp__server__fake', 'echo mcp__server__fake');",
        )
        .unwrap();
    let answer = discover(&connection, json!({}));
    let found = connectors(&answer);
    assert_eq!(found.len(), 1);
    let mut names = tool_names(&found[0]);
    names.sort_unstable();
    // The echoed text is not a tool label, so its row is read by artifact name.
    assert_eq!(names, ["fake", "read-file", "read_file"]);
}

#[test]
fn approvals_lead_and_duplicates_take_no_capacity() {
    let connection = store();
    for index in 0..128 {
        let label = format!("mcp__server__tool_{index}");
        if index < 64 {
            approval(&connection, &label, None, None);
        }
        receipt(&connection, "codex", &label, None);
    }
    let answer = discover(&connection, json!({}));
    let found = connectors(&answer);
    assert_eq!(found.len(), 1);
    let names = tool_names(&found[0]);
    assert_eq!(names.len(), 100);
    let unique: std::collections::HashSet<_> = names.iter().collect();
    assert_eq!(unique.len(), 100);
}

#[test]
fn one_scan_offers_at_most_forty_connectors() {
    let connection = store();
    for index in 0..45 {
        receipt(
            &connection,
            "codex",
            &format!("mcp__server{index}__read"),
            None,
        );
    }
    let answer = discover(&connection, json!({}));
    assert_eq!(connectors(&answer).len(), 40);
}

#[test]
fn harnesses_keep_separate_connectors() {
    let connection = store();
    receipt(&connection, "codex", "mcp__server__read", None);
    receipt(&connection, "claude-code", "mcp__server__read", None);
    receipt(&connection, "codex", "not-a-tool", None);
    let answer = discover(&connection, json!({}));
    let harnesses: Vec<&str> = connectors(&answer)
        .iter()
        .map(|connector| connector["harness"].as_str().unwrap())
        .collect();
    assert_eq!(harnesses.len(), 2);
    assert!(harnesses.contains(&"codex"));
}

#[test]
fn seen_at_is_the_newest_time_any_source_names() {
    let connection = store();
    // A retried request refreshes `last_seen_at`, so it wins over `created_at`.
    approval(
        &connection,
        "mcp__server__write",
        Some("2026-01-03T00:00:00Z"),
        Some("2026-01-01T00:00:00Z"),
    );
    receipt(
        &connection,
        "codex",
        "mcp__server__read",
        Some("2026-01-02T00:00:00Z"),
    );
    receipt(&connection, "codex", "mcp__other__read", Some("not a time"));
    approval(
        &connection,
        "mcp__third__read",
        None,
        Some("2026-01-04T00:00:00Z"),
    );
    let answer = discover(&connection, json!({}));
    let seen: Vec<(&str, &Value)> = connectors(&answer)
        .iter()
        .map(|connector| {
            (
                connector["namespace"].as_str().unwrap(),
                &connector["seen_at"],
            )
        })
        .collect();
    assert!(seen.contains(&("mcp__server__", &json!("2026-01-03T00:00:00Z"))));
    assert!(seen.contains(&("mcp__third__", &json!("2026-01-04T00:00:00Z"))));
    assert!(seen.contains(&("mcp__other__", &Value::Null)));
}

fn omp_tool(label: &str, configured: &[&str]) -> Option<(String, String, String)> {
    let connection = store();
    receipt(&connection, "omp", label, None);
    let answer = discover(&connection, json!({ "omp": configured }));
    let connector = connectors(&answer).first()?.clone();
    Some((
        connector["server_name"].as_str()?.to_owned(),
        connector["tools"][0]["name"].as_str()?.to_owned(),
        connector["namespace"].as_str()?.to_owned(),
    ))
}

fn parsed(server: &str, name: &str, namespace: &str) -> Option<(String, String, String)> {
    Some((server.to_owned(), name.to_owned(), namespace.to_owned()))
}

#[test]
fn omp_flattened_names_split_against_configured_servers() {
    assert_eq!(
        omp_tool("mcp__truenas_pilot_status", &["truenas-pilot"]),
        parsed("truenas-pilot", "status", "mcp__truenas-pilot__")
    );
    assert_eq!(
        omp_tool("mcp__truenas_pilot_list_apps", &["truenas-pilot"]),
        parsed("truenas-pilot", "list_apps", "mcp__truenas-pilot__")
    );
    let servers = ["truenas", "truenas-pilot"];
    assert_eq!(
        omp_tool("mcp__truenas_pilot_status", &servers),
        parsed("truenas-pilot", "status", "mcp__truenas-pilot__")
    );
    assert_eq!(
        omp_tool("mcp__truenas_status", &servers),
        parsed("truenas", "status", "mcp__truenas__")
    );
}

#[test]
fn omp_flattened_names_without_an_owner_are_skipped() {
    for configured in [&[][..], &["other-server"], &["pilot"]] {
        assert_eq!(omp_tool("mcp__truenas_pilot_status", configured), None);
    }
    assert_eq!(omp_tool("mcp__truenas_pilot", &["truenas-pilot"]), None);
    assert_eq!(omp_tool("mcp__truenas_pilot_", &["truenas-pilot"]), None);
    assert_eq!(
        omp_tool("mcp__truenas_pilot__x", &["truenas-pilot"]).map(|t| t.2),
        Some("mcp__truenas_pilot__".to_owned())
    );
    // Names that flatten alike belong to neither server.
    assert_eq!(omp_tool("mcp__foo_bar_tool", &["foo-bar", "foo_bar"]), None);
    // A server already ending in `_` cannot say where it ends.
    assert_eq!(omp_tool("mcp__foo_tool", &["foo_"]), None);
    assert_eq!(
        omp_tool("mcp__foo__tool", &["foo_"]),
        parsed("foo", "tool", "mcp__foo__")
    );
}

#[test]
fn omp_marked_names_keep_their_own_boundary() {
    assert_eq!(
        omp_tool("mcp__truenas_pilot__status", &["truenas"]),
        parsed("truenas_pilot", "status", "mcp__truenas_pilot__")
    );
}

#[test]
fn other_harnesses_never_split_on_configured_servers() {
    let connection = store();
    receipt(
        &connection,
        "claude-code",
        "mcp__truenas_pilot_status",
        None,
    );
    let answer = discover(
        &connection,
        json!({ "claude-code": ["truenas-pilot"], "omp": ["truenas-pilot"] }),
    );
    assert!(connectors(&answer).is_empty());
}

#[test]
fn a_malformed_server_list_is_refused() {
    let connection = store();
    for configured in [
        json!([]),
        json!({ "omp": "truenas" }),
        json!({ "omp": [1] }),
    ] {
        let args = json!({ "configured_servers": configured });
        assert!(observed_mcp_discovery(&connection, &Args(args.as_object().unwrap())).is_err());
    }
}

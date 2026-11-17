//! The MCP server helper ops: no context, answers from the request alone.

use serde_json::{json, Value};

use super::dispatch;

fn ask(request: Value) -> Value {
    dispatch(&request).unwrap()
}

fn row(name: &str, command: &str, args: &[&str]) -> Value {
    json!({
        "harness": "cursor",
        "name": name,
        "source_scope": "global",
        "config_path": "/c",
        "command": command,
        "args": args,
        "transport": "stdio",
        "env": [],
        "guard_managed_proxy": false,
        "enabled": true,
        "saved_origin": null,
        "saved_guard_home": null,
    })
}

#[test]
fn a_companion_is_verified_only_when_its_launch_is_a_guard_proxy() {
    let proxy = [
        "-m",
        "codex_plugin_scanner.cli",
        "guard",
        "cursor-mcp-proxy",
    ];
    for (name, command, args, companion, verified) in [
        ("hol-guard::x", json!("python"), json!(proxy), true, true),
        ("hol-guard::x", json!("node"), json!(["s.js"]), true, false),
        ("hol-guard::x", Value::Null, json!(proxy), true, false),
        ("other", json!("python"), json!(proxy), false, false),
    ] {
        let answer = ask(json!({
            "op": "mcp_companion", "name": name, "command": command, "args": args,
        }));
        assert_eq!(
            answer,
            json!({"companion": companion, "verified": verified}),
            "{name} {command}"
        );
    }
}

#[test]
fn a_malformed_companion_request_is_refused() {
    for request in [
        json!({"op": "mcp_companion", "name": 1, "command": null, "args": []}),
        json!({"op": "mcp_companion", "name": "a", "command": 1, "args": []}),
        json!({"op": "mcp_companion", "name": "a", "command": null, "args": [1]}),
        json!({"op": "mcp_companion", "name": "a", "command": null}),
    ] {
        assert!(dispatch(&request).is_err(), "{request}");
    }
}

#[test]
fn configured_names_group_by_harness_in_first_seen_order() {
    let artifacts = json!([
        {"harness": "omp", "artifact_type": "mcp_server", "name": " truenas "},
        {"harness": "cursor", "artifact_type": "skill", "name": "ignored"},
        {"harness": "cursor", "artifact_type": "mcp_server", "name": "  "},
        {"harness": "cursor", "artifact_type": "mcp_server", "name": "b"},
        {"harness": "omp", "artifact_type": "mcp_server", "name": "remote"},
        {"harness": "omp", "artifact_type": "mcp_server", "name": "truenas"},
        {"harness": "cursor", "artifact_type": "mcp_server", "name": "a"},
    ]);
    assert_eq!(
        ask(json!({"op": "mcp_server_names", "artifacts": artifacts})),
        json!({"names": [["omp", ["truenas", "remote"]], ["cursor", ["b", "a"]]]})
    );
}

#[test]
fn source_labels_skip_items_without_a_text_id_or_a_label() {
    let answer = ask(json!({
        "op": "mcp_source_labels",
        "cli_ids": ["a", null, "b", "c", "missing"],
        "labels": {"a": "Cursor", "b": "", "c": "Codex"},
    }));
    assert_eq!(
        answer,
        json!({"labels": ["Cursor", null, null, "Codex", null]})
    );
    assert!(dispatch(&json!({
        "op": "mcp_source_labels", "cli_ids": [1], "labels": {},
    }))
    .is_err());
    assert!(dispatch(&json!({
        "op": "mcp_source_labels", "cli_ids": [], "labels": {"a": 1},
    }))
    .is_err());
}

#[test]
fn skipped_names_are_the_named_entries_select_leaves_out() {
    let answer = ask(json!({
        "op": "mcp_skipped",
        "entries": [
            {"name": "ok", "request": row("ok", "node", &["s.js"])},
            {"name": " ", "request": row(" ", "node", &["s.js"])},
            {"name": "no-command", "request": {
                "harness": "cursor", "name": "no-command", "source_scope": "global",
                "config_path": "/c", "command": null, "args": [], "transport": "stdio",
                "env": [], "guard_managed_proxy": false, "enabled": true,
                "saved_origin": null, "saved_guard_home": null,
            }},
            {"name": "unencodable", "request": null},
        ],
    }));
    assert_eq!(answer, json!({"skipped": [2, 3]}));
}

#[test]
fn skipped_names_without_a_request_never_ask_select() {
    let answer = ask(json!({
        "op": "mcp_skipped",
        "entries": [{"name": "bad", "request": null}, {"name": "", "request": null}],
    }));
    assert_eq!(answer, json!({"skipped": [0]}));
    assert_eq!(
        ask(json!({"op": "mcp_skipped", "entries": []})),
        json!({"skipped": []})
    );
}

#[test]
fn a_malformed_skipped_request_is_refused() {
    for entries in [
        json!([{"name": 1, "request": null}]),
        json!([{"name": "a"}]),
        json!([{"name": "a", "request": "x"}]),
        json!([{"name": "a", "request": {"harness": "cursor"}}]),
    ] {
        assert!(
            dispatch(&json!({"op": "mcp_skipped", "entries": entries})).is_err(),
            "{entries}"
        );
    }
}

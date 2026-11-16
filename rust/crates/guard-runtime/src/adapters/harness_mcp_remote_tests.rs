use serde_json::{json, Map, Value};

use super::{remote, remote_rank};

fn object(value: Value) -> Map<String, Value> {
    match value {
        Value::Object(map) => map,
        _ => unreachable!("test requests are objects"),
    }
}

fn ask_remote(candidates: Value) -> Value {
    remote(&object(json!({"op": "remote", "candidates": candidates}))).unwrap()["servers"].clone()
}

fn candidate(harness: &str, name: &str, url: &str) -> Value {
    json!({"harness": harness, "name": name, "url": url})
}

#[test]
fn a_declared_server_answers_its_origin_and_the_namespace_its_calls_carry() {
    let servers = ask_remote(json!([
        candidate(
            "Codex",
            " echo mcp ",
            "https://user:pw@MCP.Example.Test/v1/a1b2c3d4e5?key=secret"
        ),
        candidate("codex", "local-sock", "file:///tmp/sock"),
        candidate("codex", "___", "https://mcp.example.test/mcp"),
        candidate("codex", "codex_apps", "https://mcp.example.test/mcp"),
    ]));
    assert_eq!(
        servers,
        json!([
            {
                "origin": "https://mcp.example.test/v1/[masked]",
                "harness": "codex",
                "namespace": "mcp__echo_mcp__",
                "name": "tool",
                "qualified_name": "mcp__echo_mcp__tool",
                "server_name": "echo_mcp",
            },
            null,
            null,
            null,
        ])
    );
}

#[test]
fn a_malformed_remote_request_is_refused() {
    for request in [
        json!({"op": "remote"}),
        json!({"op": "remote", "candidates": {}}),
        json!({"op": "remote", "candidates": [{"harness": "codex", "name": "a"}]}),
        json!({"op": "remote", "candidates": [{"harness": "codex", "name": 1, "url": "x"}]}),
        json!({"op": "remote", "candidates": [], "extra": 1}),
    ] {
        assert!(remote(&object(request)).is_err());
    }
}

fn ranked(harness: &str, namespace: &str, server: &str, label: &str) -> Value {
    json!({"harness": harness, "namespace": namespace, "server_name": server, "source_label": label})
}

#[test]
fn rank_keeps_the_first_server_per_connector_ordered_by_label_and_name() {
    let servers = json!([
        ranked("cursor", "mcp__b__", "b", "Cursor · configured server"),
        ranked("codex", "mcp__Zed__", "Zed", "Codex · configured server"),
        ranked(
            "codex",
            "mcp__alpha__",
            "alpha",
            "Codex · configured server"
        ),
        ranked(
            "codex",
            "mcp__alpha__",
            "alpha",
            "Codex · configured server"
        ),
    ]);
    let order = |limit: u64| {
        remote_rank(&object(
            json!({"op": "remote_rank", "servers": servers, "limit": limit}),
        ))
        .unwrap()["order"]
            .clone()
    };
    assert_eq!(order(100), json!([2, 1, 0]));
    assert_eq!(order(2), json!([2, 1]));
}

#[test]
fn a_malformed_rank_request_is_refused() {
    for request in [
        json!({"op": "remote_rank", "servers": [], "limit": true}),
        json!({"op": "remote_rank", "servers": [], "limit": -1}),
        json!({"op": "remote_rank", "servers": [{"harness": "codex"}], "limit": 1}),
        json!({"op": "remote_rank", "servers": []}),
    ] {
        assert!(remote_rank(&object(request)).is_err());
    }
}

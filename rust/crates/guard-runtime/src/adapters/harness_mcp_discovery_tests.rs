//! Replays `harness_mcp_discovery_vectors.json`, recorded from the original
//! Python helpers, through the native kind, and pins the request contract.

use serde_json::{json, Value};

use crate::harness_mcp_discovery::{
    dispatch, is_secret_flag, join_labels, launch_label, redact_launch_tokens,
};
use crate::runner_authority_op::ERR_INVALID;

const VECTORS: &str =
    include_str!("../../testdata/harness_mcp_discovery/harness_mcp_discovery_vectors.json");
const SCHEMA: &str = "guard-harness-mcp-discovery-vectors.v1";
const RECORDED_CASES: usize = 34;

#[test]
fn replays_every_recorded_case() {
    let document: Value = serde_json::from_str(VECTORS).expect("vectors");
    assert_eq!(document["schema"], SCHEMA);
    let cases = document["cases"].as_array().expect("cases");
    assert_eq!(cases.len(), RECORDED_CASES);
    for case in cases {
        let name = case["name"].as_str().expect("name");
        assert_eq!(
            dispatch(&case["request"]),
            Ok(case["expect"].clone()),
            "{name}"
        );
    }
}

fn entry(name: &str, command: &str) -> Value {
    json!({
        "harness": "cursor",
        "label": "Cursor",
        "name": name,
        "command": command,
        "args": ["--token", "fake-value"],
        "source_scope": "user",
        "config_path": "~/.cursor/mcp.json",
        "identity_hash": "a".repeat(64),
        "package_name": null,
        "server_command": command,
        "args_hash": "b".repeat(64),
    })
}

#[test]
fn a_group_answers_the_creating_index_and_redacts_only_the_label() {
    let answer = dispatch(&json!({
        "op": "group",
        "windows": false,
        "limit": 100,
        "servers": [entry("skip", " "), entry("srv", "node"), entry("srv", "node")],
    }))
    .expect("answer");
    let servers = answer["servers"].as_array().expect("servers");
    assert_eq!(servers.len(), 1);
    assert_eq!(servers[0]["index"], 1);
    assert_eq!(servers[0]["example_label"], "node --token '*****'");
    assert_eq!(servers[0]["launch_command"], "node --token fake-value");
    let hash = servers[0]["identity_hash"].as_str().expect("hash");
    assert_eq!(servers[0]["cli_id"], format!("local-cli.mcp-{hash}"));
}

#[test]
fn a_zero_limit_lists_nothing() {
    let answer = dispatch(&json!({
        "op": "group", "windows": true, "limit": 0, "servers": [entry("srv", "node")],
    }));
    assert_eq!(answer, Ok(json!({ "servers": [] })));
}

#[test]
fn malformed_requests_are_invalid() {
    let good = entry("srv", "node");
    let mut extra = good.clone();
    extra["env"] = json!({});
    let mut missing = good.clone();
    missing.as_object_mut().expect("entry").remove("label");
    let mut bad_args = good.clone();
    bad_args["args"] = json!(["ok", 1]);
    let mut bad_package = good.clone();
    bad_package["package_name"] = json!(1);
    let query = json!({
        "cli_id": null, "server_command": null, "args_hash": null,
        "server_identity_hash": null, "source_label": null,
    });
    let observed = json!({
        "cli_id": "c", "identity_hash": "h", "command": "node", "args_hash": "a", "source_label": "Cursor",
    });
    for args in [
        json!([]),
        json!({}),
        json!({ "op": "other" }),
        json!({ "op": "group", "windows": false, "limit": 1 }),
        json!({ "op": "group", "windows": "no", "limit": 1, "servers": [] }),
        json!({ "op": "group", "windows": false, "limit": -1, "servers": [] }),
        json!({ "op": "group", "windows": false, "limit": 1, "servers": {} }),
        json!({ "op": "group", "windows": false, "limit": 1, "servers": [], "x": 1 }),
        json!({ "op": "group", "windows": false, "limit": 1, "servers": [extra] }),
        json!({ "op": "group", "windows": false, "limit": 1, "servers": [missing] }),
        json!({ "op": "group", "windows": false, "limit": 1, "servers": [bad_args] }),
        json!({ "op": "group", "windows": false, "limit": 1, "servers": [bad_package] }),
        json!({ "op": "group", "windows": false, "limit": 1, "servers": vec![json!(null); 16_385] }),
        json!({ "op": "match", "servers": [], "query": {} }),
        json!({ "op": "match", "servers": [{}], "query": query }),
        json!({ "op": "match", "servers": [observed], "query": { "cli_id": 1 } }),
        json!({ "op": "match", "servers": [observed], "query": query, "x": 1 }),
    ] {
        assert_eq!(dispatch(&args), Err(ERR_INVALID), "{args}");
    }
}

#[test]
fn secret_flags_follow_the_python_names() {
    for flag in [
        "--token",
        "-TOKEN",
        "--api_key",
        "--Client-Secret",
        "--github-token",
        "--db_password",
        " --auth ",
        "passwd",
        "--x-secret",
    ] {
        assert!(is_secret_flag(flag), "{flag}");
    }
    for flag in ["--port", "--tokens", "--secretive", "--password-file", ""] {
        assert!(!is_secret_flag(flag), "{flag}");
    }
}

#[test]
fn a_secret_value_never_reaches_the_label() {
    let tokens = [
        "server",
        "--token",
        "fake-1",
        "--api-key=fake-2",
        "url?token=fake-3",
        "--password",
    ];
    assert_eq!(
        redact_launch_tokens(&tokens),
        [
            "server",
            "--token",
            "*****",
            "--api-key=*****",
            "url?token=*****",
            "--password"
        ]
    );
    let label = launch_label(&tokens, true);
    assert!(!label.contains("fake"), "{label}");
    let long = "x".repeat(400);
    assert_eq!(launch_label(&[long.as_str()], false).chars().count(), 160);
}

#[test]
fn labels_join_three_then_count_the_rest() {
    let labels = |values: &[&str]| -> Vec<String> {
        values.iter().map(|value| (*value).to_owned()).collect()
    };
    assert_eq!(join_labels(&labels(&[])), "");
    assert_eq!(join_labels(&labels(&["A", " ", "A", "B"])), "A, B");
    assert_eq!(join_labels(&labels(&["A", "B", "C"])), "A, B, C");
    assert_eq!(
        join_labels(&labels(&["A", "B", "C", "D", "E"])),
        "A, B, and 3 more"
    );
}

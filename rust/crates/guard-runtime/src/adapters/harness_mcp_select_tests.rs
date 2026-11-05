//! Replays `server_id_vectors.json`, recorded from the original Python
//! `stable_mcp_server_identifier`, and pins the `select` contract.

use guard_command::mcp_decision::build_mcp_server_identity;
use serde_json::{json, Map, Value};

use crate::harness_mcp_discovery::dispatch;
use crate::opencode_server_id::server_identifier;
use crate::runner_authority_op::ERR_INVALID;

const VECTORS: &str = include_str!("../../testdata/harness_mcp_discovery/server_id_vectors.json");
const SCHEMA: &str = "guard-mcp-server-id-vectors.v1";
const RECORDED_CASES: usize = 16;

#[test]
fn server_ids_match_the_python_vectors() {
    let document: Value = serde_json::from_str(VECTORS).expect("vectors");
    assert_eq!(document["schema"], SCHEMA);
    let cases = document["cases"].as_array().expect("cases");
    assert_eq!(cases.len(), RECORDED_CASES);
    let servers: Vec<Value> = cases.iter().map(|case| case["server"].clone()).collect();
    let expected: Vec<Value> = cases.iter().map(|case| case["expected"].clone()).collect();
    let answer = dispatch(&json!({"op": "server_id", "servers": servers})).expect("answer");
    assert_eq!(answer, json!({ "ids": expected }));
}

fn artifact(command: &str, args: &[&str]) -> Value {
    json!({
        "harness": "cursor",
        "name": "srv",
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

fn select(artifacts: &[Value], include_proxy: bool) -> Vec<Value> {
    let answer = dispatch(&json!({
        "op": "select",
        "include_proxy": include_proxy,
        "artifacts": artifacts,
    }))
    .expect("answer");
    answer["servers"].as_array().expect("servers").clone()
}

fn one(artifact: &Value, include_proxy: bool) -> Value {
    select(std::slice::from_ref(artifact), include_proxy)[0].clone()
}

fn proxy_args(server_id: &str) -> Vec<String> {
    [
        "cursor-mcp-proxy",
        "--guard-home",
        "/g",
        "--server-name",
        "srv",
        "--server-id",
        server_id,
        "--source-scope",
        "global",
        "--config-path",
        "/c",
        "--transport",
        "stdio",
        "--command",
        "node",
        "--arg=s.js",
        "--server-env-key=API_KEY",
    ]
    .iter()
    .map(|value| value.to_string())
    .collect()
}

fn proxy(server_id: &str, env: Value) -> Value {
    let mut proxied = artifact("hol-guard", &[]);
    proxied["args"] = json!(proxy_args(server_id));
    proxied["env"] = env;
    proxied
}

fn upstream_id() -> String {
    server_identifier("cursor", "srv", "global", "node", &["s.js"], "stdio", false)
}

#[test]
fn a_plain_server_carries_its_identity() {
    let mut plain = artifact("npx", &["-y", "pkg"]);
    plain["env"] = json!([[" TOKEN ", "v"], ["", "skip"]]);
    plain["enabled"] = json!(false);
    let server = one(&plain, false);
    let mut env = Map::new();
    env.insert("TOKEN".to_owned(), json!("v"));
    let identity = build_mcp_server_identity(
        "/c",
        "npx",
        &["-y".to_owned(), "pkg".to_owned()],
        "stdio",
        Some(&env),
        &[],
    );
    assert_eq!(server["command"], "npx");
    assert_eq!(server["args"], json!(["-y", "pkg"]));
    assert_eq!(server["transport"], "stdio");
    assert_eq!(server["env"], json!([[" TOKEN ", "v"], ["", "skip"]]));
    assert_eq!(server["enabled"], false);
    assert_eq!(server["identity"]["identity_hash"], identity.identity_hash);
    assert_eq!(
        server["identity"]["env_values_hash"],
        identity.env_values_hash
    );
    assert_eq!(server["identity"]["env_keys"], json!(identity.env_keys));
    assert_eq!(server["identity"]["args_hash"], identity.args_hash);
}

#[test]
fn answers_keep_the_request_order() {
    let servers = select(
        &[
            artifact("node", &["a.js"]),
            artifact("hol-guard", &["mcp-proxy"]),
            artifact("node", &["b.js"]),
        ],
        false,
    );
    assert_eq!(servers.len(), 3);
    assert_eq!(servers[0]["args"], json!(["a.js"]));
    assert!(servers[1].is_null());
    assert_eq!(servers[2]["args"], json!(["b.js"]));
}

#[test]
fn companions_blank_names_and_missing_commands_are_skipped() {
    let id = upstream_id();
    let mut companion = proxy(&id, json!([["API_KEY", "v"]]));
    companion["name"] = json!("hol-guard::srv");
    assert!(one(&companion, true).is_null());

    let mut blank = artifact("node", &[]);
    blank["name"] = json!(" \t");
    assert!(one(&blank, false).is_null());

    let mut missing = artifact("node", &[]);
    missing["command"] = Value::Null;
    assert!(one(&missing, false).is_null());
}

#[test]
fn a_guard_managed_proxy_is_kept_only_when_proxies_are_included() {
    let mut managed = artifact("node", &["s.js"]);
    managed["guard_managed_proxy"] = json!(true);
    assert!(one(&managed, false).is_null());
    assert_eq!(one(&managed, true)["command"], "node");
}

#[test]
fn a_proxy_unwraps_to_its_upstream_only_when_included() {
    let proxied = proxy(&upstream_id(), json!([["API_KEY", "v"], ["OTHER", "x"]]));
    assert!(one(&proxied, false).is_null());
    let server = one(&proxied, true);
    assert_eq!(server["command"], "node");
    assert_eq!(server["args"], json!(["s.js"]));
    assert_eq!(server["env"], json!([["API_KEY", "v"]]));
    assert_eq!(server["source_scope"], "global");
    assert_eq!(server["config_path"], "/c");
}

#[test]
fn a_proxy_whose_server_id_does_not_match_stays_hidden() {
    let proxied = proxy(
        "mcp_server:cursor:global:srv:0000",
        json!([["API_KEY", "v"]]),
    );
    assert!(one(&proxied, true).is_null());
}

#[test]
fn a_proxy_without_a_configured_env_mapping_stays_hidden() {
    assert!(one(&proxy(&upstream_id(), Value::Null), true).is_null());
}

#[test]
fn a_later_duplicate_stripped_env_key_wins() {
    let proxied = proxy(
        &upstream_id(),
        json!([[" API_KEY ", "first"], ["API_KEY", "later"]]),
    );
    assert_eq!(one(&proxied, true)["env"], json!([["API_KEY", "later"]]));
}

#[test]
fn only_local_transports_are_selected() {
    for (transport, expected) in [
        (json!("stdio"), Some("stdio")),
        (json!("local"), Some("local")),
        (json!(""), Some("stdio")),
        (Value::Null, Some("stdio")),
        (json!("sse"), None),
        (json!("http"), None),
    ] {
        let mut server = artifact("node", &[]);
        server["transport"] = transport.clone();
        let answer = one(&server, false);
        match expected {
            Some(name) => assert_eq!(answer["transport"], name, "{transport}"),
            None => assert!(answer.is_null(), "{transport}"),
        }
    }
}

#[test]
fn malformed_requests_are_refused() {
    let valid = json!({
        "op": "select",
        "include_proxy": false,
        "artifacts": [artifact("node", &[])],
    });
    assert!(dispatch(&valid).is_ok());
    for key in ["include_proxy", "artifacts"] {
        let mut missing = valid.clone();
        missing.as_object_mut().expect("object").remove(key);
        assert_eq!(dispatch(&missing), Err(ERR_INVALID), "{key}");
    }
    let mut extra = valid.clone();
    extra["other"] = json!(1);
    assert_eq!(dispatch(&extra), Err(ERR_INVALID));
    for (key, wrong) in [
        ("harness", json!(1)),
        ("command", json!(1)),
        ("args", json!(["ok", 1])),
        ("transport", json!(1)),
        ("env", json!({"A": "b"})),
        ("env", json!([["A"]])),
        ("env", json!([["A", 1]])),
        ("guard_managed_proxy", Value::Null),
        ("enabled", json!("yes")),
        ("saved_origin", json!("global")),
        ("saved_guard_home", json!(1)),
    ] {
        let mut bad = valid.clone();
        bad["artifacts"][0][key] = wrong.clone();
        assert_eq!(dispatch(&bad), Err(ERR_INVALID), "{key} {wrong}");
    }
    let mut missing_field = valid.clone();
    missing_field["artifacts"][0]
        .as_object_mut()
        .expect("object")
        .remove("enabled");
    assert_eq!(dispatch(&missing_field), Err(ERR_INVALID));

    let server = json!({
        "harness": "codex",
        "name": "n",
        "source_scope": "global",
        "command": "node",
        "args": [],
        "transport": "stdio",
    });
    assert!(dispatch(&json!({"op": "server_id", "servers": [server.clone()]})).is_ok());
    let mut bad = server.clone();
    bad["transport"] = Value::Null;
    assert_eq!(
        dispatch(&json!({"op": "server_id", "servers": [bad]})),
        Err(ERR_INVALID)
    );
    let mut extra = server;
    extra["env"] = json!([]);
    assert_eq!(
        dispatch(&json!({"op": "server_id", "servers": [extra]})),
        Err(ERR_INVALID)
    );
}

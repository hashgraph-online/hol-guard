//! The `proxy_args` and `proxy_env` ops, as `mcp_servers.py` asks them.

use serde_json::{json, Value};

use crate::harness_mcp_discovery::dispatch;
use crate::opencode_server_id::server_identifier;
use crate::runner_authority_op::ERR_INVALID;

fn server(env: Value) -> Value {
    json!({
        "harness": "cursor",
        "name": "srv",
        "source_scope": "global",
        "config_path": "/c/mcp.json",
        "command": "npx",
        "args": ["pkg", "--flag"],
        "transport": "stdio",
        "env": env,
    })
}

fn ask(home: Value, env: Value) -> Vec<String> {
    let answer = dispatch(&json!({
        "op": "proxy_args",
        "proxy_command": "cursor-mcp-proxy",
        "guard_home": "/g",
        "home": home,
        "workspace": null,
        "server": server(env),
    }))
    .expect("answer");
    serde_json::from_value(answer["args"].clone()).expect("args")
}

#[test]
fn proxy_args_carry_the_launch_id_and_safe_env_names() {
    let env = json!([
        ["Z_KEY", "1"],
        [" A_KEY ", "2"],
        ["pythonpath", "x"],
        ["  ", "y"]
    ]);
    let args = ask(Value::Null, env);
    let id = server_identifier(
        "cursor",
        "srv",
        "global",
        "npx",
        &["pkg", "--flag"],
        "stdio",
        false,
    );
    let expected: Vec<String> = [
        "-m",
        "codex_plugin_scanner.cli",
        "guard",
        "cursor-mcp-proxy",
        "--guard-home",
        "/g",
        "--server-name",
        "srv",
        "--server-id",
        id.as_str(),
        "--source-scope",
        "global",
        "--config-path",
        "/c/mcp.json",
        "--transport",
        "stdio",
        "--command",
        "npx",
        "--arg=pkg",
        "--arg=--flag",
        "--server-env-key=A_KEY",
        "--server-env-key=Z_KEY",
    ]
    .iter()
    .map(|part| (*part).to_owned())
    .collect();
    assert_eq!(args, expected);
    let homed = ask(json!("/h"), json!([]));
    let at = homed
        .iter()
        .position(|part| part == "--home")
        .expect("home");
    assert_eq!(homed[at + 1], "/h");
    assert!(!homed.contains(&"--workspace".to_owned()));
}

#[test]
fn proxy_env_strips_keys_and_drops_launcher_keys() {
    let answer = dispatch(&json!({
        "op": "proxy_env",
        "env": [[" A ", "1"], ["HOL_GUARD_NATIVE", "x"], ["B", "2"], ["A", "3"], ["", "z"]],
    }))
    .expect("answer");
    assert_eq!(answer, json!({"env": [["A", "3"], ["B", "2"]]}));
    let refused = dispatch(&json!({"op": "proxy_env", "env": null}));
    assert_eq!(refused, Err(ERR_INVALID));
}

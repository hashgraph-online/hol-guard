//! Replays `managed_upstream_vectors.json`, recorded from the original Python
//! `read_managed_mcp_upstream`, through the native op.

use serde_json::{json, Value};

use crate::harness_mcp_discovery::dispatch;
use crate::runner_authority_op::ERR_INVALID;

const VECTORS: &str =
    include_str!("../../testdata/harness_mcp_discovery/managed_upstream_vectors.json");
const SCHEMA: &str = "guard-managed-mcp-upstream-vectors.v1";
const RECORDED_CASES: usize = 41;
/// `_GUARD_PROXY_COMMANDS`.
const COMMANDS: [&str; 7] = [
    "cline-mcp-proxy",
    "codex-mcp-proxy",
    "copilot-mcp-proxy",
    "cursor-mcp-proxy",
    "hermes-mcp-proxy",
    "mcp-proxy",
    "opencode-mcp-proxy",
];

fn request(artifact: &Value, env_names: Vec<String>) -> Value {
    json!({
        "op": "upstream",
        "commands": COMMANDS,
        "harness": artifact["harness"],
        "name": artifact["name"],
        "transport": artifact["transport"],
        "source_scope": artifact["source_scope"],
        "config_path": artifact["config_path"],
        "args": artifact["args"],
        "saved_origin": artifact["saved_origin"],
        "saved_guard_home": artifact["saved_guard_home"],
        "env_names": env_names,
    })
}

#[test]
fn upstreams_match_the_python_vectors() {
    let document: Value = serde_json::from_str(VECTORS).expect("vectors");
    assert_eq!(document["schema"], SCHEMA);
    let cases = document["cases"].as_array().expect("cases");
    assert_eq!(cases.len(), RECORDED_CASES);
    for case in cases {
        let label = case["label"].as_str().expect("label");
        let artifact = &case["artifact"];
        let expected = &case["expected"];
        // A configured env that is not a mapping never reaches the native op.
        let Some(env) = artifact["env"].as_object() else {
            assert!(expected.is_null(), "{label}");
            continue;
        };
        let names: Vec<String> = env.keys().cloned().collect();
        let answer = dispatch(&request(artifact, names)).expect(label);
        let want = if expected.is_null() {
            Value::Null
        } else {
            let forwarded: Vec<String> = expected["env"]
                .as_object()
                .expect("env")
                .keys()
                .cloned()
                .collect();
            json!({
                "command": expected["command"],
                "args": expected["args"],
                "env_names": forwarded,
                "server_id": expected["server_id"],
                "source_scope": expected["source_scope"],
                "config_path": expected["config_path"],
            })
        };
        assert_eq!(answer, json!({"upstream": want}), "{label}");
    }
}

fn proxy_args(extra: &[String]) -> Vec<String> {
    let mut args: Vec<String> = [
        "cursor-mcp-proxy",
        "--guard-home",
        "/g",
        "--server-name",
        "srv",
        "--server-id",
        "sid",
        "--source-scope",
        "global",
        "--config-path",
        "/c",
        "--transport",
        "stdio",
        "--command",
        "node",
    ]
    .iter()
    .map(|value| value.to_string())
    .collect();
    args.extend_from_slice(extra);
    args
}

fn upstream(args: &[String]) -> Value {
    let artifact = json!({
        "harness": "cursor",
        "name": "srv",
        "transport": "stdio",
        "source_scope": "global",
        "config_path": "/c",
        "args": args,
        "saved_origin": null,
        "saved_guard_home": null,
    });
    dispatch(&request(&artifact, Vec::new())).expect("answer")["upstream"].clone()
}

#[test]
fn the_argv_count_and_byte_bounds_hold_at_their_limits() {
    let base = proxy_args(&[]);
    let mut extra: Vec<String> = Vec::new();
    while base.len() + extra.len() < 512 {
        extra.push("--arg=x".to_owned());
    }
    assert!(!upstream(&proxy_args(&extra)).is_null());
    extra.push("--arg=x".to_owned());
    assert!(upstream(&proxy_args(&extra)).is_null());

    let used: usize = base.iter().map(String::len).sum::<usize>() + "--arg=".len();
    // `é` is two UTF-8 bytes; the bound counts bytes, not characters.
    let fill = 262_144 - used;
    let at_limit = format!("--arg={}", "é".repeat(fill / 2) + &"x".repeat(fill % 2));
    assert!(!upstream(&proxy_args(&[at_limit.clone()])).is_null());
    let over = format!("{at_limit}x");
    assert!(upstream(&proxy_args(&[over])).is_null());
}

#[test]
fn a_saved_origin_must_be_the_exact_scope_and_path_pair() {
    let args = proxy_args(&[]);
    let mut artifact = json!({
        "harness": "cursor",
        "name": "srv",
        "transport": "stdio",
        "source_scope": "project",
        "config_path": "/w/.cursor/mcp.json",
        "args": args,
        "saved_origin": ["global", "/c"],
        "saved_guard_home": "/g",
    });
    let answer = dispatch(&request(&artifact, Vec::new())).expect("answer");
    assert_eq!(answer["upstream"]["source_scope"], "global");
    for saved in [
        json!(["global", "/c", "x"]),
        json!(["global"]),
        json!(["global", 1]),
        json!([]),
        Value::Null,
    ] {
        artifact["saved_origin"] = saved.clone();
        let answer = dispatch(&request(&artifact, Vec::new())).expect("answer");
        assert!(answer["upstream"].is_null(), "{saved}");
    }
}

#[test]
fn malformed_requests_are_refused() {
    let args = proxy_args(&[]);
    let artifact = json!({
        "harness": "cursor",
        "name": "srv",
        "transport": "stdio",
        "source_scope": "global",
        "config_path": "/c",
        "args": args,
        "saved_origin": null,
        "saved_guard_home": null,
    });
    let valid = request(&artifact, Vec::new());
    assert!(dispatch(&valid).is_ok());
    for key in [
        "commands",
        "harness",
        "name",
        "transport",
        "source_scope",
        "config_path",
        "args",
        "saved_origin",
        "saved_guard_home",
        "env_names",
    ] {
        let mut missing = valid.clone();
        missing.as_object_mut().expect("object").remove(key);
        assert_eq!(dispatch(&missing), Err(ERR_INVALID), "{key}");
        let mut wrong = valid.clone();
        wrong[key] = json!(1);
        assert_eq!(dispatch(&wrong), Err(ERR_INVALID), "{key}");
    }
    for key in ["commands", "args", "env_names"] {
        let mut wrong = valid.clone();
        wrong[key] = json!(["ok", 1]);
        assert_eq!(dispatch(&wrong), Err(ERR_INVALID), "{key}");
    }
    let mut extra = valid.clone();
    extra["other"] = json!("");
    assert_eq!(dispatch(&extra), Err(ERR_INVALID));
}

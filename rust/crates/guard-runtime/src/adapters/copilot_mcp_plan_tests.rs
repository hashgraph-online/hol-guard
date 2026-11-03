//! Replays `copilot_mcp_plan_vectors.json`, recorded from the original Python
//! Copilot install, through the native kind.

use serde_json::{json, Value};

use crate::copilot_mcp_plan::plan;
use crate::runner_authority_op::ERR_INVALID;

const VECTORS: &str = include_str!("../../testdata/copilot/copilot_mcp_plan_vectors.json");
const SCHEMA: &str = "guard-copilot-mcp-plan-vectors.v1";
const MODULE: [&str; 3] = ["-m", "codex_plugin_scanner.cli", "guard"];

fn request(name: &str, mcp_servers: Value, managed: Value) -> Value {
    json!({
        "workspace": true,
        "managed": managed,
        "targets": [{"path": "/w/.mcp.json", "name": name, "mcpServers": mcp_servers, "servers": null}],
    })
}

fn only_target(answer: &Value) -> &Value {
    let targets = answer["targets"].as_array().expect("targets");
    assert_eq!(targets.len(), 1);
    &targets[0]
}

#[test]
fn replays_every_recorded_python_install() {
    let document: Value = serde_json::from_str(VECTORS).expect("vectors parse");
    assert_eq!(document["schema"], json!(SCHEMA));
    let cases = document["cases"].as_array().expect("cases");
    assert_eq!(cases.len(), 17);
    for case in cases {
        let name = case["name"].as_str().expect("name");
        assert_eq!(
            plan(&case["request"]).as_ref(),
            Ok(&case["expect"]),
            "{name}"
        );
    }
}

#[test]
fn relaunches_a_list_form_proxy_command_with_its_python_argv() {
    let launch = json!({"command": ["/old/python", "-m", "codex_plugin_scanner.cli", "guard",
        "copilot-mcp-proxy", "--server-name", "danger_lab"]});
    let answer = plan(&request(
        "mcp.json",
        json!([["danger_lab", launch]]),
        json!([]),
    ))
    .expect("plan");
    let target = only_target(&answer);
    assert_eq!(target["key"], json!("mcpServers"));
    assert_eq!(target["source"], json!("mcpServers"));
    let mut argv: Vec<&str> = MODULE.to_vec();
    argv.extend(["copilot-mcp-proxy", "--server-name", "danger_lab"]);
    assert_eq!(target["refresh"], json!([[0, argv]]));
    assert_eq!(target["fields"], json!([["type", "stdio"]]));
}

#[test]
fn unwraps_only_a_relay_launch_of_a_relayed_proxy() {
    let mut relayed = vec!["mcp-relay", "/usr/bin/python3"];
    relayed.extend(MODULE);
    relayed.push("copilot-mcp-proxy");
    let tail = relayed[2..].to_vec();
    let mut kept = relayed.clone();
    kept[5] = "mcp-proxy";
    let servers = json!([
        ["relayed", {"command": "hol-guard", "args": relayed}],
        ["kept", {"command": "hol-guard", "args": kept}],
    ]);
    let answer = plan(&request(".mcp.json", servers, json!([]))).expect("plan");
    let target = only_target(&answer);
    assert_eq!(target["refresh"], json!([[0, tail], [1, kept]]));
    assert_eq!(
        target["fields"],
        json!([["type", "local"], ["tools", ["*"]]])
    );
}

#[test]
fn a_workspace_entry_shadows_only_non_project_servers() {
    let servers = json!([["shared", {"command": "npx"}], ["text", null]]);
    let managed = json!([
        ["shared", "global", "/g"],
        ["shared", "project", "/w/.mcp.json"],
        ["text", "global", "/g"],
        ["other", "project", "/w/.vscode/mcp.json"],
    ]);
    let answer = plan(&request(".mcp.json", servers.clone(), managed.clone())).expect("plan");
    assert_eq!(only_target(&answer)["add"], json!([1, 2]));
    let mut global = request(".mcp.json", servers, managed);
    global["workspace"] = json!(false);
    assert_eq!(
        only_target(&plan(&global).expect("plan"))["add"],
        json!([0, 1, 2])
    );
}

#[test]
fn refuses_requests_with_missing_extra_or_mistyped_fields() {
    let valid = request(".mcp.json", Value::Null, json!([]));
    assert!(plan(&valid).is_ok());
    let mut missing = valid.clone();
    missing.as_object_mut().expect("object").remove("workspace");
    assert_eq!(plan(&missing), Err(ERR_INVALID));
    let mut extra = valid.clone();
    extra["op"] = json!("plan");
    assert_eq!(plan(&extra), Err(ERR_INVALID));
    let mut target_extra = valid.clone();
    target_extra["targets"][0]["other"] = json!(null);
    assert_eq!(plan(&target_extra), Err(ERR_INVALID));
    let mut row = valid;
    row["managed"] = json!([["a", "global"]]);
    assert_eq!(plan(&row), Err(ERR_INVALID));
    for slot in [
        json!(true),
        json!({"a": {}}),
        json!([["a"]]),
        json!([["a", "text"]]),
        json!([["a", {"env": {}}]]),
        json!([["a", null], ["a", {}]]),
    ] {
        assert_eq!(
            plan(&request(".mcp.json", slot, json!([]))),
            Err(ERR_INVALID)
        );
    }
    assert_eq!(plan(&json!([])), Err(ERR_INVALID));
}

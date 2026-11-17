use serde_json::{json, Value};

use super::super::Ctx;
use super::{detected, managed, observed, select_request, skipped, wired};
use crate::pyjson::PyVal;

fn ctx() -> Ctx {
    Ctx::parse(Some(&json!({
        "home": "/u/home",
        "workspace": null,
        "guard_home": "/u/home/.hol-guard",
        "home_override_explicit": false,
        "cwd": "/work",
        "user_home": "/u/home",
        "env": {"PATH": ""},
        "caller": {
            "executable": "/py/bin/python",
            "executable_resolved": "/py/bin/python3.12",
            "frozen": false,
            "launcher": "/py/bin/python",
            "package_root": "/site",
            "version": "1.0.0",
            "native_runtime": null,
        },
    })))
    .unwrap()
}

fn server(name: &str, command: Value) -> Value {
    json!({
        "artifact_id": format!("copilot:global:{name}"),
        "name": name,
        "harness": "copilot",
        "artifact_type": "mcp_server",
        "source_scope": "global",
        "config_path": "/u/home/.copilot/mcp-config.json",
        "command": command,
        "args": ["server.js"],
        "url": null,
        "transport": "stdio",
        "publisher": null,
        "metadata": {"env": {"REDACTED": "*"}},
        "runtime_private_metadata": {"mcp_args": ["server.js", "--port", "1"], "mcp_env": {"LAB_MODE": "t"}},
    })
}

#[test]
fn a_select_request_carries_the_private_arguments_and_environment() {
    let request = select_request(&server("lab", json!("node"))).unwrap();
    assert_eq!(request["args"], json!(["server.js", "--port", "1"]));
    assert_eq!(request["env"], json!([["LAB_MODE", "t"]]));
    assert_eq!(request["enabled"], json!(true));
    assert_eq!(request["saved_origin"], Value::Null);
    let mut public = server("lab", json!("node"));
    public
        .as_object_mut()
        .unwrap()
        .remove("runtime_private_metadata");
    let request = select_request(&public).unwrap();
    assert_eq!(request["args"], json!(["server.js"]));
    assert_eq!(request["env"], json!([["REDACTED", "*"]]));
}

#[test]
fn a_select_request_refuses_private_arguments_that_are_not_text() {
    let mut artifact = server("lab", json!("node"));
    artifact["runtime_private_metadata"]["mcp_args"] = json!(["ok", 1]);
    assert!(select_request(&artifact).is_none());
}

#[test]
fn managed_servers_launch_behind_the_proxy_and_skip_a_server_without_a_command() {
    let artifacts = [
        server("lab", json!("node")),
        server("broken", Value::Null),
        json!({"artifact_type": "skill", "name": "not-a-server"}),
    ];
    let rows = managed(&ctx(), &artifacts, "copilot-mcp-proxy").unwrap();
    assert_eq!(rows.len(), 1);
    let (name, scope, path, entry) = &rows[0];
    assert_eq!(
        (name.as_str(), scope.as_str(), path.as_str()),
        ("lab", "global", "/u/home/.copilot/mcp-config.json")
    );
    let PyVal::Dict(entry) = entry else {
        panic!("entry is a dict");
    };
    assert_eq!(entry[0].0, "command");
    assert_eq!(entry[0].1, PyVal::Str("/py/bin/python".into()));
    assert_eq!(skipped(&artifacts).unwrap(), vec!["broken".to_owned()]);
}

#[test]
fn no_server_artifacts_manage_and_skip_nothing() {
    let artifacts = [json!({"artifact_type": "skill", "name": "x"})];
    assert!(managed(&ctx(), &artifacts, "copilot-mcp-proxy")
        .unwrap()
        .is_empty());
    assert!(skipped(&artifacts).unwrap().is_empty());
}

#[test]
fn the_codex_plan_reads_managed_servers_from_the_detected_artifacts() {
    let mut fields = serde_json::Map::new();
    fields.insert(
        "artifacts".into(),
        json!([server("lab", json!("node")), server("broken", Value::Null)]),
    );
    let (servers, managed, skipped) = wired(&ctx(), &fields, "codex-mcp-proxy").unwrap();
    assert_eq!(managed, vec!["lab".to_owned()]);
    assert_eq!(skipped, vec!["broken".to_owned()]);
    assert_eq!(servers.len(), 1);
    assert_eq!(servers[0]["name"], json!("lab"));
    assert_eq!(servers[0]["source_scope"], json!("global"));
    let entry: Value = serde_json::from_str(servers[0]["entry"].as_str().unwrap()).unwrap();
    assert_eq!(entry["command"], json!("/py/bin/python"));
    assert!(wired(&ctx(), &serde_json::Map::new(), "codex-mcp-proxy").is_err());
}

#[test]
fn observed_servers_name_each_selected_server_with_its_scope_and_path() {
    let artifacts = [server("lab", json!("node")), server("broken", Value::Null)];
    assert_eq!(
        observed(&artifacts).unwrap(),
        vec![[
            "lab".to_owned(),
            "global".to_owned(),
            "/u/home/.copilot/mcp-config.json".to_owned()
        ]]
    );
}

#[test]
fn a_detection_without_a_workspace_keeps_its_own_artifacts() {
    let detection = json!({"artifacts": [server("lab", json!("node"))], "workspace_aibom": true});
    assert_eq!(detected(&ctx(), "copilot", &detection).unwrap().len(), 1);
    assert!(detected(&ctx(), "copilot", &json!({})).is_err());
}

//! Copilot through the `harness_adapter` kind.

use std::fs;
use std::path::{Path, PathBuf};

use serde_json::{json, Map, Value};

use super::{after, dispatch, shim, Home};
use crate::runner_authority_op::KindResult;

fn write(path: &Path, text: &str) {
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(path, text).unwrap();
}

fn workspace(home: &Home) -> PathBuf {
    let workspace = home.root.join("ws");
    fs::create_dir_all(&workspace).unwrap();
    workspace
}

fn ask(home: &Home, op: &str, extra: Value) -> KindResult {
    let mut context = home.context(json!({"PATH": ""}));
    context["workspace"] = json!(workspace(home));
    let mut request = json!({"harness": "copilot", "op": op, "context": context});
    for (key, value) in extra.as_object().unwrap() {
        request[key] = value.clone();
    }
    dispatch(&request)
}

/// The fields Python sends with `prepare_install` after `install_detection`.
fn install_fields(found: &Value, refresh: Value) -> Value {
    let mut fields = Map::new();
    for (key, value) in [
        ("create_key", json!(true)),
        ("digest", found["digest"].clone()),
        ("shim", json!(shim())),
        ("config_argv", json!(["/py", "hook"])),
        ("workspace_argv", json!(["/py", "hook", "--workspace"])),
        ("managed", json!("[]")),
        ("refresh", json!(refresh.to_string())),
        ("skipped", json!("[]")),
        ("hook_env", json!("{}")),
    ] {
        fields.insert(key.to_owned(), value);
    }
    Value::Object(fields)
}

fn empty_refresh(found: &Value) -> Value {
    json!(vec![json!([]); found["refresh"].as_array().unwrap().len()])
}

#[test]
fn copilot_rebind_without_an_enrolled_key_creates_no_file() {
    let home = Home::new();
    for op in ["install_detection", "prepare_install"] {
        let answer = ask(&home, op, json!({"create_key": false})).unwrap();
        assert_eq!(
            answer,
            json!({"transition_error": "adapter_preparation_authority_missing"})
        );
    }
    assert!(!home.guard().join("managed").exists());
}

#[test]
fn copilot_install_plans_both_workspace_mcp_targets() {
    let home = Home::new();
    let ws = workspace(&home);
    write(
        &ws.join(".mcp.json"),
        r#"{"mcpServers": {"cli_lab": {"command": "python", "args": ["cli.py"]}}}"#,
    );
    let found = ask(&home, "install_detection", json!({})).unwrap();
    let refresh = empty_refresh(&found);
    let answer = ask(&home, "prepare_install", install_fields(&found, refresh)).unwrap();
    let manifest: Value = serde_json::from_str(answer["manifest"].as_str().unwrap()).unwrap();
    let targets: Vec<PathBuf> =
        serde_json::from_value(manifest["managed_config_paths"].clone()).unwrap();
    assert_eq!(targets, [ws.join(".mcp.json"), ws.join(".vscode/mcp.json")]);
    let config = answer["files"]
        .as_array()
        .unwrap()
        .iter()
        .find(|change| change["path"] == json!(home.home().join(".copilot/config.json")))
        .unwrap();
    assert!(after(config).contains("/py hook"));
}

#[test]
fn copilot_install_refuses_a_malformed_later_plan_before_planning_any_write() {
    let home = Home::new();
    let ws = workspace(&home);
    let cli = ws.join(".mcp.json");
    let ide = ws.join(".vscode/mcp.json");
    write(
        &cli,
        r#"{"mcpServers": {"cli_lab": {"command": "python", "args": ["cli.py"]}}}"#,
    );
    write(
        &ide,
        r#"{"servers": {"ide_lab": {"command": "node", "args": ["ide.js"]}}}"#,
    );
    let before = (fs::read(&cli).unwrap(), fs::read(&ide).unwrap());
    let found = ask(&home, "install_detection", json!({})).unwrap();
    // Python built relaunches for the first target only.
    let refresh = json!([[]]);
    assert!(ask(&home, "prepare_install", install_fields(&found, refresh)).is_err());
    assert_eq!((fs::read(&cli).unwrap(), fs::read(&ide).unwrap()), before);
}
